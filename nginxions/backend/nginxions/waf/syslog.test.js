import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";
import { test } from "node:test";
import { applyRelays, RELAY_BASE_PORT, RELAY_HOST, withRelays } from "./syslog.js";

const trigger = (name, syslogService, cefService) => ({ name, logDestination: { syslogService, cefService } });

test("what the agent cannot send goes through a relay; one IPv4 server stays with the agent", () => {
	const doc = {
		logTriggers: [
			trigger("direct", [{ address: "10.0.0.5", port: 514 }]),
			trigger("two", [
				{ address: "10.0.0.5", port: 514 },
				{ address: "logs.example.com", port: 6514, proto: "tcp" },
			]),
			trigger("same", [
				{ address: "10.0.0.5", port: 514 },
				{ address: "logs.example.com", port: 6514, proto: "tcp" },
			]),
			trigger("v6", undefined, [{ address: "2001:db8::5", port: 515 }]),
		],
	};
	const { doc: out, relays } = withRelays(doc);
	assert.deepEqual(out.logTriggers[0], doc.logTriggers[0]);
	assert.deepEqual(out.logTriggers[1].logDestination.syslogService, [
		{ address: RELAY_HOST, port: RELAY_BASE_PORT, proto: "udp" },
	]);
	// the same servers share a relay
	assert.deepEqual(out.logTriggers[2].logDestination.syslogService, out.logTriggers[1].logDestination.syslogService);
	assert.deepEqual(out.logTriggers[3].logDestination.cefService, [
		{ address: RELAY_HOST, port: RELAY_BASE_PORT + 1, proto: "udp" },
	]);
	assert.deepEqual(relays, [
		{
			port: RELAY_BASE_PORT,
			targets: [
				{ address: "10.0.0.5", port: 514, proto: "udp" },
				{ address: "logs.example.com", port: 6514, proto: "tcp" },
			],
		},
		{ port: RELAY_BASE_PORT + 1, targets: [{ address: "2001:db8::5", port: 515, proto: "udp" }] },
	]);
	assert.deepEqual(withRelays({ logTriggers: [doc.logTriggers[0]] }).relays, []);
});

test("the relay forwards a message to every server, UDP and TCP (octet counting)", async () => {
	const udp = dgram.createSocket("udp4");
	await new Promise((r) => udp.bind(0, "127.0.0.1", r));
	const gotUdp = new Promise((r) => udp.once("message", (m) => r(m.toString())));
	let tcpData = "";
	const gotTcp = new Promise((resolve) => {
		const server = net.createServer((c) =>
			c.on("data", (d) => {
				tcpData += d;
				if (tcpData.length >= 13) {
					c.destroy();
					server.close();
					resolve(tcpData);
				}
			}),
		);
		server.listen(0, "127.0.0.1", () => {
			const relays = [
				{
					port: RELAY_BASE_PORT + 50,
					targets: [
						{ address: "127.0.0.1", port: udp.address().port, proto: "udp" },
						{ address: "localhost", port: server.address().port, proto: "tcp" },
					],
				},
			];
			assert.equal(applyRelays(relays), 1);
			const agent = dgram.createSocket("udp4");
			// the TCP connection is up a moment later: the message waits in the queue
			setTimeout(() => agent.send("<14>1 hello", RELAY_BASE_PORT + 50, "127.0.0.1", () => agent.close()), 200);
		});
	});
	assert.equal(await gotUdp, "<14>1 hello");
	assert.equal(await gotTcp, "11 <14>1 hello");
	udp.close();
	assert.equal(applyRelays([]), 0);
});
