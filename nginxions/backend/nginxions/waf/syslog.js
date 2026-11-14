// Syslog and CEF of a log trigger to any number of servers, by IPv4, IPv6 or a host name (docs/WAF-POLICY.md). The
// agent keeps one stream of each kind and opens a socket to an IPv4 address only (core/logging/logging.cc): a trigger
// with several servers or a name is sent to a relay of NginxionS on 127.0.0.1 (the containers nginxions and
// openappsec share the network), which forwards every message to each server of the trigger, over UDP or TCP
// (octet counting, as the agent frames TCP). A trigger with one IPv4 server is sent by the agent itself.
import dgram from "node:dgram";
import net from "node:net";
import { global as logger } from "../../logger.js";

export const RELAY_HOST = "127.0.0.1";
export const RELAY_BASE_PORT = 7900;
const MAX_RELAYS = 64;
const MAX_QUEUE = 1000;
const RETRY_MS = 5000;
const SERVICES = ["syslogService", "cefService"];
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

const list = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const protoOf = (s) => (String(s?.proto || "udp").toLowerCase() === "tcp" ? "tcp" : "udp");
const targetOf = (s) => ({ address: String(s.address), port: Number(s.port) || 514, proto: protoOf(s) });

/** the agent sends to the servers itself: one server at an IPv4 address */
const direct = (services) => services.length === 1 && IPV4.test(String(services[0]?.address || ""));

/**
 * The log triggers for the agent: those it cannot send send to a relay.
 * @param {object} doc  the policy (v1beta2)
 * @returns {{doc: object, relays: {port: number, targets: {address: string, port: number, proto: string}[]}[]}}
 */
export const withRelays = (doc) => {
	const relays = new Map();
	const logTriggers = list(doc?.logTriggers).map((trigger) => {
		const dest = trigger?.logDestination;
		if (!dest) return trigger;
		const next = { ...dest };
		for (const service of SERVICES) {
			const services = list(dest[service]).filter((s) => s?.address);
			if (!services.length || direct(services)) continue;
			const targets = services.map(targetOf);
			const key = JSON.stringify(targets);
			if (!relays.has(key)) {
				if (relays.size >= MAX_RELAYS) continue;
				relays.set(key, { port: RELAY_BASE_PORT + relays.size, targets });
			}
			next[service] = [{ address: RELAY_HOST, port: relays.get(key).port, proto: "udp" }];
		}
		return { ...trigger, logDestination: next };
	});
	if (!relays.size) return { doc, relays: [] };
	return { doc: { ...doc, logTriggers }, relays: [...relays.values()] };
};

/** a TCP server: one connection, reconnected; messages queued while it is down (the oldest dropped) */
const tcpSender = (target) => {
	let socket = null;
	let ready = false;
	let timer = null;
	let closed = false;
	const queue = [];
	const flush = () => {
		while (ready && queue.length) socket.write(queue.shift());
	};
	const connect = () => {
		if (closed) return;
		socket = net.createConnection({ host: target.address, port: target.port });
		socket.setKeepAlive(true);
		socket.on("connect", () => {
			ready = true;
			flush();
		});
		socket.on("error", () => {});
		socket.on("close", () => {
			ready = false;
			if (!closed) timer = setTimeout(connect, RETRY_MS);
			timer?.unref?.();
		});
	};
	connect();
	return {
		send(msg) {
			const framed = Buffer.concat([Buffer.from(`${msg.length} `), msg]);
			if (ready) return socket.write(framed);
			queue.push(framed);
			if (queue.length > MAX_QUEUE) queue.shift();
		},
		close() {
			closed = true;
			clearTimeout(timer);
			socket?.destroy();
		},
	};
};

/** a UDP server: a datagram a message; the name is resolved by the socket each time */
const udpSender = (target) => {
	const family = net.isIPv6(target.address) ? "udp6" : "udp4";
	let socket = dgram.createSocket(family);
	socket.on("error", () => {});
	let warned = false;
	return {
		send(msg) {
			socket.send(msg, target.port, target.address, (err) => {
				if (err && !warned)
					logger.warn(`NginxionS syslog relay: ${target.address}:${target.port}: ${err.message}`);
				warned = Boolean(err);
			});
		},
		close() {
			socket.close();
			socket = null;
		},
	};
};

const running = new Map();

const keyOf = (relay) => `${relay.port} ${JSON.stringify(relay.targets)}`;

const startRelay = (relay) => {
	const senders = relay.targets.map((t) => (t.proto === "tcp" ? tcpSender(t) : udpSender(t)));
	let socket = null;
	let timer = null;
	let closed = false;
	// the port of a relay just stopped is free a moment later
	const open = (attempt) => {
		socket = dgram.createSocket("udp4");
		socket.on("message", (msg) => {
			for (const s of senders) {
				try {
					s.send(msg);
				} catch {
					// a server down: the others still get it
				}
			}
		});
		socket.on("error", (err) => {
			socket.close();
			if (!closed && err.code === "EADDRINUSE" && attempt < 20) {
				timer = setTimeout(() => open(attempt + 1), 250);
				timer.unref?.();
				return;
			}
			logger.error(`NginxionS syslog relay ${RELAY_HOST}:${relay.port}: ${err.message}`);
		});
		socket.bind(relay.port, RELAY_HOST);
		socket.unref();
	};
	open(0);
	return {
		close() {
			closed = true;
			clearTimeout(timer);
			try {
				socket.close();
			} catch {
				// already closed
			}
			for (const s of senders) s.close();
		},
	};
};

/**
 * Runs the relays of the policy, stops the others.
 * @param {{port: number, targets: object[]}[]} relays
 */
export const applyRelays = (relays) => {
	const wanted = new Map(relays.map((r) => [keyOf(r), r]));
	for (const [key, relay] of running) {
		if (!wanted.has(key)) {
			relay.close();
			running.delete(key);
		}
	}
	for (const [key, relay] of wanted) {
		if (!running.has(key)) running.set(key, startRelay(relay));
	}
	return running.size;
};
