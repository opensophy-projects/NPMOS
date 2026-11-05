import assert from "node:assert/strict";
import { test } from "node:test";
import { portConflict, portRange, reservedPorts } from "./stream-ports.js";

const reserved = reservedPorts({ HTTP_PORT: "80", HTTPS_PORT: "443" });
const s = (id, port, tcp = true, udp = false) => ({
	id,
	incoming_port: port,
	tcp_forwarding: tcp,
	udp_forwarding: udp,
});

test("a port or a range", () => {
	assert.deepEqual(portRange("2222"), [2222, 2222]);
	assert.deepEqual(portRange("3000-2000"), [2000, 3000]);
});

test("a second stream on a port of the same protocol is refused, another protocol is not", () => {
	const others = [s(1, "2222")];
	assert.match(portConflict(s(undefined, "2222"), others, reserved), /already used by the stream on port 2222/);
	assert.equal(portConflict(s(undefined, "2222", false, true), others, reserved), null);
	assert.equal(portConflict(s(1, "2222"), others, reserved), null, "the stream itself is no conflict");
});

test("ranges overlap", () => {
	const others = [s(1, "5000-5010")];
	assert.ok(portConflict(s(2, "5010"), others, reserved));
	assert.ok(portConflict(s(2, "4990-5000"), others, reserved));
	assert.equal(portConflict(s(2, "5011-5020"), others, reserved), null);
});

test("the ports of the hosts and the panel are not for streams", () => {
	assert.match(portConflict(s(1, "443"), [], reserved), /443\/TCP is used by NPMOS/);
	assert.match(portConflict(s(1, "81"), [], reserved), /81\/TCP/);
	assert.match(portConflict(s(1, "400-500", false, true), [], reserved), /443\/UDP/);
	assert.equal(portConflict(s(1, "443", false, true), [], reservedPorts({ DISABLE_H3_QUIC: "true" })), null);
});
