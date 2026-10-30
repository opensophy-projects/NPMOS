import assert from "node:assert/strict";
import { test } from "node:test";
import { toEvent } from "./denials.js";

test("mTLS denials: a line of the nginx log becomes a security event", () => {
	const none = toEvent({
		time: "2026-10-29T15:00:00+00:00",
		host: "MTLS.local",
		ip: "192.0.2.7",
		method: "GET",
		uri: "/secret?x=1",
		verify: "NONE",
	});
	assert.equal(none.kind, "mtls");
	assert.equal(none.name, "mTLS: no client certificate");
	assert.equal(none.host, "mtls.local");
	assert.equal(none.uri, "/secret");
	assert.equal(none.query, "x=1");
	assert.equal(none.response_code, 403);
	const refused = toEvent({
		time: "2026-10-29T15:00:01+00:00",
		ip: "192.0.2.8",
		uri: "/",
		verify: "SUCCESS",
		s_dn: "CN=bob,OU=Sales",
		serial: "0A",
	});
	assert.equal(refused.name, "mTLS: client certificate not accepted");
	assert.equal(refused.sample, "subject: CN=bob,OU=Sales; serial: 0A");
	assert.equal(toEvent({ ip: "192.0.2.9" }), null);
	assert.equal(toEvent({ time: "bad", ip: "192.0.2.9" }), null);
});
