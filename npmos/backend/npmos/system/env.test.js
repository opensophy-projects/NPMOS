import assert from "node:assert/strict";
import { test } from "node:test";
import { conflicts, envLines, normalize, running, SYSTEM_ENV } from "./env.js";

test("values of env settings in their form", () => {
	assert.equal(normalize("DISABLE_HTTP", "true"), true);
	assert.equal(normalize("DISABLE_HTTP", "yes"), undefined);
	assert.equal(normalize("NGINX_WORKER_PROCESSES", "auto"), "auto");
	assert.equal(normalize("NGINX_WORKER_PROCESSES", 4), 4);
	assert.equal(normalize("NGINX_WORKER_PROCESSES", 0), undefined);
	assert.equal(normalize("NGINX_WORKER_CONNECTIONS", "1024"), 1024);
	assert.equal(normalize("NGINX_WORKER_CONNECTIONS", 10), undefined);
	assert.equal(normalize("LOGROTATIONS", "7;rm"), undefined);
	assert.equal(normalize("TZ", "Europe/Moscow"), "Europe/Moscow");
	assert.equal(normalize("TZ", "../../etc/passwd"), undefined);
	assert.equal(normalize("TZ", "Mars/Olympus"), undefined);
	assert.equal(normalize("UNKNOWN", "1"), undefined);
});

test("running values fall back to the defaults", () => {
	assert.equal(running("DISABLE_GRAVATAR", {}), true);
	assert.equal(running("NGINX_WORKER_CONNECTIONS", { NGINX_WORKER_CONNECTIONS: "2048" }), 2048);
	assert.equal(running("TZ", { TZ: "bad zone" }), "UTC");
});

test("runtime.env lines and conflicts envs.sh would resolve on its own", () => {
	assert.deepEqual(envLines({ TZ: "UTC", DISABLE_HTTP: false }), ["TZ=UTC", "DISABLE_HTTP=false"]);
	const defaults = Object.fromEntries(SYSTEM_ENV.map((d) => [d.env, d.default]));
	assert.deepEqual(conflicts(defaults), []);
	assert.equal(conflicts({ ...defaults, LISTEN_PROXY_PROTOCOL_HTTPS: true }).length, 1);
	assert.equal(conflicts({ ...defaults, NGINX_FORCE_X25519MLKEM768: true }).length, 2);
});
