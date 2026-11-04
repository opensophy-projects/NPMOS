import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { knownSecrets, MASK, redact } from "./redact.js";

test("redact: password of a connection string (log of appsec-tuning)", () => {
	const line = "db name: postgres://appsec:s3cr3t-P4ss@postgres:5432/i2datatube?sslmode=disable";
	assert.equal(redact(line), `db name: postgres://appsec:${MASK}@postgres:5432/i2datatube?sslmode=disable`);
});

test("redact: key=value, JSON, Authorization, JWT, private key", () => {
	assert.equal(redact("password=hunter22 user=bob"), `password=${MASK} user=bob`);
	assert.equal(redact('{"api_key": "abcdef123"}'), `{"api_key": "${MASK}"}`);
	assert.equal(redact("DB_PASSWORD: xyz987"), `DB_PASSWORD: ${MASK}`);
	assert.equal(redact("Authorization: Bearer abc.def-123456"), `Authorization: Bearer ${MASK}`);
	assert.equal(redact("t=eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"), `t=${MASK}`);
	const pem = "-----BEGIN EC PRIVATE KEY-----\nMHcC\n-----END EC PRIVATE KEY-----";
	assert.equal(redact(pem), `-----BEGIN EC PRIVATE KEY-----${MASK}-----END EC PRIVATE KEY-----`);
});

test("redact: ordinary lines stay as they are", () => {
	for (const line of [
		"GET /api/tokens 401",
		"bypass mode off",
		"proxy_set_header Authorization $http_authorization;",
		"ssl_certificate_key /data/tls/key.pem;",
		"Last update status: Succeeded",
	]) {
		assert.equal(redact(line), line);
	}
});

test("redact: values of known secrets, from env and *_FILE", () => {
	const dir = mkdtempSync(join(tmpdir(), "redact-"));
	writeFileSync(join(dir, "pw"), "file-secret-42\n");
	const secrets = knownSecrets({
		DB_POSTGRES_PASSWORD_FILE: join(dir, "pw"),
		API_TOKEN: "env-token-99",
		HOME: "/root",
	});
	assert.deepEqual(secrets.sort(), ["env-token-99", "file-secret-42"]);
	assert.equal(redact("x file-secret-42 y env-token-99", secrets), `x ${MASK} y ${MASK}`);
});
