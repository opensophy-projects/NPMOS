import assert from "node:assert/strict";
import { test } from "node:test";
import { firstPemCertificate, pemCertificates } from "./pem.js";

const cert = (body) => `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;

test("pemCertificates: every block, in order, without the text around", () => {
	const text = `key\n${cert("AAA")}\nnoise\n${cert("BBB")}\n`;
	assert.deepEqual(pemCertificates(text), [cert("AAA"), cert("BBB")]);
	assert.equal(firstPemCertificate(text), cert("AAA"));
});

test("pemCertificates: no block, an unterminated block, not a string", () => {
	assert.deepEqual(pemCertificates("nothing"), []);
	assert.deepEqual(pemCertificates(`${cert("AAA")}\n-----BEGIN CERTIFICATE-----\nCCC`), [cert("AAA")]);
	assert.equal(firstPemCertificate(null), null);
});

test("pemCertificates: linear on many BEGIN markers without an END", () => {
	const text = "-----BEGIN CERTIFICATE-----".repeat(200000);
	const started = Date.now();
	assert.deepEqual(pemCertificates(text), []);
	assert.ok(Date.now() - started < 1000);
});
