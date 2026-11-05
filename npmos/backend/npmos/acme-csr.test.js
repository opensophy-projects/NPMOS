import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { checkCsr } from "./acme-csr-check.js";

const dir = mkdtempSync(path.join(tmpdir(), "csr-"));
const csr = (name, args) => {
	const key = path.join(dir, `${name}.key`);
	const req = path.join(dir, `${name}.csr`);
	execFileSync("openssl", ["req", "-new", "-nodes", "-keyout", key, "-out", req, ...args], { stdio: "ignore" });
	return [readFileSync(req, "utf8"), readFileSync(key, "utf8")];
};

test("a CSR with its names and key is taken; the names come from subjectAltName", async () => {
	const [req, key] = csr("a", [
		"-newkey",
		"ec",
		"-pkeyopt",
		"ec_paramgen_curve:P-384",
		"-subj",
		"/O=Office/CN=a.example.test",
		"-addext",
		"subjectAltName=DNS:a.example.test,DNS:www.a.example.test",
	]);
	const out = await checkCsr(`text before\n${req}`, key);
	assert.deepEqual(out.names, ["a.example.test", "www.a.example.test"]);
	assert.match(out.key_type, /id-ecPublicKey 384/);
	assert.match(out.subject, /O\s*=\s*Office/);
});

test("a key of another request, no subjectAltName, not a CSR: refused", async () => {
	const [req] = csr("b", [
		"-newkey",
		"rsa:2048",
		"-subj",
		"/CN=b.example.test",
		"-addext",
		"subjectAltName=DNS:b.example.test",
	]);
	const [, otherKey] = csr("c", [
		"-newkey",
		"rsa:2048",
		"-subj",
		"/CN=c.example.test",
		"-addext",
		"subjectAltName=DNS:c.example.test",
	]);
	await assert.rejects(checkCsr(req, otherKey), /does not belong/);
	const [noSan, noSanKey] = csr("d", ["-newkey", "rsa:2048", "-subj", "/CN=d.example.test"]);
	await assert.rejects(checkCsr(noSan, noSanKey), /subjectAltName/);
	await assert.rejects(checkCsr("hello", "x"), /PEM/);
	await assert.rejects(checkCsr(req, ""), /private key/);
});
