import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { assertKeyMatches } from "./cert-pair.js";

const pair = (dir, name) => {
	execFileSync(
		"openssl",
		[
			"req",
			"-x509",
			"-newkey",
			"ec",
			"-pkeyopt",
			"ec_paramgen_curve:P-256",
			"-nodes",
			"-keyout",
			path.join(dir, `${name}.key`),
			"-out",
			path.join(dir, `${name}.crt`),
			"-days",
			"2",
			"-subj",
			`/CN=${name}`,
		],
		{ stdio: "ignore" },
	);
	return [readFileSync(path.join(dir, `${name}.crt`), "utf8"), readFileSync(path.join(dir, `${name}.key`), "utf8")];
};

test("a key of another certificate is refused, its own is taken", () => {
	const dir = mkdtempSync(path.join(tmpdir(), "pair-"));
	const [a, aKey] = pair(dir, "a");
	const [, bKey] = pair(dir, "b");
	assert.doesNotThrow(() => assertKeyMatches(a, aKey));
	assert.throws(() => assertKeyMatches(a, bKey), /does not match/);
	// a chain: the first certificate counts
	assert.doesNotThrow(() => assertKeyMatches(a + a, aKey));
});
