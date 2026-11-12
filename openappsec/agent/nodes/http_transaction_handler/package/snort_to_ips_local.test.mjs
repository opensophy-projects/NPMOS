// NginxionS: snort_to_ips_local.mjs gives what the Python converter of upstream (snort_to_ips_local.py and
// snort3_to_ips/, the reference) gives, for every rule of testdata/snort-rules.txt. Needs python3 (CI runners have it).
//   node --test openappsec/agent/nodes/http_transaction_handler/package/snort_to_ips_local.test.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const rules = join(here, "testdata", "snort-rules.txt");

const run = (cmd, script) => {
	const dir = mkdtempSync(join(tmpdir(), "snort-"));
	const out = join(dir, "out.json");
	const err = join(dir, "err.json");
	execFileSync(cmd, [join(here, script), rules, out, err], { cwd: here, stdio: "pipe" });
	return { out: JSON.parse(readFileSync(out, "utf8")), err: JSON.parse(readFileSync(err, "utf8")) };
};

test("the converter in JavaScript gives the output and the errors of the Python one", () => {
	const js = run(process.execPath, "snort_to_ips_local.mjs");
	const py = run("python3", "snort_to_ips_local.py");
	assert.ok(js.out.IPSSnortSigs.protections.length > 10, "the test rules convert");
	assert.ok(js.err.Errors.length > 5, "the test rules have errors");
	assert.deepEqual(js.out, py.out);
	assert.deepEqual(js.err, py.err);
});
