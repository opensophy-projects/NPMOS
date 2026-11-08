import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { readWithStat, readWithStatSync } from "./files.js";

test("readWithStat: content and stat of one handle; accept can skip the read", async () => {
	const dir = mkdtempSync(join(tmpdir(), "nginxions-files-"));
	try {
		const file = join(dir, "a.txt");
		writeFileSync(file, "hello");
		const read = await readWithStat(file, { encoding: "utf8" });
		assert.equal(read.data, "hello");
		assert.equal(read.stat.size, 5);
		assert.equal((await readWithStat(file, { accept: (s) => s.size < 3 })).data, null);
		assert.equal(readWithStatSync(file, { encoding: "utf8" }).data, "hello");
		await assert.rejects(readWithStat(join(dir, "missing")));
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
