import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { assetDir, listLearning, readLearning } from "./learning.js";

test("the files the agent learned are listed and read, gzip or not, only inside its folder", async () => {
	const root = await mkdtemp(path.join(tmpdir(), "nginxions-learning-"));
	await mkdir(path.join(root, "shop.example.com", "api"), { recursive: true });
	const sets = { confident_sets: [{ key: "url_param#q", value: { first: ["select"], second: 1 } }] };
	await writeFile(path.join(root, "shop.example.com", "5.data"), gzipSync(JSON.stringify(sets)));
	await writeFile(path.join(root, "shop.example.com", "api", "4.data"), JSON.stringify(sets));
	// not a file of what is learned
	await writeFile(path.join(root, "shop.example.com", "waap.data"), "{}");

	const list = await listLearning(root);
	assert.deepEqual(
		list.map((a) => [a.asset, a.files.map((f) => f.name)]),
		[
			["shop.example.com", ["5.data"]],
			["shop.example.com/api", ["4.data"]],
		],
	);
	assert.deepEqual((await readLearning("shop.example.com", "5.data", root)).data, sets);
	assert.deepEqual((await readLearning("shop.example.com/api", "4.data", root)).data, sets);
	assert.equal(await readLearning("shop.example.com", "7.data", root), null);
	await assert.rejects(readLearning("shop.example.com", "waap.data", root), /unknown file/);
	await assert.rejects(readLearning("../etc", "5.data", root), /invalid asset/);
	assert.throws(() => assetDir("/etc", root), /invalid asset/);
	assert.throws(() => assetDir(".", root), /invalid asset/);
	assert.deepEqual(await listLearning(path.join(root, "missing")), []);
});
