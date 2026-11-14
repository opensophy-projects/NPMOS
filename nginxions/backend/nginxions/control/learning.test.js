import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { assetDir, checkSnapshot, listLearning, readLearning, snapshotLearning, stageRestore } from "./learning.js";

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

test("a snapshot holds every learned file as it is; its restore is staged, checked, whole", async () => {
	const root = await mkdtemp(path.join(tmpdir(), "nginxions-learning-"));
	await mkdir(path.join(root, "shop.example.com", "api"), { recursive: true });
	const gz = gzipSync(JSON.stringify({ confident_sets: [] }));
	await writeFile(path.join(root, "shop.example.com", "5.data"), gz);
	await writeFile(path.join(root, "shop.example.com", "api", "11.data"), "{}");
	const snapshot = await snapshotLearning(root);
	assert.deepEqual(
		snapshot.files.map((f) => [f.asset, f.name]),
		[
			["shop.example.com", "5.data"],
			["shop.example.com/api", "11.data"],
		],
	);
	assert.deepEqual(Buffer.from(snapshot.files[0].content, "base64"), gz);

	const restore = path.join(root, "..", `${path.basename(root)}-restore`);
	assert.equal(await stageRestore(snapshot, root, restore), 2);
	assert.deepEqual(await readFile(path.join(restore, "shop.example.com", "5.data")), gz);
	assert.deepEqual(await readdir(path.join(restore, "shop.example.com", "api")), ["11.data"]);
	// staged again: the previous staging is replaced, not merged
	assert.equal(await stageRestore({ files: [snapshot.files[1]] }, root, restore), 1);
	assert.deepEqual(await readdir(restore), ["shop.example.com"]);
	assert.deepEqual(await readdir(path.join(restore, "shop.example.com")), ["api"]);

	const file = (asset, name) => ({ asset, name, content: "" });
	assert.throws(() => checkSnapshot({ files: [file("../etc", "5.data")] }, root), /invalid asset/);
	assert.throws(() => checkSnapshot({ files: [file("a", "waap.data")] }, root), /unknown file/);
	assert.throws(() => checkSnapshot({ files: [file("a", "5.data"), file("a", "5.data")] }, root), /twice/);
	assert.throws(() => checkSnapshot({}, root), /no files/);
	await assert.rejects(stageRestore({ files: [file("/etc", "5.data")] }, root, restore), /invalid asset/);
});
