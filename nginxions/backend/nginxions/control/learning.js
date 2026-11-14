// What the agent learned (Agents -> open-appsec -> Learning), read only: the files the WAF of the agent keeps per asset
// in its data folder (Serializator.cc, BACKUP_DIRECTORY_PATH of WaapDefines.h), gzip-compressed cereal JSON. The
// asset of a location is a subfolder (asset ids hold a "/").
//   4.data  types of values normal for a parameter (TypeIndicatorsFilter)
//   5.data  indicators normal for a parameter (KeywordIndicatorFilter)
//   7.data  the same, learned from trusted sources (KeywordIndicatorFilter, trusted)
//   9.data  types learned from trusted sources (TypeIndicatorsFilter, trusted)
//  11.data  sources the scanner detector keeps out of learning (ScannerDetector)
import { open, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { gunzipSync } from "node:zlib";

export const LEARNING_DIR = process.env.NGINXIONS_AGENT_LEARNING_DIR || "/etc/cp/conf/waap";
export const LEARNED_FILES = ["4.data", "5.data", "7.data", "9.data", "11.data"];
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_DEPTH = 4;

export class LearningError extends Error {
	constructor(status, message) {
		super(message);
		this.status = status;
	}
}

/** the folder of an asset inside the data folder of the agent, or an error (no way out of it) */
export const assetDir = (asset, root = LEARNING_DIR) => {
	if (typeof asset !== "string" || !asset || asset.includes("\0") || asset.length > 512) {
		throw new LearningError(400, "invalid asset");
	}
	const base = path.resolve(root);
	const dir = path.resolve(base, asset);
	if (dir === base || !dir.startsWith(`${base}${path.sep}`)) throw new LearningError(400, "invalid asset");
	return dir;
};

/**
 * The assets with learned files: [{asset, files: [{name, size, modifiedAt}]}]
 * @param {string} [root]
 */
export const listLearning = async (root = LEARNING_DIR) => {
	const out = [];
	const walk = async (dir, depth) => {
		let entries;
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch (err) {
			if (err.code === "ENOENT") return;
			throw err;
		}
		const files = [];
		for (const e of entries) {
			if (e.isFile() && LEARNED_FILES.includes(e.name)) {
				const info = await stat(path.join(dir, e.name));
				files.push({ name: e.name, size: info.size, modifiedAt: info.mtime.toISOString() });
			} else if (e.isDirectory() && depth < MAX_DEPTH) {
				await walk(path.join(dir, e.name), depth + 1);
			}
		}
		if (files.length && dir !== root) {
			out.push({ asset: path.relative(root, dir).split(path.sep).join("/"), files });
		}
	};
	await walk(path.resolve(root), 0);
	return out.sort((a, b) => a.asset.localeCompare(b.asset));
};

/** the content of a file of the agent: gzip or plain JSON */
export const parseLearned = (buffer) => {
	const text =
		buffer[0] === 0x1f && buffer[1] === 0x8b ? gunzipSync(buffer).toString("utf8") : buffer.toString("utf8");
	return JSON.parse(text);
};

/**
 * One learned file of an asset: {modifiedAt, data}; null when the agent has not written it yet.
 * @param {string} asset
 * @param {string} name  one of LEARNED_FILES
 */
export const readLearning = async (asset, name, root = LEARNING_DIR) => {
	if (!LEARNED_FILES.includes(name)) throw new LearningError(400, "unknown file");
	const dir = assetDir(asset, root);
	let file;
	try {
		file = await open(path.join(dir, name), "r");
	} catch (err) {
		if (err.code === "ENOENT") return null;
		throw err;
	}
	// size, time and content of the same open file: the agent rewrites it in place
	try {
		const info = await file.stat();
		if (info.size > MAX_BYTES) throw new LearningError(413, "the file of the agent is too large");
		let data;
		try {
			data = parseLearned(await file.readFile());
		} catch {
			throw new LearningError(422, "the file of the agent is not readable");
		}
		return { modifiedAt: info.mtime.toISOString(), data };
	} finally {
		await file.close();
	}
};
