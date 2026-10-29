// CrowdSec hub without cscli: the index with content (.index.json of `cscli hub update
// --with-content`) lies in the config volume, which NPMOS mounts at the same path as the crowdsec
// container. An item is installed the way cscli does it: its content in hub/<path>, a symlink in
// <type>/[<stage>/]<file>, its data files in the data directory. Collections bring their items.
// Without internet the data files must already be there (offline seed or an uploaded snapshot).
import { createHash } from "node:crypto";
import { lstat, mkdir, readdir, readFile, readlink, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";

export const CONF_DIR = process.env.NPMOS_CROWDSEC_CONF_DIR || "/etc/crowdsec";
export const DATA_DIR = process.env.NPMOS_CROWDSEC_DATA_DIR || "/var/lib/crowdsec/data";
export const ONLINE_INDEX_URL = "https://cdn-hub.crowdsec.net/crowdsecurity/master/.index.json?with_content=true";
const DOWNLOAD_TIMEOUT_MS = 60000;
const MAX_DATA_BYTES = 256 * 1024 * 1024;

export const TYPES = [
	"collections",
	"parsers",
	"postoverflows",
	"scenarios",
	"contexts",
	"appsec-configs",
	"appsec-rules",
];
const STAGED = ["parsers", "postoverflows"];

export class HubError extends Error {}

let cache = { mtime: 0, dir: "", index: null };

const indexFile = (dir = CONF_DIR) => path.join(dir, "hub", ".index.json");

/** @returns {Promise<Record<string, Record<string, object>>>} */
export const loadIndex = async (dir = CONF_DIR) => {
	const file = indexFile(dir);
	let st;
	try {
		st = await stat(file);
	} catch {
		throw new HubError("The hub index is missing: upload a hub snapshot");
	}
	if (cache.index && cache.dir === dir && cache.mtime === st.mtimeMs) return cache.index;
	const index = parseIndex(await readFile(file, "utf8"));
	cache = { mtime: st.mtimeMs, dir, index };
	return index;
};

/** checks that a text is a hub index with content */
export const parseIndex = (text) => {
	let index;
	try {
		index = JSON.parse(text);
	} catch {
		throw new HubError("The hub index is not JSON");
	}
	if (!index || typeof index !== "object" || !index.collections || !index.parsers || !index.scenarios) {
		throw new HubError("Not a CrowdSec hub index");
	}
	const sample = Object.values(index.collections)[0];
	if (sample && typeof sample.content !== "string") {
		throw new HubError("The hub index has no content (made without --with-content)");
	}
	return index;
};

const safeRel = (p) => {
	const n = path.posix.normalize(String(p));
	if (!n || n.startsWith("..") || path.posix.isAbsolute(n)) throw new HubError(`Unsafe path in the hub: ${p}`);
	return n;
};

const getItem = (index, type, name) => {
	const item = index[type]?.[name];
	if (!item) throw new HubError(`${type}/${name} is not in the hub`);
	return item;
};

export const linkPath = (type, item, dir = CONF_DIR) => {
	const file = path.posix.basename(safeRel(item.path));
	return STAGED.includes(type)
		? path.join(dir, type, safeRel(item.stage || "s01-parse"), file)
		: path.join(dir, type, file);
};

export const hubPath = (item, dir = CONF_DIR) => path.join(dir, "hub", safeRel(item.path));

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** sub-items of a collection: [[type, name]] */
export const children = (item) =>
	TYPES.flatMap((type) => (Array.isArray(item[type]) ? item[type].map((name) => [type, name]) : []));

/** data files of an item: [{source_url, dest_file}] */
export const dataFiles = (content) => {
	const files = [];
	try {
		for (const doc of YAML.parseAllDocuments(content)) {
			const data = doc.toJS()?.data;
			if (Array.isArray(data)) {
				for (const d of data) {
					if (d?.dest_file)
						files.push({ source_url: String(d.source_url || ""), dest_file: safeRel(d.dest_file) });
				}
			}
		}
	} catch (err) {
		if (err instanceof HubError) throw err;
	}
	return files;
};

const exists = async (p) => {
	try {
		await stat(p);
		return true;
	} catch {
		return false;
	}
};

/**
 * State of an item on disk.
 * installed: "hub" (symlink of cscli or NPMOS), "local" (a file of its own, never touched), false
 * @returns {Promise<{installed: false|"hub"|"local", version: string|null, status: string}>}
 */
export const itemState = async (type, item, dir = CONF_DIR) => {
	const link = linkPath(type, item, dir);
	let st;
	try {
		st = await lstat(link);
	} catch {
		return { installed: false, version: null, status: "" };
	}
	if (!st.isSymbolicLink()) return { installed: "local", version: null, status: "local" };
	let content;
	try {
		content = await readFile(path.resolve(path.dirname(link), await readlink(link)));
	} catch {
		return { installed: "hub", version: null, status: "broken" };
	}
	const digest = sha256(content);
	// versions may share a digest (unchanged content): the latest one wins
	const version =
		item.versions?.[item.version]?.digest === digest
			? item.version
			: Object.entries(item.versions || {}).findLast(([, v]) => v.digest === digest)?.[0] || null;
	if (!version) return { installed: "hub", version: null, status: "tainted" };
	return { installed: "hub", version, status: version === item.version ? "up-to-date" : "outdated" };
};

/**
 * All items with their state.
 * @param {{type?: string, query?: string, installed?: boolean}} [filter]
 */
export const list = async (filter = {}, dir = CONF_DIR) => {
	const index = await loadIndex(dir);
	const states = new Map();
	for (const type of TYPES) {
		for (const [name, item] of Object.entries(index[type] || {})) {
			states.set(`${type}:${name}`, { type, name, item, state: await itemState(type, item, dir) });
		}
	}
	// collections that bring an item
	const neededBy = new Map();
	for (const { type, name, item, state } of states.values()) {
		if (type !== "collections" || !state.installed) continue;
		for (const [t, n] of children(item)) {
			const key = `${t}:${n}`;
			neededBy.set(key, [...(neededBy.get(key) || []), name]);
		}
	}
	const q = (filter.query || "").toLowerCase();
	const items = [];
	for (const [key, { type, name, item, state }] of states) {
		if (filter.type && type !== filter.type) continue;
		if (filter.installed && !state.installed) continue;
		if (
			q &&
			!name.toLowerCase().includes(q) &&
			!String(item.description || "")
				.toLowerCase()
				.includes(q)
		)
			continue;
		items.push({
			type,
			name,
			description: String(item.description || ""),
			latest: item.version || "",
			installed: state.installed,
			version: state.version,
			status: state.status,
			needed_by: neededBy.get(key) || [],
		});
	}
	return items;
};

/**
 * Items to install for one item: itself and, for a collection, everything it brings
 * @returns {[string, string, object][]}
 */
export const plan = (index, type, name, seen = new Set()) => {
	const key = `${type}:${name}`;
	if (seen.has(key)) return [];
	seen.add(key);
	const item = getItem(index, type, name);
	const result = [[type, name, item]];
	for (const [t, n] of children(item)) result.push(...plan(index, t, n, seen));
	return result;
};

const download = async (url, dest) => {
	if (!/^https:\/\//.test(url)) throw new HubError(`Not an https URL: ${url}`);
	const response = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
	if (!response.ok) throw new HubError(`${url}: HTTP ${response.status}`);
	const body = Buffer.from(await response.arrayBuffer());
	if (body.length > MAX_DATA_BYTES) throw new HubError(`${url}: larger than 256 MB`);
	await mkdir(path.dirname(dest), { recursive: true });
	await writeFile(`${dest}.tmp`, body);
	await rename(`${dest}.tmp`, dest);
};

/**
 * Installs an item with its dependencies. Local items of the same file name are left alone.
 * @param {{online?: boolean, dir?: string, dataDir?: string}} [options]  online: download missing data files
 * @returns {Promise<string[]>} installed or updated items
 */
export const install = async (type, name, { online = false, dir = CONF_DIR, dataDir = DATA_DIR } = {}) => {
	const index = await loadIndex(dir);
	const items = plan(index, type, name);
	const missing = [];
	for (const [, , item] of items) {
		for (const d of dataFiles(item.content || "")) {
			const dest = path.join(dataDir, d.dest_file);
			if (await exists(dest)) continue;
			if (online && d.source_url) {
				try {
					await download(d.source_url, dest);
					continue;
				} catch (err) {
					missing.push(`${d.dest_file} (${err.message})`);
					continue;
				}
			}
			missing.push(d.dest_file);
		}
	}
	if (missing.length) {
		throw new HubError(
			`Data files are missing: ${[...new Set(missing)].join(", ")}. Upload a hub snapshot with them${online ? "" : " or allow online hub updates"}.`,
		);
	}
	const done = [];
	for (const [t, n, item] of items) {
		const state = await itemState(t, item, dir);
		if (state.installed === "local") continue;
		if (typeof item.content !== "string") throw new HubError(`${t}/${n} has no content in the index`);
		const target = hubPath(item, dir);
		await mkdir(path.dirname(target), { recursive: true });
		if (state.status !== "up-to-date") {
			await writeFile(`${target}.tmp`, item.content);
			await rename(`${target}.tmp`, target);
		}
		const link = linkPath(t, item, dir);
		if (!state.installed) {
			await mkdir(path.dirname(link), { recursive: true });
			await symlink(target, link);
		}
		if (state.status !== "up-to-date") done.push(`${t}/${n}`);
	}
	return done;
};

/**
 * Removes an item; for a collection also the items it brought that no other installed collection
 * needs. Local files are never removed.
 * @returns {Promise<string[]>} removed items
 */
export const remove = async (type, name, { dir = CONF_DIR } = {}) => {
	const index = await loadIndex(dir);
	const item = getItem(index, type, name);
	const state = await itemState(type, item, dir);
	if (state.installed === "local") throw new HubError(`${type}/${name} is a local file, not a hub item`);
	if (!state.installed) return [];
	const keep = new Set();
	for (const [n, c] of Object.entries(index.collections)) {
		if (type === "collections" && n === name) continue;
		if ((await itemState("collections", c, dir)).installed) {
			for (const [t, sub] of plan(index, "collections", n)) keep.add(`${t}:${sub}`);
		}
	}
	const removed = [];
	for (const [t, n, it] of type === "collections" ? plan(index, type, name) : [[type, name, item]]) {
		if (`${t}:${n}` !== `${type}:${name}` && keep.has(`${t}:${n}`)) continue;
		const st = await itemState(t, it, dir);
		if (st.installed !== "hub") continue;
		await rm(linkPath(t, it, dir), { force: true });
		removed.push(`${t}/${n}`);
	}
	return removed;
};

/** writes content of the current index for installed, outdated items */
export const upgradeAll = async ({ dir = CONF_DIR } = {}) => {
	const index = await loadIndex(dir);
	const upgraded = [];
	for (const type of TYPES) {
		for (const [name, item] of Object.entries(index[type] || {})) {
			const state = await itemState(type, item, dir);
			if (state.installed === "hub" && state.status === "outdated" && typeof item.content === "string") {
				await writeFile(hubPath(item, dir), item.content);
				upgraded.push(`${type}/${name}`);
			}
		}
	}
	return upgraded;
};

/** replaces the index (the content of installed items changes only with upgradeAll) */
export const writeIndex = async (text, { dir = CONF_DIR } = {}) => {
	const index = parseIndex(text);
	const file = indexFile(dir);
	await mkdir(path.dirname(file), { recursive: true });
	await writeFile(`${file}.tmp`, text);
	await rename(`${file}.tmp`, file);
	cache = { mtime: 0, dir: "", index: null };
	return TYPES.reduce((n, t) => n + Object.keys(index[t] || {}).length, 0);
};

/** copies the data files of an unpacked snapshot (only names, no subdirectories) */
export const copyData = async (srcDir, { dataDir = DATA_DIR } = {}) => {
	let n = 0;
	let names = [];
	try {
		names = await readdir(srcDir, { withFileTypes: true });
	} catch {
		return 0;
	}
	await mkdir(dataDir, { recursive: true });
	for (const e of names) {
		// the database of CrowdSec is never replaced
		if (!e.isFile() || e.name.startsWith("crowdsec.db")) continue;
		const body = await readFile(path.join(srcDir, e.name));
		await writeFile(path.join(dataDir, `${e.name}.tmp`), body);
		await rename(path.join(dataDir, `${e.name}.tmp`), path.join(dataDir, e.name));
		n++;
	}
	return n;
};

/** hub index from the CrowdSec CDN (online hub updates, enabled by the administrator) */
export const fetchOnlineIndex = async () => {
	let response;
	try {
		response = await fetch(ONLINE_INDEX_URL, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS) });
	} catch (err) {
		throw new HubError(`The CrowdSec hub is unreachable: ${err.cause?.code || err.message}`);
	}
	if (!response.ok) throw new HubError(`The CrowdSec hub answered HTTP ${response.status}`);
	return response.text();
};
