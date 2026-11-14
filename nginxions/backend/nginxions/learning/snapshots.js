// Snapshots of what the agent learned (docs/ROADMAP.md, phase 12; docs/adr/0011-learning.md): protection against
// poisoning of learning and the backup and transfer of the learned state.
//   - NginxionS takes a snapshot of the learned files of the agent (/etc/cp/conf/waap, read by nginxions-control) once a
//     day and on demand, and keeps them in its data volume (/data/nginxions/learning/snapshots): a backup of NginxionS
//     (its data volume) holds them;
//   - each snapshot is compared with the one before: an asset whose norm grew or shrank sharply is a shift, shown on
//     the page and told by the notification rule learning_shift;
//   - a snapshot is restored in place of the learned state (the agent and nginxions restart; the state before is
//     kept as a snapshot first), downloaded, and uploaded on another NginxionS (transfer).
// RBAC: who sees learning sees the snapshots; who labels takes and downloads them; restore, upload and delete also need
// waf_policy:manage (they change what the WAF blocks).
import { randomBytes } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import internalAuditLog from "../../internal/audit-log.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import control from "../control/client.js";
import { checkSnapshot, LearningError, MAX_SNAPSHOT_BYTES, parseLearned } from "../control/learning.js";
import { shiftOf, summarize } from "./model.js";

export const SNAPSHOT_DIR = process.env.NGINXIONS_LEARNING_SNAPSHOT_DIR || "/data/nginxions/learning/snapshots";
export const FORMAT = "nginxions-learning-snapshot";
export const REASONS = ["auto", "manual", "before-restore", "import"];
const KEEP_AUTO = 14;
const AUTO_MS = 24 * 3600 * 1000;
const CHECK_MS = 3600 * 1000;
const ID = /^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$/;

const newId = (date = new Date()) =>
	`${date
		.toISOString()
		.replace(/[-:]/g, "")
		.replace(/\.\d+Z$/, "Z")}-${randomBytes(3).toString("hex")}`;

const fileOf = (id, ext) => {
	if (!ID.test(id)) throw new errs.ValidationError("invalid snapshot id");
	return path.join(SNAPSHOT_DIR, `${id}.${ext}`);
};

/** the parsed learned files of a bundle; a file the agent wrote half (or not gzip-JSON) counts as empty */
const parsedFiles = (files) =>
	files.map((f) => {
		let data = null;
		try {
			data = parseLearned(Buffer.from(f.content, "base64"));
		} catch {
			// counted as nothing learned
		}
		return { asset: f.asset, name: f.name, data };
	});

const writeAtomic = async (file, content) => {
	const tmp = `${file}.tmp`;
	await writeFile(tmp, content, { mode: 0o600 });
	await rename(tmp, file);
};

/** the snapshots, the newest first: [{id, takenOn, reason, userId, size, files, assets, shift, restoredOn}] */
export const listSnapshots = async () => {
	let names;
	try {
		names = await readdir(SNAPSHOT_DIR);
	} catch (err) {
		if (err.code === "ENOENT") return [];
		throw err;
	}
	const metas = [];
	for (const name of names.filter((n) => n.endsWith(".meta.json"))) {
		try {
			metas.push(JSON.parse(await readFile(path.join(SNAPSHOT_DIR, name), "utf8")));
		} catch {
			// a broken description: the snapshot is not listed
		}
	}
	return metas.filter((m) => ID.test(m?.id ?? "")).sort((a, b) => b.takenOn.localeCompare(a.takenOn));
};

/**
 * Keeps a snapshot: its files (gzip JSON) and its description, compared with the newest snapshot before it.
 * @param {{files: {asset: string, name: string, modifiedAt?: string, content: string}[]}} bundle
 * @param {{reason: string, userId?: number, sourceTakenOn?: string}} info
 */
const keep = async (bundle, { reason, userId = 0, sourceTakenOn = null }) => {
	const files = bundle.files.map((f) => ({
		asset: f.asset,
		name: f.name,
		modifiedAt: f.modifiedAt ?? null,
		content: f.content,
	}));
	const assets = summarize(parsedFiles(files));
	const previous = (await listSnapshots())[0];
	const takenOn = new Date();
	const id = newId(takenOn);
	const payload = gzipSync(JSON.stringify({ format: FORMAT, version: 1, takenOn: takenOn.toISOString(), files }));
	const meta = {
		id,
		takenOn: takenOn.toISOString(),
		reason,
		userId,
		size: payload.length,
		files: files.length,
		assets,
		// the shift from the snapshot before (none for the first one)
		shift: previous ? shiftOf(previous.assets ?? [], assets) : [],
		comparedWith: previous?.id ?? null,
		sourceTakenOn,
		restoredOn: null,
	};
	await mkdir(SNAPSHOT_DIR, { recursive: true, mode: 0o700 });
	await writeAtomic(fileOf(id, "json.gz"), payload);
	await writeAtomic(fileOf(id, "meta.json"), JSON.stringify(meta));
	return meta;
};

/** the automatic snapshots beyond the newest KEEP_AUTO are deleted; the others stay until deleted in the GUI */
const prune = async () => {
	const autos = (await listSnapshots()).filter((m) => m.reason === "auto");
	for (const m of autos.slice(KEEP_AUTO)) {
		await rm(fileOf(m.id, "json.gz"), { force: true });
		await rm(fileOf(m.id, "meta.json"), { force: true });
	}
};

/**
 * A snapshot of what the agent learned now.
 * @param {string} reason
 * @param {number} [userId]
 */
export const takeSnapshot = async (reason, userId = 0) => {
	const meta = await keep(await control.snapshotAgentLearning(), { reason, userId });
	if (reason === "auto") await prune();
	if (meta.shift.length) {
		logger.warn(
			`Learning: a sharp shift of the norm of ${meta.shift.map((s) => s.asset).join(", ")} (snapshot ${meta.id})`,
		);
	}
	return meta;
};

/** the files of a kept snapshot */
const loadSnapshot = async (id) => {
	let content;
	try {
		content = await readFile(fileOf(id, "json.gz"));
	} catch (err) {
		if (err.code === "ENOENT") throw new errs.ItemNotFoundError(id);
		throw err;
	}
	return readPayload(content);
};

/** the content of a snapshot file (downloaded or uploaded), checked */
export const readPayload = (content) => {
	let payload;
	try {
		payload = JSON.parse(gunzipSync(content, { maxOutputLength: MAX_SNAPSHOT_BYTES * 2 }).toString("utf8"));
	} catch {
		throw new errs.ValidationError("not a snapshot of learning of NginxionS");
	}
	if (payload?.format !== FORMAT || payload.version !== 1) {
		throw new errs.ValidationError("not a snapshot of learning of NginxionS");
	}
	try {
		// assets inside the data folder of the agent, only learned files, sizes in bounds (as nginxions-control checks)
		checkSnapshot(payload, "/etc/cp/conf/waap");
	} catch (err) {
		if (err instanceof LearningError) throw new errs.ValidationError(`the snapshot: ${err.message}`);
		throw err;
	}
	return payload;
};

/** the latest snapshot with a shift, taken in the last two days: [{id, takenOn, asset, before, after, direction}] */
export const recentShifts = async (now = new Date()) => {
	const latest = (await listSnapshots()).find((m) => m.reason === "auto" || m.reason === "manual");
	if (!latest || now.getTime() - new Date(latest.takenOn).getTime() > 2 * AUTO_MS) return [];
	return (latest.shift ?? []).map((s) => ({ id: latest.id, takenOn: latest.takenOn, ...s }));
};

// ------------------------------------------------------------------ the daily snapshot
const autoDue = async (now = new Date()) => {
	const last = (await listSnapshots()).find((m) => m.reason === "auto");
	return !last || now.getTime() - new Date(last.takenOn).getTime() >= AUTO_MS;
};

let timer = null;
export const start = () => {
	if (timer) clearInterval(timer);
	const run = async () => {
		if (!(await autoDue())) return;
		// nothing learned yet: no snapshot
		if (!(await control.listAgentLearning()).length) return;
		await takeSnapshot("auto");
	};
	const tick = () => run().catch((err) => logger.warn(`Learning snapshots: ${err.message}`));
	timer = setInterval(tick, CHECK_MS);
	timer.unref?.();
	// the agent learns for a while after a start: the first check is in an hour, not at once
};

// ------------------------------------------------------------------ API
const audit = (access, meta) =>
	internalAuditLog.add(access, { action: "updated", object_type: "waf_learning", meta: { snapshot: meta } });

const canManage = async (access) => {
	await access.can("waf_learning:label");
	await access.can("waf_policy:manage");
};

const internalLearningSnapshots = {
	/** @param {Access} access */
	list: async (access) => {
		await access.can("waf_learning:view");
		return { snapshots: await listSnapshots(), keepAuto: KEEP_AUTO };
	},

	/** @param {Access} access */
	take: async (access) => {
		await access.can("waf_learning:label");
		const meta = await takeSnapshot("manual", access.token.getUserId(0));
		await audit(access, { action: "taken", id: meta.id });
		return meta;
	},

	/**
	 * The snapshot in place of the learned state of the agent: the state now is kept as a snapshot first, then the
	 * agent and nginxions restart (a minute without the WAF answering, as a restart of the agent).
	 * @param {Access} access
	 * @param {string} id
	 */
	restore: async (access, id) => {
		await canManage(access);
		const payload = await loadSnapshot(id);
		const before = await takeSnapshot("before-restore", access.token.getUserId(0));
		await control.restoreAgentLearning({ files: payload.files }, access.token.getUserId(0));
		const metaFile = fileOf(id, "meta.json");
		const meta = JSON.parse(await readFile(metaFile, "utf8"));
		meta.restoredOn = new Date().toISOString();
		await writeAtomic(metaFile, JSON.stringify(meta));
		await audit(access, { action: "restored", id, before: before.id });
		return { restored: id, before: before.id, restarting: true };
	},

	/**
	 * @param {Access} access
	 * @param {string} id
	 */
	remove: async (access, id) => {
		await canManage(access);
		const file = fileOf(id, "json.gz");
		await loadSnapshot(id);
		await rm(file, { force: true });
		await rm(fileOf(id, "meta.json"), { force: true });
		await audit(access, { action: "deleted", id });
		return true;
	},

	/**
	 * The file of a snapshot, for a backup or another NginxionS.
	 * @param {Access} access
	 * @param {string} id
	 */
	download: async (access, id) => {
		await access.can("waf_learning:label");
		await loadSnapshot(id);
		await audit(access, { action: "downloaded", id });
		return { name: `nginxions-learning-${id}.json.gz`, content: await readFile(fileOf(id, "json.gz")) };
	},

	/**
	 * A snapshot file of this or another NginxionS, kept as a snapshot (restored separately).
	 * @param {Access} access
	 * @param {Buffer|null} content
	 */
	upload: async (access, content) => {
		await canManage(access);
		if (!content?.length) throw new errs.ValidationError("no file");
		const payload = readPayload(content);
		const meta = await keep(payload, {
			reason: "import",
			userId: access.token.getUserId(0),
			sourceTakenOn: typeof payload.takenOn === "string" ? payload.takenOn.slice(0, 40) : null,
		});
		await audit(access, { action: "uploaded", id: meta.id });
		return meta;
	},
};

export default internalLearningSnapshots;
