// File Security of a practice of the WAF policy (docs/WAF-POLICY.md; Premium in open-appsec): uploads are checked by
// ClamAV (the clamav container, clamd on its port 3310) in nginx before they reach the server of the host
// (rootfs/usr/local/lua/nginxions/nginxions_files.lua, called from _common.conf of a host that has it).
//   - the rules per proxy host come from the policy: the rules of its domains (host and locations, the longest path
//     wins), else the default rule; written to /data/nginxions/files-security.json, nginx regenerates the hosts
//     and reloads when they change;
//   - clamd runs only while a rule has File Security on (1 GB of memory for its signatures): the flag "enabled" in
//     the control volume of clamav (deploy/clamav/nginxions-clamav.sh), clamav restarts when it changes;
//   - signatures: those of the image, files uploaded in WAF -> Agent (offline), or freshclam when online updates
//     are allowed there;
//   - the findings (nginx: /data/nginx/logs/nginxions-files.log) become security events.
import { mkdir, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import db from "../../db.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import control from "../control/client.js";
import { startJsonLog } from "../events/jsonlog.js";
import { getSetting, setSetting } from "../settings.js";
import { engineMode } from "./engines.js";

export const CONF_FILE = process.env.NGINXIONS_FILES_CONF || "/data/nginxions/files-security.json";
export const LOG_FILE = process.env.NGINXIONS_FILES_LOG || "/data/nginx/logs/nginxions-files.log";
/** the control volume of the clamav container (read only there) */
export const CONTROL_DIR = process.env.NGINXIONS_CLAMAV_DIR || "/var/lib/nginxions-clamav";
const CLAMD = { host: process.env.NGINXIONS_CLAMD_HOST || "clamav", port: 3310 };
const SERVICE = "clamav";
const CURSOR = "files:findings";
const SIGNATURE_FILE = /^[a-z0-9][a-z0-9_-]{0,63}\.(cvd|cld|cud)$/;
export const MAX_SIGNATURE_BYTES = 512 * 1024 * 1024;
const SEVERITIES = ["low", "medium", "high", "critical"];
const UNITS = { bytes: 1, KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 };
const list = (v) => (Array.isArray(v) ? v : []);
const parseJson = (v) => (typeof v === "string" ? JSON.parse(v) : v) || [];

/** an action of the practice for the mode of the engine: inherited is the mode */
const actionOf = (value, mode) => (!value || value === "inherited" ? mode : value);

/**
 * The rule of File Security of a rule of the policy, for nginx.
 * @param {object} rule  a rule of the policy (v1beta2)
 * @param {Map<string, object>} practices
 * @param {string} path  "" for the whole host
 */
export const fileRule = (rule, practices, path) => {
	const practice = practices.get(list(rule?.threatPreventionPractices)[0]);
	const mode = engineMode(practice, "fileSecurity", rule?.mode);
	if (mode === "inactive") return { path, mode };
	const fs = practice.fileSecurity ?? {};
	const large = fs.largeFileInspection ?? {};
	const limit = Number(large.fileSizeLimit ?? 10) * (UNITS[large.fileSizeLimitUnit ?? "MB"] ?? UNITS.MB);
	const archive = fs.archiveInspection ?? {};
	const archiveLimit =
		Number(archive.scanMaxFileSize ?? 10) * (UNITS[archive.scanMaxFileSizeUnit ?? "MB"] ?? UNITS.MB);
	return {
		path,
		mode,
		// the confidence of a signature of ClamAV (nginxions_files.lua): the action of the practice for it
		actions: {
			high: actionOf(fs.highConfidenceEventAction, mode),
			medium: actionOf(fs.mediumConfidenceEventAction, mode),
			low: actionOf(fs.lowConfidenceEventAction ?? "detect", mode),
		},
		max_bytes: Math.max(1, Math.round(limit)),
		large_action: actionOf(large.filesExceedingSizeLimitAction, mode),
		// a signature below it is not acted upon (the severity of its kind of malware, nginxions_files.lua)
		min_severity: SEVERITIES.includes(fs.minSeverityLevel) ? fs.minSeverityLevel : "medium",
		archives: {
			// off: an archive is not opened, so not scanned (as the agent, which only extracts when asked)
			extract: fs.archiveInspection?.extractArchiveFiles === true,
			max_bytes: Math.max(1, Math.round(archiveLimit)),
			nested_action: actionOf(fs.archiveInspection?.archivedFilesWithinArchivedFiles, mode),
			failed_action: actionOf(fs.archiveInspection?.archivedFilesWhereContentExtractionFailed, mode),
		},
		// a file whose name is not known: a body of a binary type with no name in Content-Disposition or the path
		unnamed_action: actionOf(fs.unnamedFilesAction, mode),
		// threat emulation: instead of the sandbox of Check Point, the deep static analysis of clamd counts (Office
		// macros, broken executables and media, partitions that intersect); off, these findings are left out
		deep: fs.threatEmulationEnabled === true,
	};
};

/**
 * The rules of File Security of each proxy host.
 * @param {object} doc  the policy (v1beta2, merged)
 * @param {{id: number, domains: string[]}[]} hosts  the enabled proxy hosts
 * @returns {{hosts: Record<string, object[]>, enabled: boolean}}  hosts: only those with a rule that is on
 */
export const filesRules = (doc, hosts) => {
	const practices = new Map(list(doc?.threatPreventionPractices).map((p) => [p.name, p]));
	const specific = list(doc?.policies?.specificRules).filter((r) => r?.host);
	const out = {};
	for (const h of hosts) {
		const domains = new Set(h.domains.map((d) => String(d).toLowerCase()));
		const rules = [];
		for (const r of specific) {
			const text = String(r.host);
			const slash = text.indexOf("/");
			const host = (slash === -1 ? text : text.slice(0, slash)).toLowerCase();
			if (!domains.has(host)) continue;
			const p = slash === -1 ? "" : text.slice(slash);
			rules.push(fileRule(r, practices, p === "/" ? "" : p));
		}
		if (!rules.length && doc?.policies?.default) rules.push(fileRule(doc.policies.default, practices, ""));
		// one rule a path (the domains of a host share them)
		const unique = [...new Map(rules.map((r) => [r.path, r])).values()];
		if (unique.some((r) => r.mode !== "inactive")) out[String(h.id)] = unique;
	}
	return { hosts: out, enabled: Object.keys(out).length > 0 };
};

// ---------------------------------------------------------------- the rules in force

let current = null;
const load = async () => {
	if (current) return current;
	try {
		current = JSON.parse(await readFile(CONF_FILE, "utf8"));
	} catch {
		current = { hosts: {}, enabled: false };
	}
	return current;
};

/** hook of internal/nginx.js: nginxions_files of the templates (the host has File Security) */
export const prepareHost = async (hostType, host) => {
	if (hostType !== "proxy_host" || !host?.id) return;
	const state = await load();
	host.nginxions_files = Boolean(state.hosts?.[String(host.id)]);
};

const exists = async (file) => {
	try {
		await readFile(file);
		return true;
	} catch {
		return false;
	}
};

/** clamd runs (the flag of the control volume) when a rule needs it; clamav restarts when that changes */
const setClamd = async (enabled) => {
	const flag = path.join(CONTROL_DIR, "enabled");
	if ((await exists(flag)) === enabled) return false;
	await mkdir(CONTROL_DIR, { recursive: true });
	if (enabled) await writeFile(flag, `${new Date().toISOString()}\n`);
	else await rm(flag, { force: true });
	await control
		.restartService(SERVICE)
		.catch((err) => logger.warn(`File Security: clamav not restarted: ${err.message}`));
	return true;
};

/**
 * The policy changed (waf/policy.js): the rules of File Security, the hosts of nginx that have them, clamd.
 * @param {object} doc  the policy (v1beta2, merged)
 */
export const applyFiles = async (doc) => {
	const rows = await db()("proxy_host").select("id", "domain_names").where({ is_deleted: 0, enabled: 1 });
	const next = filesRules(
		doc,
		rows.map((r) => ({ id: r.id, domains: parseJson(r.domain_names) })),
	);
	const before = await load();
	const changed = JSON.stringify(before) !== JSON.stringify(next);
	if (changed) {
		await mkdir(path.dirname(CONF_FILE), { recursive: true });
		await writeFile(`${CONF_FILE}.tmp`, JSON.stringify(next), { mode: 0o644 });
		await rename(`${CONF_FILE}.tmp`, CONF_FILE);
		current = next;
		// the hosts that get or lose the check, and the rules every worker reads at a reload
		const { regenerateAllHosts } = await import("../../setup.js");
		const internalNginx = (await import("../../internal/nginx.js")).default;
		await regenerateAllHosts(true);
		await internalNginx.reload();
		logger.info(`File Security: ${Object.keys(next.hosts).length} host(s)`);
	}
	await setClamd(next.enabled);
	return changed;
};

// ---------------------------------------------------------------- findings → security events

const str = (v, max = 255) => String(v ?? "").slice(0, max);

/** a line of nginxions-files.log → a row of nginxions_security_event */
export const toEvent = (line, nodeId = "local") => {
	if (!line?.time || !line.ip) return null;
	const time = new Date(line.time);
	if (Number.isNaN(time.getTime())) return null;
	const [uri, query = ""] = str(line.uri, 4096).split(/\?(.*)/s);
	const virus = str(line.signature);
	return {
		node_id: nodeId,
		time,
		kind: "security",
		name: virus ? `File Security: ${virus}` : `File Security: ${str(line.reason, 200)}`,
		severity: virus ? (line.confidence === "high" ? "critical" : "high") : "medium",
		priority: "",
		confidence: str(line.confidence, 32),
		action: line.action === "prevent" ? "Prevent" : "Detect",
		incident_type: "File Security",
		source_ip: str(line.ip, 64),
		source_port: null,
		proxy_ip: "",
		source_country: "",
		host: str(line.host).toLowerCase(),
		asset: "",
		method: str(line.method, 16),
		uri: uri.slice(0, 2048),
		query: query.slice(0, 2048),
		response_code: line.action === "prevent" ? 403 : null,
		location: "body",
		parameter: "",
		sample: str(`${virus || line.reason || ""}${line.size ? ` (${line.size} bytes)` : ""}`, 2048),
		indicators: virus,
		score: null,
		rule: virus,
		practice: "",
		override: "",
		service: "File Security (ClamAV)",
		raw: JSON.stringify(line).slice(0, 64 * 1024),
	};
};

export const startFilesLog = () => startJsonLog({ name: "File Security", file: LOG_FILE, cursor: CURSOR, toEvent });

// ---------------------------------------------------------------- clamd and its signatures

/** a command of clamd (zVERSION...) and its answer; null if it does not answer */
export const clamdCommand = (command, { host = CLAMD.host, port = CLAMD.port, timeoutMs = 3000 } = {}) =>
	new Promise((resolve) => {
		const socket = net.connect({ host, port });
		let data = "";
		const done = (value) => {
			socket.destroy();
			resolve(value);
		};
		socket.setTimeout(timeoutMs, () => done(null));
		socket.on("error", () => done(null));
		socket.on("connect", () => socket.write(`z${command}\0`));
		socket.on("data", (chunk) => {
			data += chunk.toString("utf8");
		});
		socket.on("end", () => done(data.replace(/\0/g, "").trim() || null));
	});

// imported when used: the audit log loads the JWT keys, which the policy generator (and its tests) do not need
const audit = async (access, action, meta) => {
	const { default: internalAuditLog } = await import("../../internal/audit-log.js");
	return internalAuditLog.add(access, { action, object_type: "waf", meta });
};

const internalWafFiles = {
	/** @param {Access} access */
	status: async (access) => {
		await access.can("waf_policy:view");
		const state = await load();
		const version = state.enabled ? await clamdCommand("VERSION") : null;
		let uploaded = [];
		try {
			uploaded = (await readdir(path.join(CONTROL_DIR, "db"))).filter((n) => SIGNATURE_FILE.test(n));
		} catch {
			// none yet
		}
		return {
			enabled: state.enabled,
			hosts: Object.keys(state.hosts ?? {}).length,
			clamd: version,
			uploaded,
			settings: await getSetting("waf.files"),
		};
	},

	/**
	 * A signature file of ClamAV (main.cvd, daily.cvd, bytecode.cvd...), used from the next start of clamd.
	 * @param {Access} access
	 * @param {string} name
	 * @param {Buffer} content
	 */
	uploadSignatures: async (access, name, content) => {
		await access.can("waf_policy:manage");
		if (!SIGNATURE_FILE.test(String(name))) {
			throw new errs.ValidationError(
				"a signature file of ClamAV is named like main.cvd, daily.cld or bytecode.cvd",
			);
		}
		if (!content?.length) throw new errs.ValidationError("the file is empty");
		// a .cvd/.cld starts with its header "ClamAV-VDB:"
		if (!content.subarray(0, 11).equals(Buffer.from("ClamAV-VDB:"))) {
			throw new errs.ValidationError("not a signature database of ClamAV (no ClamAV-VDB header)");
		}
		const dir = path.join(CONTROL_DIR, "db");
		await mkdir(dir, { recursive: true });
		await writeFile(path.join(dir, `${name}.tmp`), content);
		await rename(path.join(dir, `${name}.tmp`), path.join(dir, name));
		await audit(access, "updated", { clamav: name });
		if ((await load()).enabled) await control.restartService(SERVICE, access.token.getUserId(1)).catch(() => {});
		return { name, size: content.length };
	},

	/**
	 * Online updates of the signatures (freshclam, needs the internet) on or off.
	 * @param {Access} access
	 * @param {{online_updates: boolean}} data
	 */
	setSettings: async (access, data) => {
		await access.can("waf_policy:manage");
		const settings = { online_updates: data?.online_updates === true };
		await setSetting("waf.files", settings);
		await mkdir(CONTROL_DIR, { recursive: true });
		const flag = path.join(CONTROL_DIR, "freshclam");
		if (settings.online_updates) await writeFile(flag, "on\n");
		else await rm(flag, { force: true });
		await audit(access, "updated", { clamav: settings });
		if ((await load()).enabled) await control.restartService(SERVICE, access.token.getUserId(1)).catch(() => {});
		return settings;
	},
};

export default internalWafFiles;
