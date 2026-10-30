// CrowdSec in the GUI of NPMOS (docs/ROADMAP.md, phase 7; docs/adr/0010-crowdsec.md), instead of
// the CrowdSec Console and cscli: alerts, decisions (ban and unban by hand, in bulk), machines,
// bouncers, metrics, the hub, settings (sources, profiles, allowlist, AppSec, the bouncer of
// NPMOS), local blocklists and the hosts the bouncer leaves out. Fully local: the hub is updated
// from an uploaded snapshot, or online only when the administrator allows it.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import internalNginx from "../../internal/nginx.js";
import internalProxyHostAccessList from "../../internal/proxy-host-access-list.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import deadHostModel from "../../models/dead_host.js";
import proxyHostModel from "../../models/proxy_host.js";
import redirectionHostModel from "../../models/redirection_host.js";
import { EVENT_TABLE } from "../events/store.js";
import { encrypt } from "../secrets.js";
import { getSetting, setSetting } from "../settings.js";
import { OWN_SCENARIO, alertsStatus, startAlerts } from "./alerts.js";
import { apply, pending } from "./apply.js";
import { dueLists, scenarioOf, syncList } from "./blocklists.js";
import { HOST_TYPES, applyBouncer, perHostSupported } from "./bouncer.js";
import { ConfigError, DECISION_TYPES, durationMinutes, normalize, normalizeIpOrCidr, requiredItems } from "./config.js";
import * as hub from "./hub.js";
import * as lapi from "./lapi.js";
import { exportText, parseList } from "./lists.js";

const run = promisify(execFile);
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;
const BLOCKLIST_TIMER_MS = 5 * 60000;
const NAME = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/;

/** errors of CrowdSec and of the input become 400 with their text */
const wrap = async (fn) => {
	try {
		return await fn();
	} catch (err) {
		if (
			err instanceof ConfigError ||
			err instanceof hub.HubError ||
			err instanceof lapi.LapiError ||
			err.rolledBack
		) {
			throw new errs.ValidationError(err.message);
		}
		throw err;
	}
};

/** stored settings with the defaults of newer versions of NPMOS */
const settings = async () => normalize(await getSetting("crowdsec"));

/** settings for the GUI: the captcha secret never leaves NPMOS */
const publicSettings = (s) => ({
	...s,
	bouncer: {
		...s.bouncer,
		captcha: { ...s.bouncer.captcha, secret_key: "", has_secret: !!s.bouncer.captcha.secret_key },
	},
});

const hostModel = (type) =>
	({ proxy_host: proxyHostModel, redirection_host: redirectionHostModel, dead_host: deadHostModel })[type];

const reconfigure = async (hostType, id) => {
	const model = hostModel(hostType);
	const row = await model.query().where({ id, is_deleted: 0 }).withGraphFetched(model.defaultAllowGraph).first();
	if (!row) throw new errs.ItemNotFoundError(id);
	if (!row.enabled) return null;
	let host = row;
	if (hostType === "proxy_host") {
		host = await internalProxyHostAccessList.populateLocationAccessLists(
			internalProxyHostAccessList.cleanAccessListTypes(row),
		);
	}
	const meta = await internalNginx.configure(model, hostType, host);
	return { nginx_online: meta.nginx_online, nginx_err: meta.nginx_err };
};

const hostLabel = (host, id) => {
	let names = host.domain_names;
	if (typeof names === "string") {
		try {
			names = JSON.parse(names);
		} catch {
			names = [names];
		}
	}
	return (Array.isArray(names) && names[0]) || `#${id}`;
};

const audit = (access, action, meta) => internalAuditLog.add(access, { action, object_type: "crowdsec", meta });

const sum = (rows, name, filter = () => true) =>
	rows.filter((r) => r.name === name && filter(r.labels)).reduce((n, r) => n + r.value, 0);

const groupSum = (rows, name, label) => {
	const out = {};
	for (const r of rows) if (r.name === name) out[r.labels[label] || ""] = (out[r.labels[label] || ""] || 0) + r.value;
	return Object.entries(out)
		.map(([key, value]) => ({ key, value }))
		.sort((a, b) => b.value - a.value);
};

/** metrics of Prometheus that the GUI shows (cscli metrics) */
export const summarizeMetrics = (rows) => ({
	version: rows.find((r) => r.name === "cs_info")?.labels.version || "",
	lines_read: groupSum(rows, "cs_filesource_hits_total", "source"),
	lines_parsed: sum(rows, "cs_parser_hits_ok_total"),
	lines_unparsed: sum(rows, "cs_parser_hits_ko_total"),
	overflows: groupSum(rows, "cs_bucket_overflowed_total", "name").slice(0, 20),
	bouncer_requests: groupSum(rows, "cs_lapi_bouncer_requests_total", "bouncer"),
	machine_requests: groupSum(rows, "cs_lapi_machine_requests_total", "machine"),
	decisions: groupSum(rows, "cs_active_decisions", "origin"),
	appsec_requests: sum(rows, "cs_appsec_reqs_total"),
	appsec_blocked: sum(rows, "cs_appsec_block_total"),
});

const allowlistOf = async () => (await settings()).allowlist.ips;

const values = (list) => {
	if (!Array.isArray(list) || !list.length) throw new errs.ValidationError("No addresses");
	if (list.length > 10000) throw new errs.ValidationError("Up to 10000 addresses at once");
	const result = [];
	for (const v of list) {
		const n = normalizeIpOrCidr(v);
		if (!n) throw new errs.ValidationError(`Not an IP or CIDR: ${v}`);
		if (!result.includes(n)) result.push(n);
	}
	return result;
};

const checkBlocklist = (data, old = {}) => {
	const row = { ...old, ...data };
	if (typeof row.name !== "string" || !NAME.test(row.name))
		throw new errs.ValidationError("Name: up to 64 characters, A-Z 0-9 space _ . -");
	if (!["file", "url"].includes(row.source)) throw new errs.ValidationError("Source: file or url");
	if (row.source === "url" && !/^https?:\/\/\S{1,990}$/.test(row.url || ""))
		throw new errs.ValidationError("Invalid URL");
	if (!DECISION_TYPES.includes(row.decision)) throw new errs.ValidationError("Decision: ban or captcha");
	try {
		durationMinutes(row.duration);
	} catch (err) {
		throw new errs.ValidationError(err.message);
	}
	if (!Number.isInteger(row.refresh_minutes) || row.refresh_minutes < 0 || row.refresh_minutes > 43200) {
		throw new errs.ValidationError("Refresh: 0–43200 minutes");
	}
	if (row.source === "file" && typeof row.content === "string" && row.content.length > 20 * 1024 * 1024) {
		throw new errs.ValidationError("The list is larger than 20 MB");
	}
	return row;
};

const blocklistOut = (r) => ({
	id: r.id,
	created_on: r.created_on,
	modified_on: r.modified_on,
	name: r.name,
	enabled: !!r.enabled,
	source: r.source,
	url: r.url,
	has_token: !!r.token_enc,
	insecure: !!r.insecure,
	lines:
		r.source === "file"
			? String(r.content || "")
					.split("\n")
					.filter((l) => l.trim()).length
			: null,
	decision: r.decision,
	duration: r.duration,
	refresh_minutes: r.refresh_minutes,
	synced_on: r.synced_on,
	count: r.count,
	error: r.error,
});

const tokenHash = (token) => createHash("sha256").update(token).digest("hex");

/** ban counts of hosts from CrowdSec alerts with a decision, last 24 h */
export const bansByHost = async () => {
	const rows = await db()(EVENT_TABLE)
		.select("host")
		.count({ n: "*" })
		.where("kind", "crowdsec")
		.whereIn("action", DECISION_TYPES)
		.andWhere("time", ">=", new Date(Date.now() - 86400000))
		.groupBy("host");
	return Object.fromEntries(rows.filter((r) => r.host).map((r) => [r.host, Number(r.n)]));
};

const applyAll = async (access, s, { force = false } = {}) => {
	const result = await apply(s, { actor: access?.token.getUserId(1), force, online: s.online_hub });
	const bouncer = await applyBouncer(s);
	return { ...result, bouncer_changed: bouncer.changed };
};

const internalCrowdsec = {
	/** @param {Access} access */
	overview: async (access) => {
		await access.can("crowdsec:view");
		const s = await settings();
		const out = {
			settings: {
				bouncer: s.bouncer.enabled,
				sources: s.sources,
				appsec: s.appsec.enabled,
				openappsec_ban: s.openappsec_ban,
			},
			lapi: { healthy: false, error: "" },
			metrics: null,
			machines: [],
			bouncers: [],
			decisions: { total: 0, by_origin: {}, by_type: {} },
			alerts_24h: 0,
			hub: { installed: 0, outdated: 0, error: "" },
			alerts_ingest: alertsStatus(),
			pending: [],
		};
		try {
			await lapi.health();
			out.lapi.healthy = true;
		} catch (err) {
			out.lapi.error = err.message;
		}
		const tasks = [
			lapi.metrics().then((m) => {
				out.metrics = summarizeMetrics(m);
			}),
			lapi.registry().then((r) => {
				out.machines = r.machines;
				out.bouncers = r.bouncers;
			}),
			lapi.decisions().then((list) => {
				out.decisions.total = list.length;
				for (const d of list) {
					out.decisions.by_origin[d.origin] = (out.decisions.by_origin[d.origin] || 0) + 1;
					out.decisions.by_type[d.type] = (out.decisions.by_type[d.type] || 0) + 1;
				}
			}),
			hub.list({ installed: true }).then((items) => {
				out.hub.installed = items.length;
				out.hub.outdated = items.filter((i) => i.status === "outdated").length;
			}),
			db()(EVENT_TABLE)
				.count({ n: "*" })
				.where("kind", "crowdsec")
				.andWhere("time", ">=", new Date(Date.now() - 86400000))
				.first()
				.then((r) => {
					out.alerts_24h = Number(r?.n || 0);
				}),
			pending(s).then((p) => {
				out.pending = Object.keys(p);
			}),
		];
		const results = await Promise.allSettled(tasks);
		const failed = results.filter((r) => r.status === "rejected").map((r) => r.reason?.message);
		if (results[3].status === "rejected") out.hub.error = results[3].reason?.message || "";
		out.errors = failed;
		return out;
	},

	/** @param {Access} access */
	getSettings: async (access) => {
		await access.can("crowdsec:view");
		const s = await settings();
		return {
			...publicSettings(s),
			pending: Object.keys(await pending(s).catch(() => ({}))),
			per_host: perHostSupported(),
			share_enabled: !!(await getSetting("crowdsec.share")).token_hash,
		};
	},

	/**
	 * @param {Access}  access
	 * @param {object}  data
	 * @param {boolean} [doApply]  write the files and restart CrowdSec now
	 */
	setSettings: async (access, data, doApply = true) => {
		await access.can("crowdsec:manage");
		return wrap(async () => {
			const old = await settings();
			const secret = String(data?.bouncer?.captcha?.secret_key ?? "").trim();
			const next = normalize({
				...data,
				bouncer: { ...data.bouncer, captcha: { ...data.bouncer?.captcha, secret_key: secret } },
			});
			if (next.bouncer.captcha.provider && !secret && !old.bouncer.captcha.secret_key) {
				throw new ConfigError("The captcha needs a secret key");
			}
			next.bouncer.captcha.secret_key = !next.bouncer.captcha.provider
				? ""
				: secret
					? encrypt(secret)
					: old.bouncer.captcha.secret_key;
			const saved = await setSetting("crowdsec", next);
			let result = { applied: false };
			if (doApply) {
				try {
					result = { applied: true, ...(await applyAll(access, saved)) };
				} catch (err) {
					// the files are the previous ones again: so are the settings
					await setSetting("crowdsec", old);
					await applyBouncer(old).catch(() => {});
					throw err;
				}
			}
			const { secret_key: _s, ...captcha } = saved.bouncer.captcha;
			await audit(access, "updated", { name: "settings", ...saved, bouncer: { ...saved.bouncer, captcha } });
			return { ...publicSettings(saved), result };
		});
	},

	/** @param {Access} access */
	apply: async (access) => {
		await access.can("crowdsec:manage");
		return wrap(async () => {
			const result = await applyAll(access, await settings(), { force: true });
			await audit(access, "applied", { name: "settings" });
			return result;
		});
	},

	/**
	 * @param {Access} access
	 * @param {{ip?, scenario?, since?, limit?, all?: boolean, active?: boolean}} query
	 */
	alerts: async (access, query) => {
		await access.can("crowdsec:view");
		return wrap(async () => {
			const limit = Math.min(Number(query.limit) || 200, 1000);
			const params = { limit: query.all ? limit : limit * 2, since: query.since || undefined };
			if (query.ip) params.ip = query.ip;
			if (query.scenario) params.scenario = query.scenario;
			if (query.active) params.has_active_decision = true;
			const list = (await lapi.alerts(params))
				.filter((a) => query.all || !OWN_SCENARIO.test(a.scenario || ""))
				.slice(0, limit);
			return list.map((a) => ({
				id: a.id,
				created_at: a.created_at,
				start_at: a.start_at,
				stop_at: a.stop_at,
				scenario: a.scenario,
				message: a.message,
				machine_id: a.machine_id,
				events_count: a.events_count,
				simulated: !!a.simulated,
				source: a.source || {},
				decisions: (a.decisions || []).map((d) => ({
					id: d.id,
					type: d.type,
					value: d.value,
					duration: d.duration,
					origin: d.origin,
				})),
				meta: (a.meta || []).map((m) => ({ key: m.key, value: m.value })),
			}));
		});
	},

	/** @param {Access} access */
	alert: async (access, id) => {
		await access.can("crowdsec:view");
		return wrap(() => lapi.alert(id));
	},

	/**
	 * Active decisions, filtered and paginated here (the LAPI returns them all at once).
	 * @param {Access} access
	 * @param {{q?, type?, origin?, offset?, limit?}} query
	 */
	decisions: async (access, query) => {
		await access.can("crowdsec:view");
		return wrap(async () => {
			const q = String(query.q || "").toLowerCase();
			const list = (await lapi.decisions()).filter(
				(d) =>
					(!query.type || d.type === query.type) &&
					(!query.origin || d.origin === query.origin) &&
					(!q || String(d.value).toLowerCase().includes(q) || String(d.scenario).toLowerCase().includes(q)),
			);
			list.sort((a, b) => Number(b.id) - Number(a.id));
			const offset = Math.max(0, Number(query.offset) || 0);
			const limit = Math.min(Math.max(1, Number(query.limit) || 100), 1000);
			return { total: list.length, items: list.slice(offset, offset + limit) };
		});
	},

	/**
	 * Ban (or captcha) by hand, one or many addresses.
	 * @param {Access} access
	 * @param {{values: string[], type?: string, duration?: string, reason?: string}} data
	 */
	ban: async (access, data) => {
		await access.can("crowdsec:decide");
		return wrap(async () => {
			const list = values(data.values);
			const type = data.type || "ban";
			const duration = data.duration || "4h";
			if (!DECISION_TYPES.includes(type)) throw new errs.ValidationError("Decision: ban or captcha");
			durationMinutes(duration);
			const reason = String(data.reason || "").slice(0, 200);
			const user = access.token.getUserId(0);
			for (let i = 0; i < list.length; i += 1000) {
				await lapi.pushDecisions({
					scenario: "npmos/manual",
					origin: "cscli",
					message: `NPMOS: ${type} by user ${user}${reason ? `: ${reason}` : ""}`,
					decisions: list
						.slice(i, i + 1000)
						.map((value) => ({ scope: value.includes("/") ? "Range" : "Ip", value, type, duration })),
				});
			}
			await audit(access, type === "ban" ? "banned" : "captcha", {
				name: list.length === 1 ? list[0] : `${list.length} addresses`,
				values: list.slice(0, 100),
				duration,
				reason,
			});
			return { count: list.length };
		});
	},

	/**
	 * Unban: decisions by id, or every decision of these addresses.
	 * @param {Access} access
	 * @param {{ids?: number[], values?: string[]}} data
	 */
	unban: async (access, data) => {
		await access.can("crowdsec:decide");
		return wrap(async () => {
			let deleted = 0;
			const ids = Array.isArray(data.ids) ? data.ids.filter((id) => Number.isInteger(id) && id > 0) : [];
			for (const id of ids) {
				const r = await lapi.deleteDecision(id);
				deleted += Number(r?.nbDeleted || 0);
			}
			const list = data.values?.length ? values(data.values) : [];
			for (const value of list) {
				const r = await lapi.deleteDecisions(value.includes("/") ? { range: value } : { ip: value });
				deleted += Number(r?.nbDeleted || 0);
			}
			if (!ids.length && !list.length) throw new errs.ValidationError("Nothing to unban");
			await audit(access, "unbanned", {
				name: list.length === 1 && !ids.length ? list[0] : `${deleted} decision(s)`,
				values: list.slice(0, 100),
				ids: ids.slice(0, 100),
			});
			return { deleted };
		});
	},

	/** @param {Access} access */
	registry: async (access) => {
		await access.can("crowdsec:view");
		return wrap(async () => {
			const own = lapi.machineId(
				(
					await readFile(
						path.join(process.env.NPMOS_SECRETS_DIR || "/run/npmos-secrets", "crowdsec_machine_password"),
						"utf8",
					).catch(() => "")
				).trim(),
			);
			const r = await lapi.registry();
			return { ...r, own_machine: own, protected: lapi.PROTECTED };
		});
	},

	/**
	 * Deletes a stale machine or bouncer (an old registration, a node that is gone).
	 * @param {Access} access
	 * @param {"machines"|"bouncers"} kind
	 * @param {string} name
	 */
	deleteRegistered: async (access, kind, name) => {
		await access.can("crowdsec:manage");
		const own = lapi.machineId(
			(
				await readFile(
					path.join(process.env.NPMOS_SECRETS_DIR || "/run/npmos-secrets", "crowdsec_machine_password"),
					"utf8",
				).catch(() => "")
			).trim(),
		);
		if (kind === "machines" && name === own) throw new errs.ValidationError("This is the machine of NPMOS itself");
		const deleted = await wrap(() => lapi.deleteRegistered(kind, name));
		if (!deleted) throw new errs.ItemNotFoundError(name);
		await audit(access, "deleted", { name: `CrowdSec ${kind === "machines" ? "machine" : "bouncer"} ${name}` });
		return true;
	},

	/** @param {Access} access */
	metrics: async (access) => {
		await access.can("crowdsec:view");
		return wrap(async () => summarizeMetrics(await lapi.metrics()));
	},

	/**
	 * @param {Access} access
	 * @param {{type?, q?, installed?}} query
	 */
	hub: async (access, query) => {
		await access.can("crowdsec:view");
		return wrap(async () => {
			const s = await settings();
			const required = requiredItems(s).map(([t, n]) => `${t}:${n}`);
			const items = await hub.list({ type: query.type, query: query.q, installed: query.installed === "true" });
			return items.map((i) => ({ ...i, required: required.includes(`${i.type}:${i.name}`) }));
		});
	},

	/**
	 * @param {Access} access
	 * @param {{type, name, action: "install"|"remove"}} data
	 */
	hubItem: async (access, { type, name, action }) => {
		await access.can("crowdsec:manage");
		return wrap(async () => {
			if (!hub.TYPES.includes(type)) throw new errs.ValidationError("Unknown hub type");
			const s = await settings();
			let items;
			if (action === "install") {
				items = await hub.install(type, name, { online: s.online_hub });
			} else if (action === "remove") {
				if (requiredItems(s).some(([t, n]) => t === type && n === name)) {
					throw new errs.ValidationError(`${type}/${name} is needed by the CrowdSec settings of NPMOS`);
				}
				items = await hub.remove(type, name);
			} else {
				throw new errs.ValidationError("Unknown action");
			}
			const result = items.length ? await apply(s, { actor: access.token.getUserId(1), force: true }) : null;
			await audit(access, action === "install" ? "installed" : "removed", { name: `${type}/${name}`, items });
			return { items, restarted: !!result?.restarted };
		});
	},

	/** @param {Access} access */
	hubUpgrade: async (access) => {
		await access.can("crowdsec:manage");
		return wrap(async () => {
			const items = await hub.upgradeAll();
			const result = items.length
				? await apply(await settings(), { actor: access.token.getUserId(1), force: true })
				: null;
			await audit(access, "updated", { name: "hub items", items });
			return { items, restarted: !!result?.restarted };
		});
	},

	/**
	 * Hub snapshot: .index.json (cscli hub update --with-content) or a .tar.gz with .index.json
	 * and data/ (made by scripts/crowdsec-hub-snapshot.sh).
	 * @param {Access} access
	 * @param {Buffer} body
	 */
	hubUpload: async (access, body) => {
		await access.can("crowdsec:manage");
		return wrap(async () => {
			if (!body?.length) throw new errs.ValidationError("Empty file");
			if (body.length > MAX_UPLOAD_BYTES) throw new errs.ValidationError("The snapshot is larger than 200 MB");
			let indexText;
			let data = 0;
			if (body[0] === 0x1f && body[1] === 0x8b) {
				const dir = await mkdtemp(path.join(os.tmpdir(), "npmos-hub-"));
				try {
					const archive = path.join(dir, "snapshot.tar.gz");
					await writeFile(archive, body);
					// only .index.json and plain files in data/: no other paths, links or devices
					const { stdout } = await run("tar", ["-tvzf", archive], { maxBuffer: 16 * 1024 * 1024 });
					for (const line of stdout.split("\n").filter(Boolean)) {
						const name = line.split(/\s+/).slice(5).join(" ").replace(/^\.\//, "");
						if (!/^[-d]/.test(line) || line.includes(" -> "))
							throw new hub.HubError("The archive may hold files only");
						if (!/^(\.index\.json|data\/?|data\/[A-Za-z0-9_.-]+)$/.test(name)) {
							throw new hub.HubError(`Unexpected file in the archive: ${name}`);
						}
					}
					await run("tar", ["-xzf", archive, "-C", dir, "--no-same-owner"]);
					indexText = await readFile(path.join(dir, ".index.json"), "utf8").catch(() => {
						throw new hub.HubError("The archive has no .index.json");
					});
					hub.parseIndex(indexText);
					data = await hub.copyData(path.join(dir, "data"));
				} finally {
					await rm(dir, { recursive: true, force: true });
				}
			} else {
				indexText = body.toString("utf8");
			}
			const items = await hub.writeIndex(indexText);
			await audit(access, "updated", { name: "hub snapshot", items, data_files: data });
			return { items, data_files: data };
		});
	},

	/** @param {Access} access */
	hubOnline: async (access) => {
		await access.can("crowdsec:manage");
		return wrap(async () => {
			if (!(await settings()).online_hub)
				throw new errs.ValidationError("Online hub updates are off (CrowdSec → Settings)");
			const items = await hub.writeIndex(await hub.fetchOnlineIndex());
			await audit(access, "updated", { name: "hub index (online)", items });
			return { items, data_files: 0 };
		});
	},

	/** @param {Access} access */
	blocklists: async (access) => {
		await access.can("crowdsec:view");
		return (await db()("npmos_crowdsec_blocklist").orderBy("name")).map(blocklistOut);
	},

	/**
	 * @param {Access} access
	 * @param {object} data  {name, source, url?, token?, content?, decision, duration, refresh_minutes, enabled}
	 */
	createBlocklist: async (access, data) => {
		await access.can("crowdsec:manage");
		const row = checkBlocklist({ decision: "ban", duration: "24h", refresh_minutes: 0, enabled: true, ...data });
		if (row.source === "file" && parseList(row.content || "").entries.length === 0) {
			throw new errs.ValidationError("The list has no IP or CIDR");
		}
		if (await db()("npmos_crowdsec_blocklist").where("name", row.name).first()) {
			throw new errs.ValidationError("A blocklist with this name exists");
		}
		const now = new Date();
		const [id] = await db()("npmos_crowdsec_blocklist")
			.insert({
				created_on: now,
				modified_on: now,
				name: row.name,
				enabled: row.enabled !== false,
				source: row.source,
				url: row.source === "url" ? row.url : "",
				token_enc: row.source === "url" && row.token ? encrypt(String(row.token)) : null,
				insecure: row.source === "url" && row.insecure === true,
				content: row.source === "file" ? row.content : null,
				decision: row.decision,
				duration: row.duration,
				refresh_minutes: row.source === "url" ? row.refresh_minutes : 0,
			})
			.returning("id");
		const created = await db()("npmos_crowdsec_blocklist")
			.where("id", id?.id ?? id)
			.first();
		await audit(access, "created", { name: `blocklist ${row.name}`, source: row.source, url: row.url || "" });
		let sync = null;
		try {
			sync = await syncList(created, await allowlistOf());
		} catch (err) {
			sync = { error: err.message };
		}
		return { ...blocklistOut(await db()("npmos_crowdsec_blocklist").where("id", created.id).first()), sync };
	},

	/** @param {Access} access */
	updateBlocklist: async (access, id, data) => {
		await access.can("crowdsec:manage");
		const old = await db()("npmos_crowdsec_blocklist").where("id", id).first();
		if (!old) throw new errs.ItemNotFoundError(id);
		const row = checkBlocklist(data, { ...old, enabled: !!old.enabled });
		if (row.name !== old.name && (await db()("npmos_crowdsec_blocklist").where("name", row.name).first())) {
			throw new errs.ValidationError("A blocklist with this name exists");
		}
		const patch = {
			modified_on: new Date(),
			name: row.name,
			enabled: !!row.enabled,
			url: row.source === "url" ? row.url : "",
			insecure: row.source === "url" && row.insecure === true,
			decision: row.decision,
			duration: row.duration,
			refresh_minutes: row.source === "url" ? row.refresh_minutes : 0,
		};
		if (row.source === "url" && data.token !== undefined)
			patch.token_enc = data.token ? encrypt(String(data.token)) : null;
		if (row.source === "file" && typeof data.content === "string") patch.content = data.content;
		await db()("npmos_crowdsec_blocklist").where("id", id).update(patch);
		await audit(access, "updated", { name: `blocklist ${row.name}` });
		const updated = await db()("npmos_crowdsec_blocklist").where("id", id).first();
		let sync = null;
		try {
			sync = await syncList(updated, await allowlistOf());
		} catch (err) {
			sync = { error: err.message };
		}
		return { ...blocklistOut(await db()("npmos_crowdsec_blocklist").where("id", id).first()), sync };
	},

	/** @param {Access} access */
	syncBlocklist: async (access, id) => {
		await access.can("crowdsec:decide");
		const row = await db()("npmos_crowdsec_blocklist").where("id", id).first();
		if (!row) throw new errs.ItemNotFoundError(id);
		return wrap(async () => {
			try {
				return await syncList(row, await allowlistOf());
			} catch (err) {
				throw new errs.ValidationError(err.message);
			}
		});
	},

	/** @param {Access} access */
	deleteBlocklist: async (access, id) => {
		await access.can("crowdsec:manage");
		const row = await db()("npmos_crowdsec_blocklist").where("id", id).first();
		if (!row) throw new errs.ItemNotFoundError(id);
		await wrap(() => lapi.deleteDecisions({ scenario: scenarioOf(id) }));
		await db()("npmos_crowdsec_blocklist").where("id", id).delete();
		await audit(access, "deleted", { name: `blocklist ${row.name}` });
		return true;
	},

	/**
	 * Token for other NPMOS nodes to take this node's decisions (shown once).
	 * @param {Access}  access
	 * @param {boolean} enabled  false: the export is off
	 */
	setShare: async (access, enabled) => {
		await access.can("crowdsec:manage");
		const token = enabled ? randomBytes(24).toString("base64url") : "";
		await setSetting("crowdsec.share", { token_hash: token ? tokenHash(token) : "" });
		await audit(access, enabled ? "enabled" : "disabled", { name: "decisions export" });
		return { enabled, token };
	},

	/**
	 * Public (no login), Authorization: Bearer <token>: the decisions of this node, one per line.
	 * @param {string} token
	 */
	exportDecisions: async (token) => {
		const { token_hash: hash } = await getSetting("crowdsec.share");
		const given = Buffer.from(tokenHash(String(token || "")), "hex");
		if (!hash || !token || !timingSafeEqual(given, Buffer.from(hash, "hex"))) {
			throw new errs.PermissionError("Invalid token");
		}
		return exportText(await lapi.decisions());
	},

	/** @param {Access} access */
	hosts: async (access) => {
		await access.can("crowdsec:view");
		const rows = await db()("npmos_crowdsec_host");
		return {
			bouncer_enabled: (await settings()).bouncer.enabled,
			per_host: perHostSupported(),
			bans: await bansByHost().catch(() => ({})),
			hosts: rows.map((r) => ({ host_type: r.host_type, host_id: r.host_id, bouncer: !!r.bouncer })),
		};
	},

	/**
	 * Bouncer of NPMOS on or off for one host.
	 * @param {Access} access
	 */
	setHost: async (access, hostType, hostId, bouncer) => {
		await access.can("crowdsec:manage");
		if (!HOST_TYPES.includes(hostType)) throw new errs.ValidationError("Unknown host type");
		if (typeof bouncer !== "boolean") throw new errs.ValidationError("bouncer must be a boolean");
		const id = Number(hostId);
		const host = await db()(hostType).where({ id, is_deleted: 0 }).first();
		if (!host) throw new errs.ItemNotFoundError(hostId);
		const table = db()("npmos_crowdsec_host");
		if (bouncer) await table.where({ host_type: hostType, host_id: id }).delete();
		else {
			await db()("npmos_crowdsec_host")
				.insert({ host_type: hostType, host_id: id, modified_on: new Date(), bouncer: false })
				.onConflict(["host_type", "host_id"])
				.merge();
		}
		const nginx = await reconfigure(hostType, id);
		await audit(access, bouncer ? "enabled" : "disabled", {
			name: `bouncer on ${hostLabel(host, id)}`,
			host_type: hostType,
			host_id: id,
		});
		return { host_type: hostType, host_id: id, bouncer, nginx };
	},
};

const refreshLists = async () => {
	try {
		const due = await dueLists();
		if (!due.length) return;
		const allowlist = await allowlistOf();
		for (const row of due) {
			try {
				const { count } = await syncList(row, allowlist);
				logger.info(`NPMOS CrowdSec: blocklist ${row.name} synced, ${count} decision(s)`);
			} catch (err) {
				logger.warn(`NPMOS CrowdSec: blocklist ${row.name}: ${err.message}`);
			}
		}
	} catch (err) {
		logger.warn(`NPMOS CrowdSec: blocklists: ${err.message}`);
	}
};

/**
 * At backend start, in the background (CrowdSec may start later than NPMOS): files of the
 * settings, the bouncer, the alert reader and the refresh of URL blocklists.
 */
export const bootstrap = async () => {
	let s;
	try {
		s = await settings();
		// nginx is reloaded by the start of the backend right after
		await applyBouncer(s, { reload: false });
	} catch (err) {
		logger.error(`NPMOS CrowdSec bouncer: ${err.message}`);
		if (!s) return;
	}
	apply(s, { online: false })
		.then((r) => r.restarted && logger.info("NPMOS CrowdSec: settings applied at start"))
		.catch((err) => logger.error(`NPMOS CrowdSec: ${err.message}`));
	startAlerts();
	const timer = setInterval(refreshLists, BLOCKLIST_TIMER_MS);
	timer.unref();
};

export default internalCrowdsec;
