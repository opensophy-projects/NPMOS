// Agents → open-appsec → Learning (docs/ROADMAP.md, phase 8; docs/adr/0011-learning.md): the queue of what the
// agent is not sure about, labels and their effects, readiness of hosts. RBAC: waf_learning:view, :label.
//
// Effects of a label:
// 1. learning: decisions.data of every asset of the host in the shared storage (the agent reads it every 30
//    min); for a suggestion of the tuning service, the tuning service writes it. Rebuilt from the database on
//    every change and every 10 min, so an undone label leaves the file and a reset storage is filled again.
// 2. instantly (optional): an exception for the host in the policy (store.js reads learning/policy.js), with an
//    end for benign; a ban of the sources in CrowdSec for malicious.
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import { isPostgres } from "../../lib/config.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import { EVENT_TABLE } from "../events/store.js";
import { scheduleRegenerate } from "../waf/policy.js";
import * as appsec from "./appsec.js";
import {
	assetsOf,
	checkLabel,
	decisionEntries,
	defaultScopes,
	enforcedIds,
	exceptionActive,
	GREY_MIN,
	groupsOf,
	hostStats,
	mergeDecisions,
	statsOf,
	suggestionOf,
} from "./model.js";
import { LABEL_TABLE, parseLabel } from "./policy.js";

const DAY = 24 * 3600 * 1000;
export const PERIODS = { "24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY };
const MAX_GROUPS = 3000;
const SYNC_MS = 10 * 60 * 1000;
const EXPIRY_MS = 60 * 1000;

const parseJson = (value, fallback) => {
	if (typeof value !== "string") return value ?? fallback;
	try {
		return JSON.parse(value);
	} catch {
		return fallback;
	}
};

const audit = (access, action, meta) => internalAuditLog.add(access, { action, object_type: "waf_learning", meta });

// ------------------------------------------------------------------ hosts and assets

/** proxy hosts with WAF on: id, name, domains, assets, mode, minimum confidence */
const wafHosts = async () => {
	const knex = db();
	const rows = await knex("npmos_waf_host")
		.join("proxy_host", "proxy_host.id", "npmos_waf_host.proxy_host_id")
		.where("proxy_host.is_deleted", 0)
		.select(
			"proxy_host.id",
			"proxy_host.domain_names",
			"npmos_waf_host.enabled",
			"npmos_waf_host.mode",
			"npmos_waf_host.minimum_confidence",
		);
	const locations = await knex("npmos_waf_location").select("proxy_host_id", "path");
	return rows.map((r) => {
		const domains = parseJson(r.domain_names, []);
		const paths = locations.filter((l) => l.proxy_host_id === r.id).map((l) => l.path);
		return {
			id: r.id,
			name: domains.join(", "),
			domains,
			assets: assetsOf(domains, paths),
			enabled: !!r.enabled,
			mode: r.mode,
			minimumConfidence: r.minimum_confidence,
		};
	});
};

const hostById = async (id) => (await wafHosts()).find((h) => h.id === id) ?? null;

// the tenant of the agent, from its events: none when it runs local only (NPMOS_LOCAL_ONLY, no registration)
let tenantCache = { value: "", at: 0 };
export const getTenant = async () => {
	if (Date.now() - tenantCache.at < 10 * 60 * 1000) return tenantCache.value;
	let tenant = "";
	if (isPostgres()) {
		const row = await db()(EVENT_TABLE)
			.whereRaw("raw->'eventSource'->>'tenantId' <> ''")
			.select(db().raw("raw->'eventSource'->>'tenantId' as tenant"))
			.orderBy("time", "desc")
			.first();
		tenant = row?.tenant || "";
	}
	tenantCache = { value: tenant, at: Date.now() };
	return tenant;
};

// ------------------------------------------------------------------ queue

/**
 * Rows of the queue: events of the assets of protected hosts (the agent names an asset after the host of its rule:
 * a domain, or domain + path of a location), grouped by asset, URI, parameter and indicators.
 */
const groupRows = (from, assets) =>
	db()(EVENT_TABLE)
		.where("kind", "security")
		.where("time", ">=", from)
		.whereIn("asset", assets.length ? assets : [""])
		.where((w) => w.whereRaw("lower(action) = 'prevent'").orWhere("score", ">=", GREY_MIN))
		.groupBy("asset", "uri", "parameter", "indicators")
		.select("asset", "uri", "parameter", "indicators")
		.select(
			db().raw("count(*) as events"),
			db().raw("count(distinct source_ip) as sources"),
			db().raw("max(score) as score"),
			db().raw("sum(case when lower(action) = 'prevent' then 1 else 0 end) as blocked"),
			db().raw("min(time) as first"),
			db().raw("max(time) as last"),
			db().raw("max(host) as host"),
			db().raw("max(incident_type) as incident_type"),
			db().raw("max(sample) as sample"),
			db().raw("max(id) as event_id"),
		)
		.orderBy("events", "desc")
		.limit(MAX_GROUPS);

/** asset → proxy host */
const assetOwner = (hosts) => {
	const owners = new Map();
	for (const h of hosts) for (const a of h.assets) owners.set(a.toLowerCase(), h.id);
	return (row) => owners.get(String(row.asset || "").toLowerCase());
};

/** groups of hosts (all with WAF, or one) in a period, labelled ones included or not */
const findGroups = async (from, hosts, labelled = new Set()) =>
	groupsOf(
		await groupRows(
			from,
			hosts.flatMap((h) => h.assets),
		),
		labelled,
		new Date(),
		assetOwner(hosts),
	);

const activeKeys = async () =>
	new Set(
		(await db()(LABEL_TABLE).whereNull("undone_on").where("origin", "group").select("group_key")).map(
			(r) => r.group_key,
		),
	);

/** groups of the queue in a period (all hosts or one) */
const queueGroups = async (period, hostId, hosts = null) => {
	const from = new Date(Date.now() - (PERIODS[period] ?? PERIODS["7d"]));
	const all = hosts ?? (await wafHosts());
	return findGroups(from, hostId ? all.filter((h) => h.id === hostId) : all, await activeKeys());
};

/** sources of a group (for a ban or a source scope) */
const groupSources = async (group, from, assets) => {
	const rows = await db()(EVENT_TABLE)
		.where("kind", "security")
		.where("time", ">=", from)
		.where("uri", group.uri)
		.where("parameter", group.parameter)
		.where("indicators", group.indicators)
		.whereIn("asset", assets.length ? assets : [""])
		.whereNot("source_ip", "")
		.select("source_ip")
		.count({ n: "*" })
		.groupBy("source_ip")
		.orderBy("n", "desc")
		.limit(50);
	return rows.map((r) => ({ ip: r.source_ip, events: Number(r.n) }));
};

/** suggestions of the tuning service for the assets of the hosts */
const suggestions = async (hosts) => {
	const tenant = await getTenant();
	const items = [];
	let error = null;
	for (const host of hosts) {
		for (const asset of host.assets) {
			try {
				for (const raw of await appsec.getSuggestions(tenant, asset)) {
					items.push({ ...suggestionOf(raw, asset), hostId: host.id, hostName: host.name });
				}
			} catch (err) {
				error = err.message;
			}
		}
	}
	return { items, error };
};

// ------------------------------------------------------------------ decisions.data

const activeLabels = async (where = {}) =>
	(await db()(LABEL_TABLE).where(where).whereNull("undone_on").orderBy("id")).map(parseLabel);

/**
 * Writes decisions.data of the assets of hosts from the labels in force (only those of the queue: suggestions
 * are written by the tuning service).
 * @param {number[]|null} hostIds  null: every host with labels, and hosts whose labels were all undone
 */
export const syncDecisions = async (hostIds = null) => {
	const tenant = await getTenant();
	const hosts = await wafHosts();
	const ids = hostIds ?? [
		...new Set(
			(
				await db()(LABEL_TABLE).where("origin", "group").whereNotNull("proxy_host_id").distinct("proxy_host_id")
			).map((r) => r.proxy_host_id),
		),
	];
	const now = new Date();
	for (const id of ids) {
		const host = hosts.find((h) => h.id === id);
		const labels = await activeLabels({ proxy_host_id: id, origin: "group" });
		const ours = decisionEntries(labels);
		let error = "";
		if (host) {
			for (const asset of host.assets) {
				try {
					const current = await appsec.getDecisions(tenant, asset);
					const merged = mergeDecisions(current, ours);
					if (JSON.stringify(merged) !== JSON.stringify(current ?? { decisions: [] })) {
						await appsec.putDecisions(tenant, asset, merged);
					}
				} catch (err) {
					error = err.message;
				}
			}
		}
		if (labels.length) {
			await db()(LABEL_TABLE)
				.whereIn(
					"id",
					labels.map((l) => l.id),
				)
				.update(error ? { sync_error: error } : { synced_on: now, sync_error: "" });
		}
		if (error) logger.warn(`Learning: decisions of host ${id} not written: ${error}`);
	}
};

// ------------------------------------------------------------------ expiry of exceptions

let lastActive = null;
const checkExpiry = async () => {
	const now = new Date();
	const rows = (
		await db()(LABEL_TABLE)
			.where("exception", true)
			.whereNull("undone_on")
			.select("id", "exception", "expires_on", "undone_on")
	).filter((r) => exceptionActive(r, now));
	const signature = rows.map((r) => r.id).join(",");
	// the first check after a start only remembers what is in force (the policy was built at the start)
	if (lastActive !== null && signature !== lastActive) scheduleRegenerate();
	lastActive = signature;
};

let timers = [];
/** timers of learning: decisions.data every 10 min, ends of exceptions every minute */
export const start = () => {
	for (const t of timers) clearInterval(t);
	const run = (fn, name) => () => fn().catch((err) => logger.warn(`Learning: ${name}: ${err.message}`));
	timers = [
		setInterval(
			run(() => syncDecisions(), "sync"),
			SYNC_MS,
		),
		setInterval(run(checkExpiry, "expiry"), EXPIRY_MS),
	];
	for (const t of timers) t.unref?.();
	run(checkExpiry, "expiry")();
};

/** groups waiting in the queue (notifications) */
export const queueSize = async (period = "24h") => (await queueGroups(period)).length;

// ------------------------------------------------------------------ API

const toApi = (row, users = new Map()) => {
	const l = parseLabel(row);
	return {
		id: l.id,
		createdOn: new Date(l.created_on).toISOString(),
		user: users.get(l.user_id) ?? null,
		origin: l.origin,
		groupKey: l.group_key,
		tuningId: l.tuning_id,
		hostId: l.proxy_host_id,
		host: l.host,
		decision: l.decision,
		scopes: l.scopes,
		features: l.features,
		note: l.note,
		exception: l.exception,
		exceptionActive: exceptionActive(l),
		expiresOn: l.expires_on ? new Date(l.expires_on).toISOString() : null,
		banned: l.banned,
		banDuration: l.ban_duration,
		syncedOn: l.synced_on ? new Date(l.synced_on).toISOString() : null,
		syncError: l.sync_error,
		undoneOn: l.undone_on ? new Date(l.undone_on).toISOString() : null,
		undoneBy: l.undone_by ? (users.get(l.undone_by) ?? null) : null,
	};
};

const userNames = async (ids) => {
	const list = [...new Set(ids.filter(Boolean))];
	if (!list.length) return new Map();
	const rows = await db()("user").whereIn("id", list).select("id", "name");
	return new Map(rows.map((r) => [r.id, { id: r.id, name: r.name }]));
};

const crowdsec = async () => (await import("../crowdsec/index.js")).default;

const internalLearning = {
	/**
	 * The queue: groups of events (and suggestions of the tuning service), most important first.
	 * @param {Access} access
	 * @param {{period?, host?, reason?, q?, limit?, offset?, suggestions?}} query
	 */
	queue: async (access, query = {}) => {
		await access.can("waf_learning:view");
		const period = Object.hasOwn(PERIODS, query.period) ? query.period : "7d";
		const hostId = Number.parseInt(query.host, 10) || null;
		const hosts = await wafHosts();
		const names = new Map(hosts.map((h) => [h.id, h.name]));
		let groups = await queueGroups(period, hostId, hosts);
		const counts = { blocked: 0, grey: 0, detected: 0 };
		for (const g of groups) counts[g.reason]++;
		if (["blocked", "grey", "detected"].includes(query.reason))
			groups = groups.filter((g) => g.reason === query.reason);
		const q = String(query.q || "")
			.trim()
			.toLowerCase();
		if (q) {
			groups = groups.filter((g) =>
				[g.uri, g.parameter, g.indicators, g.sample, g.host, g.incidentType].some((v) =>
					v.toLowerCase().includes(q),
				),
			);
		}
		const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 25, 1), 200);
		const offset = Math.max(Number.parseInt(query.offset, 10) || 0, 0);
		let tuning = { items: [], error: null };
		if (query.suggestions !== "0") {
			tuning = await suggestions(hostId ? hosts.filter((h) => h.id === hostId) : hosts.filter((h) => h.enabled));
		}
		return {
			period,
			total: groups.length,
			counts,
			limit,
			offset,
			items: groups.slice(offset, offset + limit).map((g) => ({
				...g,
				hostName: names.get(g.hostId) ?? g.host,
				hostMode: hosts.find((h) => h.id === g.hostId)?.mode ?? null,
				scopes: defaultScopes(g),
			})),
			suggestions: tuning.items,
			suggestionsError: tuning.error,
		};
	},

	/**
	 * A group of the queue with its sources (to choose what the label applies to).
	 * @param {Access} access
	 * @param {string} key
	 */
	group: async (access, key, period = "30d") => {
		await access.can("waf_learning:view");
		const from = new Date(Date.now() - (PERIODS[period] ?? PERIODS["30d"]));
		const hosts = await wafHosts();
		const group = (await findGroups(from, hosts)).find((g) => g.key === key);
		if (!group) throw new errs.ItemNotFoundError(key);
		const assets = hosts.find((h) => h.id === group.hostId)?.assets ?? [];
		return { ...group, scopes: defaultScopes(group), sourceList: await groupSources(group, from, assets) };
	},

	/**
	 * Labels a group of the queue or a suggestion of the tuning service.
	 * @param {Access} access
	 * @param {{key?: string, suggestion?: {id, asset, type, title, hostId}, decision, scopes, exception?,
	 *   ttl_days?, ban?, ban_duration?, note?}} data
	 */
	label: async (access, data = {}) => {
		await access.can("waf_learning:label");
		const userId = access.token.getUserId(0);
		const now = new Date();
		if (data.suggestion) {
			// the API client of the GUI sends snake_case keys
			const raw = data.suggestion;
			const s = { ...raw, hostId: raw.host_id ?? raw.hostId, attackTypes: raw.attack_types ?? raw.attackTypes };
			if (!["benign", "malicious", "dismiss"].includes(data.decision)) throw new errs.ValidationError("decision");
			const host = await hostById(Number(s.hostId));
			if (!host?.assets.includes(s.asset)) throw new errs.ValidationError("suggestion: unknown asset");
			const tenant = await getTenant();
			await appsec.postSuggestions(tenant, s.asset, [
				{ id: String(s.id), decision: data.decision, eventType: s.type, eventTitle: String(s.title) },
			]);
			const [row] = await db()(LABEL_TABLE)
				.insert({
					created_on: now,
					user_id: userId,
					origin: "tuning",
					tuning_id: String(s.id).slice(0, 128),
					proxy_host_id: host.id,
					host: s.asset,
					decision: data.decision,
					scopes: JSON.stringify([{ type: s.type, value: String(s.title) }]),
					features: JSON.stringify({
						asset: s.asset,
						severity: s.severity ?? "",
						attackTypes: s.attackTypes ?? [],
					}),
					note: String(data.note || "").slice(0, 500),
					exception: false,
					banned: "[]",
					synced_on: now,
					sync_error: "",
				})
				.returning("id");
			const id = typeof row === "object" ? row.id : row;
			await audit(access, "labeled", {
				name: `${s.asset}: ${s.title}`.slice(0, 200),
				decision: data.decision,
				id,
			});
			return { id };
		}

		const group = (await findGroups(new Date(now.getTime() - PERIODS["30d"]), await wafHosts())).find(
			(g) => g.key === data.key,
		);
		if ((await activeKeys()).has(data.key)) throw new errs.ValidationError("The group is already labelled");
		if (!group)
			throw new errs.ValidationError(
				"The group is no longer in the queue (labelled, or its events are older than 30 days)",
			);
		const label = checkLabel(data);
		if (label.errors) throw new errs.ValidationError(label.errors.join("; "));
		const host = await hostById(group.hostId);
		let banned = [];
		if (label.ban) {
			banned = label.scopes.filter((s) => s.type === "source").map((s) => s.value);
			await (await crowdsec()).ban(access, {
				values: banned,
				duration: label.banDuration,
				reason: `learning: ${group.incidentType || "attack"} on ${host?.name || group.host}`,
				replace: true,
			});
		}
		const [row] = await db()(LABEL_TABLE)
			.insert({
				created_on: now,
				user_id: userId,
				origin: "group",
				group_key: group.key,
				proxy_host_id: group.hostId,
				host: host?.name || group.host,
				decision: label.decision,
				scopes: JSON.stringify(label.scopes),
				features: JSON.stringify({
					uri: group.uri,
					parameter: group.parameter,
					indicators: group.indicators,
					incidentType: group.incidentType,
					sample: group.sample,
					events: group.events,
					sources: group.sources,
					blocked: group.blocked,
					score: group.score,
					reason: group.reason,
					first: group.first,
					last: group.last,
					eventId: group.eventId,
				}),
				note: label.note,
				exception: label.exception,
				expires_on: label.exception && label.ttlDays ? new Date(now.getTime() + label.ttlDays * DAY) : null,
				banned: JSON.stringify(banned),
				ban_duration: label.ban ? label.banDuration : "",
				sync_error: "",
			})
			.returning("id");
		const id = typeof row === "object" ? row.id : row;
		await audit(access, "labeled", {
			name: `${host?.name || group.host}${group.uri}${group.parameter ? ` ${group.parameter}` : ""}`.slice(
				0,
				200,
			),
			decision: label.decision,
			scopes: label.scopes.map((s) => s.type),
			exception: label.exception,
			ban: banned.length,
			id,
		});
		if (label.exception) scheduleRegenerate();
		await syncDecisions([group.hostId]).catch((err) => logger.warn(`Learning: ${err.message}`));
		const saved = await db()(LABEL_TABLE).where("id", id).first();
		return toApi(saved);
	},

	/**
	 * Undoes a label: out of decisions.data, its exception out of the policy, its bans lifted; the group comes
	 * back to the queue. The label stays in the history.
	 * @param {Access} access
	 * @param {number} id
	 */
	undo: async (access, id) => {
		await access.can("waf_learning:label");
		const row = await db()(LABEL_TABLE).where("id", id).first();
		if (!row) throw new errs.ItemNotFoundError(id);
		if (row.undone_on) throw new errs.ValidationError("Already undone");
		const label = parseLabel(row);
		if (label.origin === "tuning") {
			const tenant = await getTenant();
			const scope = label.scopes[0] ?? {};
			await appsec.postSuggestions(tenant, label.host, [
				{ id: label.tuning_id, decision: "undecided", eventType: scope.type, eventTitle: scope.value },
			]);
		}
		if (label.banned.length) {
			await (await crowdsec())
				.unban(access, { values: label.banned })
				.catch((err) => logger.warn(`Learning: unban: ${err.message}`));
		}
		await db()(LABEL_TABLE)
			.where("id", id)
			.update({ undone_on: new Date(), undone_by: access.token.getUserId(0) });
		await audit(access, "unlabeled", { name: label.host, decision: label.decision, id });
		if (label.exception) scheduleRegenerate();
		if (label.origin === "group")
			await syncDecisions([label.proxy_host_id]).catch((err) => logger.warn(`Learning: ${err.message}`));
		return { ok: true };
	},

	/**
	 * History of labels, newest first.
	 * @param {Access} access
	 * @param {{host?, decision?, active?, limit?, offset?}} query
	 */
	labels: async (access, query = {}) => {
		await access.can("waf_learning:view");
		const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 25, 1), 200);
		const offset = Math.max(Number.parseInt(query.offset, 10) || 0, 0);
		const filter = (q) => {
			const hostId = Number.parseInt(query.host, 10);
			if (hostId) q.where("proxy_host_id", hostId);
			if (["benign", "malicious", "dismiss"].includes(query.decision)) q.where("decision", query.decision);
			if (query.active === "1") q.whereNull("undone_on");
			if (query.active === "0") q.whereNotNull("undone_on");
			return q;
		};
		const rows = await filter(db()(LABEL_TABLE)).orderBy("id", "desc").limit(limit).offset(offset);
		const counted = await filter(db()(LABEL_TABLE)).count({ n: "*" }).first();
		const users = await userNames(rows.flatMap((r) => [r.user_id, r.undone_by]));
		return { items: rows.map((r) => toApi(r, users)), total: Number(counted?.n ?? 0), limit, offset };
	},

	/**
	 * Hosts with WAF: readiness of learning (tuning service), labels, decisions taken by the agent, events of the
	 * groups labelled benign before and after the label (false positives that are gone), recommendation.
	 * @param {Access} access
	 */
	hosts: async (access) => {
		await access.can("waf_learning:view");
		const hosts = (await wafHosts()).filter((h) => h.enabled);
		const tenant = await getTenant();
		const labels = await activeLabels();
		const now = Date.now();
		let error = null;
		const result = [];
		for (const host of hosts) {
			const stats = [];
			let enforced = 0;
			for (const asset of host.assets) {
				try {
					const raw = await appsec.getStatistics(tenant, asset);
					if (raw) stats.push(statsOf(raw));
					enforced += enforcedIds(await appsec.getDecisions(tenant, asset)).size;
				} catch (err) {
					error = err.message;
				}
			}
			const own = labels.filter((l) => l.proxy_host_id === host.id);
			// false positives: events of benign groups in the 7 days before and after their label
			let before = 0;
			let after = 0;
			for (const l of own.filter((x) => x.decision === "benign" && x.origin === "group")) {
				const at = new Date(l.created_on).getTime();
				const count = async (from, to) => {
					const r = await db()(EVENT_TABLE)
						.where("kind", "security")
						.where("time", ">=", new Date(from))
						.where("time", "<", new Date(to))
						.where("uri", l.features.uri ?? "")
						.where("parameter", l.features.parameter ?? "")
						.where("indicators", l.features.indicators ?? "")
						.whereIn("asset", host.assets.length ? host.assets : [""])
						.count({ n: "*" })
						.first();
					return Number(r?.n ?? 0);
				};
				before += await count(at - 7 * DAY, at);
				after += await count(at, Math.min(now, at + 7 * DAY));
			}
			const best = hostStats(stats);
			result.push({
				id: host.id,
				name: host.name,
				mode: host.mode,
				minimumConfidence: host.minimumConfidence,
				stats: best,
				labels: {
					benign: own.filter((l) => l.decision === "benign").length,
					malicious: own.filter((l) => l.decision === "malicious").length,
					dismiss: own.filter((l) => l.decision === "dismiss").length,
					exceptions: own.filter((l) => exceptionActive(l)).length,
				},
				enforced,
				falsePositives: { before, after },
				queue: (await queueGroups("7d", host.id, hosts)).length,
				// ready to block: the tuning service says so (prevent critical or high) while the host only detects
				readyToPrevent:
					!!best &&
					["prevent_critical", "prevent_high"].includes(best.recommendation) &&
					!String(host.mode).startsWith("prevent"),
			});
		}
		return { hosts: result, error };
	},
};

export default internalLearning;
