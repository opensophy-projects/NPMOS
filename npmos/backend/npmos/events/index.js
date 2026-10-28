// Security events (WAF → Events): stored events of the open-appsec agent with filters, pages,
// one event with its raw JSON, export, retention settings. RBAC: waf_events:view (settings:
// settings:view / settings:manage).
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import { isPostgres } from "../../lib/config.js";
import errs from "../../lib/error.js";
import { getSetting, setSetting } from "../settings.js";
import { status as ingestStatus, runMaintenance } from "./ingest.js";
import { IMPORTANT_SEVERITIES } from "./normalize.js";
import { EVENT_TABLE } from "./store.js";

const MAX_LIMIT = 500;
const MAX_EXPORT = 100000;
/** counting stops here ("10000+") */
const COUNT_CAP = 10000;
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
/** period: the last hour/day/week/month up to `to` */
export const PERIODS = { "1h": HOUR, "24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY };

/** columns of the list (raw JSON only in one event) */
const LIST_COLUMNS = [
	"id",
	"time",
	"kind",
	"name",
	"severity",
	"priority",
	"confidence",
	"action",
	"incident_type",
	"source_ip",
	"source_port",
	"proxy_ip",
	"source_country",
	"host",
	"asset",
	"method",
	"uri",
	"query",
	"response_code",
	"location",
	"parameter",
	"sample",
	"indicators",
	"score",
	"rule",
	"practice",
	"override",
	"service",
];

const list = (value) =>
	String(value ?? "")
		.split(",")
		.map((v) => v.trim())
		.filter(Boolean);

const date = (value, fallback) => {
	if (!value) return fallback;
	const d = new Date(value);
	if (Number.isNaN(d.getTime())) throw new errs.ValidationError(`Invalid date: ${value}`);
	return d;
};

const score = (value) => {
	if (value === undefined || value === null || value === "") return null;
	const n = Number.parseFloat(value);
	if (!Number.isFinite(n)) throw new errs.ValidationError(`Invalid score: ${value}`);
	return n;
};

/**
 * Filters from query parameters.
 * from/to: ISO time (default: `period` before `to`, the last 24 h); kind: security (default) | system | all;
 * important: only critical/high; host, ip, action, severity, type: comma-separated, exact;
 * min_score/max_score; q: text in host, request, IP, sample, parameter, event name and type.
 */
export const parseFilters = (query, now = new Date()) => {
	const to = date(query.to, now);
	const from = date(
		query.from,
		new Date(to.getTime() - (Object.hasOwn(PERIODS, query.period) ? PERIODS[query.period] : DAY)),
	);
	if (from > to) throw new errs.ValidationError("from is after to");
	const kind = ["security", "system", "all"].includes(query.kind) ? query.kind : "security";
	return {
		from,
		to,
		kind,
		important: query.important === "true" || query.important === true,
		host: list(query.host).map((h) => h.toLowerCase()),
		ip: list(query.ip),
		action: list(query.action).map((a) => a.toLowerCase()),
		severity: list(query.severity).map((s) => s.toLowerCase()),
		type: list(query.type),
		minScore: score(query.min_score),
		maxScore: score(query.max_score),
		q: String(query.q ?? "")
			.trim()
			.slice(0, 200),
	};
};

const like = (q) => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

/** where clauses of the filters on a query builder */
const applyFilters = (builder, f) => {
	builder.where("time", ">=", f.from).where("time", "<=", f.to);
	if (f.kind !== "all") builder.where("kind", f.kind);
	if (f.important)
		builder.whereRaw(`lower(severity) in (${IMPORTANT_SEVERITIES.map(() => "?").join(",")})`, IMPORTANT_SEVERITIES);
	if (f.host.length) builder.whereIn("host", f.host);
	if (f.ip.length) builder.whereIn("source_ip", f.ip);
	if (f.action.length) builder.whereRaw(`lower(action) in (${f.action.map(() => "?").join(",")})`, f.action);
	if (f.severity.length) builder.whereRaw(`lower(severity) in (${f.severity.map(() => "?").join(",")})`, f.severity);
	if (f.type.length) builder.whereIn("incident_type", f.type);
	if (f.minScore !== null) builder.where("score", ">=", f.minScore);
	if (f.maxScore !== null) builder.where("score", "<=", f.maxScore);
	if (f.q) {
		const op = isPostgres() ? "ilike" : "like";
		const pattern = like(f.q);
		builder.where((w) => {
			for (const column of [
				"host",
				"uri",
				"query",
				"source_ip",
				"sample",
				"parameter",
				"name",
				"incident_type",
			]) {
				w.orWhere(column, op, pattern);
			}
		});
	}
	return builder;
};

/** "<ISO time>_<id>" of the last row of a page */
const cursorOf = (row) => `${new Date(row.time).toISOString()}_${row.id}`;

const parseCursor = (value) => {
	if (!value) return null;
	const m = /^(.+)_(\d+)$/.exec(String(value));
	const time = m && new Date(m[1]);
	if (!m || Number.isNaN(time.getTime())) throw new errs.ValidationError("Invalid cursor");
	return { time, id: m[2] };
};

const toApi = (row) => ({
	...row,
	id: String(row.id),
	time: new Date(row.time).toISOString(),
	score: row.score === null ? null : Number(row.score),
});

const internalEvents = {
	/**
	 * A page of events, newest first.
	 * @param {Access} access
	 * @param {object} query  filters (parseFilters), limit, before (cursor of the previous page)
	 */
	list: async (access, query = {}) => {
		await access.can("waf_events:view");
		const f = parseFilters(query);
		const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 100, 1), MAX_LIMIT);
		const before = parseCursor(query.before);
		const knex = db();
		const rows = await applyFilters(knex(EVENT_TABLE).select(LIST_COLUMNS), f)
			.modify((b) => {
				if (before) {
					b.where((w) =>
						w
							.where("time", "<", before.time)
							.orWhere((x) => x.where("time", before.time).where("id", "<", before.id)),
					);
				}
			})
			.orderBy([
				{ column: "time", order: "desc" },
				{ column: "id", order: "desc" },
			])
			.limit(limit + 1);
		const counted = await knex
			.count({ n: "*" })
			.from(
				applyFilters(knex(EVENT_TABLE).select(knex.raw("1")), f)
					.limit(COUNT_CAP + 1)
					.as("c"),
			)
			.first();
		const total = Number(counted?.n ?? 0);
		const page = rows.slice(0, limit);
		const ingest = ingestStatus();
		return {
			events: page.map(toApi),
			next: rows.length > limit ? cursorOf(page[page.length - 1]) : null,
			total: Math.min(total, COUNT_CAP),
			totalCapped: total > COUNT_CAP,
			from: f.from.toISOString(),
			to: f.to.toISOString(),
			// the agent's log directory is mounted and read
			available: ingest.available,
			ingestError: ingest.lastError,
		};
	},

	/**
	 * One event with its raw JSON.
	 * @param {Access} access
	 * @param {string} id
	 * @param {string} time  ISO time of the event (finds its day partition)
	 */
	get: async (access, id, time) => {
		await access.can("waf_events:view");
		const t = date(time, null);
		if (!/^\d{1,18}$/.test(String(id)) || !t) throw new errs.ValidationError("Invalid event");
		const row = await db()(EVENT_TABLE).where({ id, time: t }).first();
		if (!row) throw new errs.ItemNotFoundError(id);
		return { ...toApi(row), raw: typeof row.raw === "string" ? JSON.parse(row.raw) : row.raw };
	},

	/**
	 * Events of the filters, newest first, as rows (the route writes CSV or JSON).
	 * @returns {Promise<{rows: object[], capped: boolean}>}
	 */
	export: async (access, query = {}) => {
		await access.can("waf_events:view");
		const f = parseFilters(query);
		const rows = await applyFilters(db()(EVENT_TABLE).select(LIST_COLUMNS), f)
			.orderBy([
				{ column: "time", order: "desc" },
				{ column: "id", order: "desc" },
			])
			.limit(MAX_EXPORT + 1);
		return { rows: rows.slice(0, MAX_EXPORT).map(toApi), capped: rows.length > MAX_EXPORT };
	},

	/** retention and the state of the ingest */
	getSettings: async (access) => {
		await access.can("settings:view");
		const knex = db();
		const retention = await getSetting("events.retention");
		const [{ n: events }] = await knex(EVENT_TABLE).count({ n: "*" });
		const oldest = await knex(EVENT_TABLE).min({ t: "time" }).first();
		let bytes = null;
		if (isPostgres()) {
			const { rows } = await knex.raw(
				"SELECT COALESCE(SUM(pg_total_relation_size(i.inhrelid)), 0) AS bytes FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = ?",
				[EVENT_TABLE],
			);
			bytes = Number(rows[0]?.bytes ?? 0);
		}
		return {
			retention,
			storage: {
				events: Number(events),
				oldest: oldest?.t ? new Date(oldest.t).toISOString() : null,
				bytes,
			},
			ingest: ingestStatus(),
		};
	},

	/**
	 * @param {Access} access
	 * @param {{days: number, aggregate_days: number}} data
	 */
	setSettings: async (access, data) => {
		await access.can("settings:manage");
		const value = { days: data.days, aggregateDays: data.aggregate_days };
		await setSetting("events.retention", value);
		await runMaintenance();
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "setting",
			meta: { name: "events.retention", ...value },
		});
		return internalEvents.getSettings(access);
	},
};

export default internalEvents;
