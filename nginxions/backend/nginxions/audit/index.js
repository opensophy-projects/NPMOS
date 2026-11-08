// Analytics → Audit log: pages from the server (the upstream list stops at the last 100 entries), search over
// the whole log, filters by action, object, user and period, export. RBAC: audit_log:view.
import db from "../../db.js";
import { isPostgres, isSqlite } from "../../lib/config.js";
import errs from "../../lib/error.js";

const MAX_LIMIT = 200;
const MAX_EXPORT = 100000;
const DAY = 24 * 3600 * 1000;
/** period: the last day/week/month/quarter; "all" (default) has no lower bound */
export const PERIODS = { "24h": DAY, "7d": 7 * DAY, "30d": 30 * DAY, "90d": 90 * DAY };

const list = (value) =>
	String(value ?? "")
		.split(",")
		.map((v) => v.trim())
		.filter(Boolean);

const date = (value) => {
	if (!value) return null;
	const d = new Date(value);
	if (Number.isNaN(d.getTime())) throw new errs.ValidationError(`Invalid date: ${value}`);
	return d;
};

/**
 * Filters from query parameters: period=24h|7d|30d|90d|all or from/to (ISO); action, object (object type),
 * user (ids): comma-separated, exact; q: text in the details, action, object type and user name.
 */
export const parseFilters = (query, now = new Date()) => {
	const to = date(query.to);
	let from = date(query.from);
	if (!from && Object.hasOwn(PERIODS, query.period)) from = new Date((to ?? now).getTime() - PERIODS[query.period]);
	if (from && to && from > to) throw new errs.ValidationError("from is after to");
	const user = list(query.user).map((u) => Number.parseInt(u, 10));
	if (user.some((u) => !Number.isInteger(u) || u < 0)) throw new errs.ValidationError("Invalid user");
	return {
		from,
		to,
		action: list(query.action),
		object: list(query.object),
		user,
		q: String(query.q ?? "")
			.trim()
			.slice(0, 200),
	};
};

const like = (q) => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

const applyFilters = (builder, f) => {
	if (f.from) builder.where("a.created_on", ">=", f.from);
	if (f.to) builder.where("a.created_on", "<=", f.to);
	if (f.action.length) builder.whereIn("a.action", f.action);
	if (f.object.length) builder.whereIn("a.object_type", f.object);
	if (f.user.length) builder.whereIn("a.user_id", f.user);
	if (f.q) {
		const pattern = like(f.q.toLowerCase());
		const meta = isPostgres() ? "a.meta::text" : "a.meta";
		// backslash escapes by default, except in SQLite
		const escapeClause = isSqlite() ? " escape '\\'" : "";
		builder.where((w) => {
			for (const column of [meta, "a.action", "a.object_type", "u.name", "u.email"]) {
				w.orWhereRaw(`lower(${column}) like ?${escapeClause}`, [pattern]);
			}
		});
	}
	return builder;
};

const base = (knex) => knex({ a: "audit_log" }).leftJoin({ u: "user" }, "u.id", "a.user_id");

const COLUMNS = [
	"a.id",
	"a.created_on",
	"a.user_id",
	"a.action",
	"a.object_type",
	"a.object_id",
	"a.meta",
	"u.name as user_name",
	"u.email as user_email",
	"u.avatar as user_avatar",
];

const toApi = (row) => ({
	id: row.id,
	created_on: new Date(row.created_on).toISOString(),
	user_id: row.user_id,
	action: row.action,
	object_type: row.object_type,
	object_id: row.object_id,
	meta: typeof row.meta === "string" ? safeJson(row.meta) : (row.meta ?? {}),
	user: row.user_name
		? { id: row.user_id, name: row.user_name, email: row.user_email, avatar: row.user_avatar }
		: null,
});

const safeJson = (text) => {
	try {
		return JSON.parse(text);
	} catch {
		return {};
	}
};

const ordered = (builder) =>
	builder.orderBy([
		{ column: "a.created_on", order: "desc" },
		{ column: "a.id", order: "desc" },
	]);

const internalAudit = {
	/**
	 * A page of the log, newest first, with the values the filters offer.
	 * @param {Access} access
	 * @param {object} query  filters (parseFilters), limit, offset
	 */
	list: async (access, query = {}) => {
		await access.can("audit_log:view");
		const f = parseFilters(query);
		const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 50, 1), MAX_LIMIT);
		const offset = Math.max(Number.parseInt(query.offset, 10) || 0, 0);
		const knex = db();
		const rows = await ordered(applyFilters(base(knex).select(COLUMNS), f))
			.limit(limit)
			.offset(offset);
		const counted = await applyFilters(base(knex), f).count({ n: "*" }).first();
		const [actions, objects, users] = await Promise.all([
			knex("audit_log").distinct("action").orderBy("action"),
			knex("audit_log").distinct("object_type").orderBy("object_type"),
			knex({ a: "audit_log" })
				.join({ u: "user" }, "u.id", "a.user_id")
				.distinct("u.id", "u.name")
				.orderBy("u.name"),
		]);
		return {
			items: rows.map(toApi),
			total: Number(counted?.n ?? 0),
			limit,
			offset,
			facets: {
				actions: actions.map((r) => r.action).filter(Boolean),
				objects: objects.map((r) => r.object_type).filter(Boolean),
				users: users.map((r) => ({ id: r.id, name: r.name })),
			},
		};
	},

	/** entries of the filters, newest first (the route writes CSV or JSON) */
	export: async (access, query = {}) => {
		await access.can("audit_log:view");
		const f = parseFilters(query);
		const rows = await ordered(applyFilters(base(db()).select(COLUMNS), f)).limit(MAX_EXPORT + 1);
		return { rows: rows.slice(0, MAX_EXPORT).map(toApi), capped: rows.length > MAX_EXPORT };
	},
};

export default internalAudit;
