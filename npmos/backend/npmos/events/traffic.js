// Analytics of the traffic of the hosts (Analytics → Requests, Visitors, Performance, Security, Cache, Origin) and
// the log of every request (Analytics → Requests log), from npmos_request_log (requests.js). Periods longer than
// the log is kept (events.retention.requestDays) take their totals from the hourly aggregates; their details
// (top lists, percentiles) cover only the days still kept: `detailFrom` says from when. RBAC: analytics:view.
// Postgres only (ADR-4): buckets with date_bin, percentiles with percentile_cont.
import db from "../../db.js";
import errs from "../../lib/error.js";
import { isPostgres } from "../../lib/config.js";
import { getSetting } from "../settings.js";
import { ATTACK_KINDS, PERIODS } from "./analytics.js";
import { EVENT_TABLE, oldestKeptDay, REQUEST_LOG_TABLE } from "./store.js";

const HOUR = 3600 * 1000;
const TOP = 10;
const PAGE_MAX = 200;
const KNOWN_TTL = 30 * 1000;

export const TABS = ["requests", "visitors", "performance", "security", "cache", "origin"];

/** filters of the query → columns of npmos_request_log (exact match, comma-separated values) */
const TEXT_FILTERS = {
	host: "host",
	country: "country",
	ip: "ip",
	method: "method",
	browser: "browser",
	os: "os",
	device: "device",
	protocol: "protocol",
	tls: "tls",
	cache: "cache",
	contentType: "content_type",
	origin: "upstream_addr",
	referer: "referer_host",
	port: "port",
};

/** ranges of the query → numeric columns (min…max, both optional) */
const RANGE_FILTERS = {
	ms: "duration_ms",
	bytes: "bytes",
};

const int = (v) => {
	const n = Number.parseInt(String(v ?? ""), 10);
	return Number.isFinite(n) && n >= 0 ? n : null;
};

/** 404 or 4xx */
const statuses = (v) => list(v).filter((s) => /^[1-5](\d\d|xx)$/i.test(s));

const list = (v) =>
	String(v ?? "")
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean)
		.slice(0, 50);

/**
 * Filters of a query string.
 * @returns {{text: Record<string, string[]>, status: string[], originStatus: string[], path: string, q: string,
 *   ranges: Record<string, [number|null, number|null]>, unknown: boolean, mitigated: boolean|null}}
 */
export const parseTrafficFilters = (query = {}) => {
	const text = {};
	for (const [key, column] of Object.entries(TEXT_FILTERS)) {
		const snake = key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`);
		const values = list(query[key] ?? query[snake]);
		if (!values.length) continue;
		text[column] = column === "host" ? values.map((v) => v.toLowerCase()) : values;
		if (column === "country") text[column] = values.map((v) => v.toUpperCase());
		if (column === "port") text[column] = values.filter((v) => /^\d{1,5}$/.test(v));
		if (!text[column].length) delete text[column];
	}
	const ranges = {};
	for (const [key, column] of Object.entries(RANGE_FILTERS)) {
		const cap = key[0].toUpperCase() + key.slice(1);
		const min = int(query[`min${cap}`]);
		const max = int(query[`max${cap}`]);
		if (min !== null || max !== null) ranges[column] = [min, max];
	}
	return {
		text,
		status: statuses(query.status),
		// status of the server behind the host
		originStatus: statuses(query.originStatus ?? query.origin_status),
		// the start of a path
		path: String(query.path ?? "").slice(0, 512),
		// a part of the host, path, address, user agent or referer
		q: String(query.q ?? "")
			.trim()
			.slice(0, 200),
		ranges,
		unknown: query.unknown === "1" || query.unknown === "true" || query.unknown === true,
		mitigated:
			query.mitigated === "1" || query.mitigated === "true"
				? true
				: query.mitigated === "0" || query.mitigated === "false"
					? false
					: null,
	};
};

/** filters other than the host need the request log (the hourly aggregates know only hosts) */
export const needsLog = (f) =>
	Object.keys(f.text).some((c) => c !== "host") ||
	f.status.length > 0 ||
	f.originStatus.length > 0 ||
	Object.keys(f.ranges).length > 0 ||
	!!f.q ||
	!!f.path ||
	f.unknown ||
	f.mitigated !== null;

let known = { at: 0, exact: new Set(), wildcards: [] };

/** domain names of the hosts in NPMOS (proxy, redirection, 404 hosts): requests to other names are "unknown" */
export const knownDomains = async () => {
	if (Date.now() - known.at < KNOWN_TTL) return known;
	const knex = db();
	const exact = new Set();
	const wildcards = [];
	for (const table of ["proxy_host", "redirection_host", "dead_host"]) {
		const rows = await knex(table).where("is_deleted", 0).select("domain_names");
		for (const row of rows) {
			let names = row.domain_names;
			try {
				names = typeof names === "string" ? JSON.parse(names) : names;
			} catch {
				names = [];
			}
			for (const raw of names || []) {
				const name = String(raw).toLowerCase();
				if (name.startsWith("*.")) wildcards.push(name.slice(1));
				else exact.add(name);
			}
		}
	}
	known = { at: Date.now(), exact, wildcards };
	return known;
};

/** is a Host header one of the hosts of NPMOS */
export const isKnownHost = (host, k = known) =>
	k.exact.has(host) || k.wildcards.some((suffix) => host.endsWith(suffix) && host.length > suffix.length);

const likeEscape = (v) => v.replace(/[\\%_]/g, (c) => `\\${c}`);

/** 404 or 4xx on a status column */
const whereStatus = (b, column, list) => {
	if (!list.length) return;
	b.where((q) => {
		for (const s of list) {
			if (/xx$/i.test(s)) {
				const base = Number(s[0]) * 100;
				q.orWhereBetween(column, [base, base + 99]);
			} else q.orWhere(column, Number(s));
		}
	});
};

const SEARCH_COLUMNS = ["host", "path", "ip", "user_agent", "referer_host"];

const applyFilters = (b, f, k) => {
	for (const [column, values] of Object.entries(f.text)) b.whereIn(column, values);
	whereStatus(b, "status", f.status);
	whereStatus(b, "upstream_status", f.originStatus);
	for (const [column, [min, max]] of Object.entries(f.ranges)) {
		if (min !== null) b.where(column, ">=", min);
		if (max !== null) b.where(column, "<=", max);
	}
	if (f.q) {
		const like = `%${likeEscape(f.q)}%`;
		b.where((q) => {
			for (const column of SEARCH_COLUMNS) q.orWhereRaw("?? ILIKE ?", [column, like]);
		});
	}
	if (f.path) b.where("path", "like", `${likeEscape(f.path)}%`);
	if (f.mitigated !== null) b.where("mitigated", f.mitigated);
	if (f.unknown) {
		if (k.exact.size) b.whereNotIn("host", [...k.exact]);
		for (const suffix of k.wildcards) b.whereNot("host", "like", `%${suffix}`);
	}
	return b;
};

const num = (v) => (v === null || v === undefined ? 0 : Number(v));
const numOrNull = (v) => (v === null || v === undefined ? null : Math.round(Number(v)));
const ratio = (a, b) => (b > 0 ? a / b : null);

/** change against the previous period, null when the previous one had nothing */
const change = (now, before) => (before === null || before === undefined || !before ? null : (now - before) / before);

/**
 * Period, buckets and where the details come from.
 * @returns {Promise<object>}
 */
const context = async (query, now) => {
	const period = Object.hasOwn(PERIODS, query.period) ? query.period : "24h";
	const { length, bucket } = PERIODS[period];
	const to = now;
	const from = new Date(Math.floor((to.getTime() - length) / bucket) * bucket);
	const prevFrom = new Date(from.getTime() - length);
	const retention = await getSetting("events.retention");
	const logFrom = oldestKeptDay(retention.requestDays ?? 7, now);
	const filters = parseTrafficFilters(query);
	const k = await knownDomains();
	return {
		period,
		length,
		bucket,
		from,
		to,
		prevFrom,
		logFrom,
		requestDays: retention.requestDays ?? 7,
		filters,
		known: k,
		// the log covers the whole period: everything from it
		covered: from >= logFrom,
	};
};

const sec = (ms) => `${Math.round(ms / 1000)} seconds`;

/** a query builder over a time range of the request log, filtered */
const logQuery = (c, from = c.from, to = c.to) =>
	applyFilters(db()(REQUEST_LOG_TABLE).where("time", ">=", from).where("time", "<=", to), c.filters, c.known);

/** buckets of the period, filled by rows {t, ...counters} */
export const fillBuckets = (from, to, bucket, rows, keys) => {
	const start = Math.floor(from.getTime() / bucket) * bucket;
	const buckets = [];
	const index = new Map();
	for (let t = start; t <= to.getTime(); t += bucket) {
		index.set(t, buckets.length);
		buckets.push({ t: new Date(t).toISOString(), ...Object.fromEntries(keys.map((k) => [k, 0])) });
	}
	for (const row of rows) {
		const t = Math.floor(new Date(row.t).getTime() / bucket) * bucket;
		const i = index.get(t);
		if (i === undefined) continue;
		for (const k of keys) {
			if (row[k] === null || row[k] === undefined) continue;
			buckets[i][k] += Number(row[k]);
		}
	}
	return buckets;
};

/** a timeline from the request log: `columns` are SQL expressions by name */
const logTimeline = async (c, columns) => {
	const knex = db();
	const b = logQuery(c).select(
		knex.raw("date_bin(?::interval, time, ?::timestamptz) AS t", [sec(c.bucket), c.from.toISOString()]),
	);
	for (const [name, sql] of Object.entries(columns)) b.select(knex.raw(`${sql} AS ??`, [name]));
	const rows = await b.groupByRaw("1");
	return fillBuckets(c.from, c.to, c.bucket, rows, Object.keys(columns));
};

/** a timeline from the hourly aggregates (periods longer than the log, host filter only) */
const hourlyTimeline = async (c, columns) => {
	const knex = db();
	const b = knex("npmos_request_hourly")
		.where("hour", ">=", new Date(Math.floor(c.from.getTime() / HOUR) * HOUR))
		.where("hour", "<=", c.to)
		.select(knex.raw("date_bin(?::interval, hour, ?::timestamptz) AS t", [sec(c.bucket), c.from.toISOString()]));
	if (c.filters.text.host) b.whereIn("host", c.filters.text.host);
	for (const [name, sql] of Object.entries(columns)) b.select(knex.raw(`${sql} AS ??`, [name]));
	const rows = await b.groupByRaw("1");
	return fillBuckets(c.from, c.to, c.bucket, rows, Object.keys(columns));
};

/** the top values of a column: [{value, requests, bytes}] */
const top = async (c, column, { where, orderBy = "requests", limit = TOP, extra = {} } = {}) => {
	const knex = db();
	const b = logQuery(c)
		.select({ value: column })
		.count({ requests: "*" })
		.sum({ bytes: "bytes" })
		.groupBy(column)
		.orderBy(orderBy, "desc")
		.limit(limit);
	for (const [name, sql] of Object.entries(extra)) b.select(knex.raw(`${sql} AS ??`, [name]));
	if (where) where(b);
	const rows = await b;
	// numbers of the database come as strings (bigint, numeric): text values stay text
	const value = (v) => (v === null || v === undefined ? null : /^-?\d+(\.\d+)?$/.test(String(v)) ? Number(v) : v);
	return rows
		.filter((r) => r.value !== "" && r.value !== null)
		.map((r) => ({
			...Object.fromEntries(Object.keys(extra).map((k) => [k, value(r[k])])),
			value: String(r.value),
			requests: num(r.requests),
			bytes: num(r.bytes),
		}));
};

const STATUS_SERIES = {
	s1xx: "SUM(CASE WHEN status BETWEEN 100 AND 199 THEN 1 ELSE 0 END)",
	s2xx: "SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END)",
	s3xx: "SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END)",
	s4xx: "SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END)",
	s5xx: "SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END)",
};
const CACHE_HIT = "cache IN ('HIT', 'STALE', 'UPDATING', 'REVALIDATED')";
const CACHED = `SUM(CASE WHEN ${CACHE_HIT} THEN 1 ELSE 0 END)`;
const TO_ORIGIN = "upstream_addr <> ''";
const FAILED =
	"(upstream_addr <> '' AND (upstream_status IS NULL OR (connect_ms IS NULL AND upstream_status IN (502, 504))))";

/** totals of the request log over a range */
const logTotals = async (c, from, to, columns) => {
	const knex = db();
	const b = logQuery(c, from, to);
	for (const [name, sql] of Object.entries(columns)) b.select(knex.raw(`${sql} AS ??`, [name]));
	const row = (await b.first()) ?? {};
	return Object.fromEntries(Object.keys(columns).map((k) => [k, row[k] === null ? null : Number(row[k] ?? 0)]));
};

/** totals of the hourly aggregates over a range (host filter only) */
const hourlyTotals = async (c, from, to) => {
	const b = db()("npmos_request_hourly")
		.where("hour", ">=", new Date(Math.floor(from.getTime() / HOUR) * HOUR))
		.where("hour", "<", to)
		.sum({ requests: "requests", bytes: "bytes", s5xx: "s5xx", blocked: "blocked" });
	if (c.filters.text.host) b.whereIn("host", c.filters.text.host);
	const row = (await b.first()) ?? {};
	return { requests: num(row.requests), bytes: num(row.bytes), s5xx: num(row.s5xx), mitigated: num(row.blocked) };
};

/** requests, bytes, 5xx, mitigated: the log when it covers the range or filters need it, else the hourly rows */
const basicTotals = async (c, from, to, covered) =>
	covered || needsLog(c.filters)
		? logTotals(c, from, to, {
				requests: "COUNT(*)",
				bytes: "COALESCE(SUM(bytes), 0)",
				s5xx: STATUS_SERIES.s5xx,
				mitigated: "SUM(CASE WHEN mitigated THEN 1 ELSE 0 END)",
			})
		: hourlyTotals(c, from, to);

const kpi = (value, before, series) => ({ value, change: change(value, before), series });

/** countries of the map: [{value: ISO code, requests, mitigated, bytes}] */
const countries = async (c, { metric = "requests" } = {}) => {
	if (c.covered || needsLog(c.filters)) {
		return top(c, "country", {
			limit: 250,
			extra: {
				mitigated: "SUM(CASE WHEN mitigated THEN 1 ELSE 0 END)",
				pageviews: "SUM(CASE WHEN pageview THEN 1 ELSE 0 END)",
			},
			orderBy: metric,
		});
	}
	const b = db()("npmos_request_country_hourly")
		.where("hour", ">=", new Date(Math.floor(c.from.getTime() / HOUR) * HOUR))
		.where("hour", "<=", c.to)
		.whereNot("country", "")
		.select({ value: "country" })
		.sum({ requests: "requests", mitigated: "mitigated", bytes: "bytes" })
		.groupBy("country")
		.orderBy("requests", "desc")
		.limit(250);
	if (c.filters.text.host) b.whereIn("host", c.filters.text.host);
	return (await b).map((r) => ({
		value: r.value,
		requests: num(r.requests),
		mitigated: num(r.mitigated),
		bytes: num(r.bytes),
		pageviews: null,
	}));
};

const percentileColumns = (column) => ({
	p50: `percentile_cont(0.5) WITHIN GROUP (ORDER BY ${column})`,
	p95: `percentile_cont(0.95) WITHIN GROUP (ORDER BY ${column})`,
	p99: `percentile_cont(0.99) WITHIN GROUP (ORDER BY ${column})`,
});

const rounded = (row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, k === "t" ? v : numOrNull(v)]));

/** percentiles per bucket: percentile_cont is not additive, so empty buckets stay null */
const percentileTimeline = async (c, column, where) => {
	const knex = db();
	const b = logQuery(c).select(
		knex.raw("date_bin(?::interval, time, ?::timestamptz) AS t", [sec(c.bucket), c.from.toISOString()]),
	);
	for (const [name, sql] of Object.entries(percentileColumns(column))) b.select(knex.raw(`${sql} AS ??`, [name]));
	b.whereNotNull(column);
	if (where) where(b);
	const rows = new Map(
		(await b.groupByRaw("1")).map((r) => [Math.floor(new Date(r.t).getTime() / c.bucket) * c.bucket, r]),
	);
	return fillBuckets(c.from, c.to, c.bucket, [], []).map((bk) => {
		const r = rows.get(Date.parse(bk.t));
		return rounded({ t: bk.t, p50: r?.p50 ?? null, p95: r?.p95 ?? null, p99: r?.p99 ?? null });
	});
};

const sparkline = (timeline, key) => timeline.map((b) => b[key]);

const tabs = {
	requests: async (c) => {
		const series = {
			requests: "COUNT(*)",
			bytes: "COALESCE(SUM(bytes), 0)",
			visits: "SUM(CASE WHEN visit THEN 1 ELSE 0 END)",
			mitigated: "SUM(CASE WHEN mitigated THEN 1 ELSE 0 END)",
			cached: CACHED,
			cacheable: "SUM(CASE WHEN cache <> '' THEN 1 ELSE 0 END)",
			...STATUS_SERIES,
		};
		const fromLog = c.covered || needsLog(c.filters);
		const timeline = fromLog
			? await logTimeline(c, series)
			: await hourlyTimeline(c, {
					requests: "SUM(requests)",
					bytes: "SUM(bytes)",
					mitigated: "SUM(blocked)",
					s2xx: "SUM(s2xx)",
					s3xx: "SUM(s3xx)",
					s4xx: "SUM(s4xx)",
					s5xx: "SUM(s5xx)",
				});
		const sum = (k) => timeline.reduce((n, b) => n + num(b[k]), 0);
		const prev = await basicTotals(c, c.prevFrom, c.from, c.prevFrom >= c.logFrom);
		const prevVisits =
			c.prevFrom >= c.logFrom ? (await logTotals(c, c.prevFrom, c.from, { v: series.visits })).v : null;
		const [cache, paths, ips, hosts, browsers, os, devices, agents, protocols, statuses, ctry] = await Promise.all([
			fromLog ? null : logTotals(c, c.logFrom, c.to, { cached: CACHED, cacheable: series.cacheable }),
			top(c, "path"),
			top(c, "ip", { extra: { country: "MAX(country)" } }),
			top(c, "host"),
			top(c, "browser"),
			top(c, "os"),
			top(c, "device"),
			top(c, "user_agent"),
			top(c, "protocol"),
			top(c, "status"),
			countries(c),
		]);
		const requests = sum("requests");
		const cached = cache ? num(cache.cached) : sum("cached");
		const cacheable = cache ? num(cache.cacheable) : sum("cacheable");
		return {
			kpi: {
				requests: kpi(requests, prev.requests, sparkline(timeline, "requests")),
				bytes: kpi(sum("bytes"), prev.bytes, sparkline(timeline, "bytes")),
				visits: fromLog ? kpi(sum("visits"), prevVisits, sparkline(timeline, "visits")) : null,
				cacheHitRate: { value: ratio(cached, cacheable), change: null, series: null },
				errorRate5xx: kpi(ratio(sum("s5xx"), requests) ?? 0, ratio(prev.s5xx, prev.requests), null),
			},
			timeline,
			countries: ctry,
			top: {
				paths,
				ips: ips.map((r) => ({ ...r, country: r.country ?? "" })),
				hosts: hosts.map((r) => ({ ...r, known: isKnownHost(r.value, c.known) })),
				browsers,
				os,
				devices,
				agents,
				protocols,
				statuses,
			},
		};
	},

	visitors: async (c) => {
		const timeline = await logTimeline(c, {
			pageviews: "SUM(CASE WHEN pageview THEN 1 ELSE 0 END)",
			visits: "SUM(CASE WHEN visit THEN 1 ELSE 0 END)",
			desktop: "SUM(CASE WHEN pageview AND device = 'desktop' THEN 1 ELSE 0 END)",
			mobile: "SUM(CASE WHEN pageview AND device = 'mobile' THEN 1 ELSE 0 END)",
			tablet: "SUM(CASE WHEN pageview AND device = 'tablet' THEN 1 ELSE 0 END)",
			bot: "SUM(CASE WHEN pageview AND device = 'bot' THEN 1 ELSE 0 END)",
			other: "SUM(CASE WHEN pageview AND device = 'other' THEN 1 ELSE 0 END)",
		});
		const sum = (k) => timeline.reduce((n, b) => n + num(b[k]), 0);
		const prev =
			c.prevFrom >= c.logFrom
				? await logTotals(c, c.prevFrom, c.from, {
						pageviews: "SUM(CASE WHEN pageview THEN 1 ELSE 0 END)",
						visits: "SUM(CASE WHEN visit THEN 1 ELSE 0 END)",
					})
				: { pageviews: null, visits: null };
		const pv = (b) => b.where("pageview", true);
		const [ctry, paths, hosts, os, browsers, agents, referers] = await Promise.all([
			top(c, "country", { where: pv, limit: 250 }),
			top(c, "path", { where: pv }),
			top(c, "host", { where: pv }),
			top(c, "os", { where: pv }),
			top(c, "browser", { where: pv }),
			top(c, "user_agent", { where: pv }),
			top(c, "referer_host", { where: (b) => b.where("visit", true) }),
		]);
		return {
			kpi: {
				pageviews: kpi(sum("pageviews"), prev.pageviews, sparkline(timeline, "pageviews")),
				visits: kpi(sum("visits"), prev.visits, sparkline(timeline, "visits")),
			},
			timeline,
			countries: ctry.map((r) => ({ ...r, pageviews: r.requests })),
			top: {
				paths,
				hosts: hosts.map((r) => ({ ...r, known: isKnownHost(r.value, c.known) })),
				os,
				browsers,
				agents,
				referers,
			},
		};
	},

	performance: async (c) => {
		const toOrigin = (b) => b.whereRaw(TO_ORIGIN);
		const [origin, total, timeline, protocolTimeline, protocols, tls, pathsByBytes, slowPaths] = await Promise.all([
			logTotals(c, c.from, c.to, percentileColumns("upstream_ms")),
			logTotals(c, c.from, c.to, percentileColumns("duration_ms")),
			percentileTimeline(c, "upstream_ms", toOrigin),
			logTimeline(c, {
				http1: "SUM(CASE WHEN protocol IN ('HTTP/1.0', 'HTTP/1.1') THEN 1 ELSE 0 END)",
				http2: "SUM(CASE WHEN protocol = 'HTTP/2.0' THEN 1 ELSE 0 END)",
				http3: "SUM(CASE WHEN protocol = 'HTTP/3.0' THEN 1 ELSE 0 END)",
				other: "SUM(CASE WHEN protocol NOT IN ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0', 'HTTP/3.0') THEN 1 ELSE 0 END)",
			}),
			top(c, "protocol"),
			top(c, "tls"),
			top(c, "path", { orderBy: "bytes" }),
			top(c, "path", {
				where: (b) => b.whereRaw(TO_ORIGIN).whereNotNull("upstream_ms"),
				extra: { p95: percentileColumns("upstream_ms").p95 },
				orderBy: "p95",
			}),
		]);
		const prev =
			c.prevFrom >= c.logFrom ? await logTotals(c, c.prevFrom, c.from, percentileColumns("upstream_ms")) : null;
		return {
			kpi: {
				originP50: kpi(numOrNull(origin.p50), numOrNull(prev?.p50), sparkline(timeline, "p50")),
				originP95: kpi(numOrNull(origin.p95), numOrNull(prev?.p95), sparkline(timeline, "p95")),
				totalP50: kpi(numOrNull(total.p50), null, null),
				totalP95: kpi(numOrNull(total.p95), null, null),
			},
			timeline,
			protocolTimeline,
			top: {
				protocols,
				tls,
				pathsByBytes,
				slowPaths: slowPaths.map((r) => ({ ...r, p95: numOrNull(r.p95) })),
			},
		};
	},

	security: async (c) => {
		const knex = db();
		const mitigatedOnly = (b) => b.where("mitigated", true);
		const timeline = await logTimeline(c, {
			requests: "COUNT(*)",
			mitigated: "SUM(CASE WHEN mitigated THEN 1 ELSE 0 END)",
			allowed: "SUM(CASE WHEN mitigated THEN 0 ELSE 1 END)",
			refused: "SUM(CASE WHEN status = 403 THEN 1 ELSE 0 END)",
			rateLimited: "SUM(CASE WHEN status = 429 THEN 1 ELSE 0 END)",
			dropped: "SUM(CASE WHEN status = 444 THEN 1 ELSE 0 END)",
			mtls: "SUM(CASE WHEN status IN (495, 496) THEN 1 ELSE 0 END)",
		});
		// security products: their own events (open-appsec, CrowdSec, mTLS)
		const host = c.filters.text.host;
		const events = () => {
			const b = knex(EVENT_TABLE)
				.whereIn("kind", ATTACK_KINDS)
				.where("time", ">=", c.from)
				.where("time", "<=", c.to);
			if (host) b.whereIn("host", host);
			if (c.filters.text.ip) b.whereIn("source_ip", c.filters.text.ip);
			return b;
		};
		const productRows = await knex(EVENT_TABLE)
			.whereIn("kind", ATTACK_KINDS)
			.where("time", ">=", c.from)
			.where("time", "<=", c.to)
			.modify((b) => host && b.whereIn("host", host))
			.modify((b) => c.filters.text.ip && b.whereIn("source_ip", c.filters.text.ip))
			.select(knex.raw("date_bin(?::interval, time, ?::timestamptz) AS t", [sec(c.bucket), c.from.toISOString()]))
			.select(
				knex.raw("SUM(CASE WHEN kind = 'security' AND lower(action) = 'prevent' THEN 1 ELSE 0 END) AS ??", [
					"appsecPrevent",
				]),
				knex.raw("SUM(CASE WHEN kind = 'security' AND lower(action) = 'detect' THEN 1 ELSE 0 END) AS ??", [
					"appsecDetect",
				]),
				knex.raw("SUM(CASE WHEN kind = 'crowdsec' AND action IN ('ban', 'captcha') THEN 1 ELSE 0 END) AS ??", [
					"crowdsecBan",
				]),
				knex.raw(
					"SUM(CASE WHEN kind = 'crowdsec' AND action NOT IN ('ban', 'captcha') THEN 1 ELSE 0 END) AS ??",
					["crowdsecAlert"],
				),
				knex.raw("SUM(CASE WHEN kind = 'mtls' THEN 1 ELSE 0 END) AS ??", ["mtls"]),
			)
			.groupByRaw("1");
		const productTimeline = fillBuckets(c.from, c.to, c.bucket, productRows, [
			"appsecPrevent",
			"appsecDetect",
			"crowdsecBan",
			"crowdsecAlert",
			"mtls",
		]);
		const sum = (rows, k) => rows.reduce((n, b) => n + num(b[k]), 0);
		const [actions, attackTypes, attackCountries, attackSources, paths, mitigatedCountries, ips, attackPaths] =
			await Promise.all([
				events()
					.select("kind", "action")
					.count({ events: "*" })
					.groupBy("kind", "action")
					.orderBy("events", "desc"),
				events()
					.select({ value: knex.raw("CASE WHEN kind = 'security' THEN incident_type ELSE name END") })
					.count({ events: "*" })
					.groupByRaw("1")
					.orderBy("events", "desc")
					.limit(TOP),
				events()
					.select({ value: "source_country" })
					.count({ events: "*" })
					.whereNot("source_country", "")
					.groupBy("source_country")
					.orderBy("events", "desc")
					.limit(250),
				events()
					.select({ value: "source_ip" })
					.max({ country: "source_country" })
					.count({ events: "*" })
					.whereNot("source_ip", "")
					.groupBy("source_ip")
					.orderBy("events", "desc")
					.limit(TOP),
				top(c, "path", { where: mitigatedOnly }),
				top(c, "country", { where: mitigatedOnly, limit: 250 }),
				top(c, "ip", { where: mitigatedOnly, extra: { country: "MAX(country)" } }),
				events()
					.select({ value: "uri" })
					.count({ events: "*" })
					.whereNot("uri", "")
					.groupBy("uri")
					.orderBy("events", "desc")
					.limit(TOP),
			]);
		const requests = sum(timeline, "requests");
		const mitigated = sum(timeline, "mitigated");
		const prev = c.prevFrom >= c.logFrom ? await basicTotals(c, c.prevFrom, c.from, true) : null;
		const ev = (rows) =>
			rows.map((r) => ({ value: String(r.value ?? ""), events: num(r.events), country: r.country ?? undefined }));
		return {
			kpi: {
				requests: kpi(requests, prev?.requests, sparkline(timeline, "requests")),
				mitigated: kpi(mitigated, prev?.mitigated, sparkline(timeline, "mitigated")),
				mitigatedRate: kpi(
					ratio(mitigated, requests) ?? 0,
					prev ? ratio(prev.mitigated, prev.requests) : null,
					null,
				),
				appsec: kpi(
					sum(productTimeline, "appsecPrevent") + sum(productTimeline, "appsecDetect"),
					null,
					productTimeline.map((b) => b.appsecPrevent + b.appsecDetect),
				),
				crowdsec: kpi(
					sum(productTimeline, "crowdsecBan") + sum(productTimeline, "crowdsecAlert"),
					null,
					productTimeline.map((b) => b.crowdsecBan + b.crowdsecAlert),
				),
				rateLimited: kpi(sum(timeline, "rateLimited"), null, sparkline(timeline, "rateLimited")),
			},
			timeline,
			productTimeline,
			actions: actions.map((r) => ({ kind: r.kind, action: r.action, events: num(r.events) })),
			countries: mitigatedCountries,
			attackCountries: ev(attackCountries),
			top: {
				attackTypes: ev(attackTypes),
				attackSources: ev(attackSources),
				attackPaths: ev(attackPaths),
				paths,
				ips: ips.map((r) => ({ ...r, country: r.country ?? "" })),
			},
		};
	},

	cache: async (c) => {
		const timeline = await logTimeline(c, {
			requests: "COUNT(*)",
			cached: CACHED,
			uncached: `SUM(CASE WHEN ${CACHE_HIT} THEN 0 ELSE 1 END)`,
			bytes: "COALESCE(SUM(bytes), 0)",
			cachedBytes: `COALESCE(SUM(CASE WHEN ${CACHE_HIT} THEN bytes ELSE 0 END), 0)`,
			hit: "SUM(CASE WHEN cache = 'HIT' THEN 1 ELSE 0 END)",
			miss: "SUM(CASE WHEN cache = 'MISS' THEN 1 ELSE 0 END)",
			expired: "SUM(CASE WHEN cache = 'EXPIRED' THEN 1 ELSE 0 END)",
			bypass: "SUM(CASE WHEN cache = 'BYPASS' THEN 1 ELSE 0 END)",
			other: `SUM(CASE WHEN cache NOT IN ('', 'HIT', 'MISS', 'EXPIRED', 'BYPASS') THEN 1 ELSE 0 END)`,
			none: "SUM(CASE WHEN cache = '' THEN 1 ELSE 0 END)",
		});
		const sum = (k) => timeline.reduce((n, b) => n + num(b[k]), 0);
		const hit = (b) => b.whereRaw(CACHE_HIT);
		const miss = (b) => b.whereRaw(`NOT (${CACHE_HIT})`);
		const [cachedPaths, uncachedPaths, cachedTypes, uncachedTypes, statuses] = await Promise.all([
			top(c, "path", { where: hit }),
			top(c, "path", { where: miss }),
			top(c, "content_type", { where: hit }),
			top(c, "content_type", { where: miss }),
			top(c, "cache"),
		]);
		const requests = sum("requests");
		const cacheable = requests - sum("none");
		return {
			kpi: {
				hitRate: kpi(ratio(sum("cached"), cacheable), null, null),
				cached: kpi(sum("cached"), null, sparkline(timeline, "cached")),
				uncached: kpi(sum("uncached"), null, sparkline(timeline, "uncached")),
				cachedBytes: kpi(sum("cachedBytes"), null, sparkline(timeline, "cachedBytes")),
				bytes: kpi(sum("bytes"), null, sparkline(timeline, "bytes")),
				savedRate: kpi(ratio(sum("cachedBytes"), sum("bytes")), null, null),
			},
			timeline,
			top: { cachedPaths, uncachedPaths, cachedTypes, uncachedTypes, statuses },
		};
	},

	origin: async (c) => {
		const knex = db();
		const toOrigin = (b) => b.whereRaw(TO_ORIGIN);
		const [timeline, percentiles, totals, paths, statuses, origins, endpoints] = await Promise.all([
			logTimeline(c, {
				toOrigin: `SUM(CASE WHEN ${TO_ORIGIN} THEN 1 ELSE 0 END)`,
				reached: `SUM(CASE WHEN ${TO_ORIGIN} AND NOT ${FAILED} THEN 1 ELSE 0 END)`,
				failed: `SUM(CASE WHEN ${FAILED} THEN 1 ELSE 0 END)`,
				connectMs: "AVG(connect_ms)",
				upstreamMs: "AVG(upstream_ms)",
				u1xx: "SUM(CASE WHEN upstream_status BETWEEN 100 AND 199 THEN 1 ELSE 0 END)",
				u2xx: "SUM(CASE WHEN upstream_status BETWEEN 200 AND 299 THEN 1 ELSE 0 END)",
				u3xx: "SUM(CASE WHEN upstream_status BETWEEN 300 AND 399 THEN 1 ELSE 0 END)",
				u4xx: "SUM(CASE WHEN upstream_status BETWEEN 400 AND 499 THEN 1 ELSE 0 END)",
				u5xx: "SUM(CASE WHEN upstream_status BETWEEN 500 AND 599 THEN 1 ELSE 0 END)",
			}),
			percentileTimeline(c, "upstream_ms", toOrigin),
			logTotals(c, c.from, c.to, {
				toOrigin: `SUM(CASE WHEN ${TO_ORIGIN} THEN 1 ELSE 0 END)`,
				failed: `SUM(CASE WHEN ${FAILED} THEN 1 ELSE 0 END)`,
				errors: "SUM(CASE WHEN upstream_status >= 500 THEN 1 ELSE 0 END)",
				bytes: `COALESCE(SUM(CASE WHEN ${TO_ORIGIN} THEN bytes ELSE 0 END), 0)`,
				p50: percentileColumns("upstream_ms").p50,
				connectMs: "AVG(connect_ms)",
				upstreamMs: "AVG(upstream_ms)",
			}),
			top(c, "path", { where: toOrigin }),
			top(c, "upstream_status", { where: (b) => b.whereNotNull("upstream_status") }),
			top(c, "upstream_addr", { where: toOrigin }),
			logQuery(c)
				.whereRaw(TO_ORIGIN)
				.select("host", "path")
				.count({ requests: "*" })
				.select(
					knex.raw(`${percentileColumns("upstream_ms").p95} AS p95`),
					knex.raw("SUM(CASE WHEN upstream_status BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS e4xx"),
					knex.raw("SUM(CASE WHEN upstream_status >= 500 THEN 1 ELSE 0 END) AS e5xx"),
					knex.raw(`SUM(CASE WHEN ${FAILED} THEN 1 ELSE 0 END) AS failed`),
				)
				.groupBy("host", "path")
				.orderBy("requests", "desc")
				.limit(50),
		]);
		const sum = (k) => timeline.reduce((n, b) => n + num(b[k]), 0);
		const to = num(totals.toOrigin);
		return {
			kpi: {
				reachability: kpi(ratio(to - num(totals.failed), to), null, null),
				connectionSuccess: kpi(ratio(to - num(totals.failed), to), null, null),
				p50: kpi(numOrNull(totals.p50), null, sparkline(percentiles, "p50")),
				errorRate: kpi(ratio(num(totals.errors), to), null, null),
				requests: kpi(to, null, sparkline(timeline, "toOrigin")),
				bytes: kpi(num(totals.bytes), null, null),
			},
			timeline: timeline.map((b) => ({
				...b,
				connectMs: numOrNull(b.connectMs),
				upstreamMs: numOrNull(b.upstreamMs),
			})),
			percentiles,
			breakdown: { connectMs: numOrNull(totals.connectMs), upstreamMs: numOrNull(totals.upstreamMs) },
			failed: sum("failed"),
			top: {
				paths,
				statuses,
				origins,
				endpoints: endpoints.map((r) => ({
					host: r.host,
					path: r.path,
					requests: num(r.requests),
					p95: numOrNull(r.p95),
					rate4xx: ratio(num(r.e4xx), num(r.requests)),
					rate5xx: ratio(num(r.e5xx), num(r.requests)),
					failed: num(r.failed),
				})),
			},
		};
	},
};

/** a row of the request log for the API */
const toApi = (r, k) => ({
	id: String(r.id),
	time: new Date(r.time).toISOString(),
	host: r.host,
	known: isKnownHost(r.host, k),
	port: r.port,
	ip: r.ip,
	country: r.country,
	method: r.method,
	path: r.path,
	status: r.status,
	bytes: Number(r.bytes),
	requestBytes: Number(r.request_bytes),
	durationMs: r.duration_ms,
	upstreamMs: r.upstream_ms,
	upstreamStatus: r.upstream_status,
	upstreamAddr: r.upstream_addr,
	cache: r.cache,
	protocol: r.protocol,
	tls: r.tls,
	contentType: r.content_type,
	refererHost: r.referer_host,
	userAgent: r.user_agent,
	browser: r.browser,
	os: r.os,
	device: r.device,
	mitigated: r.mitigated,
});

const NEWEST = [
	{ column: "time", order: "desc" },
	{ column: "id", order: "desc" },
];
const EXPORT_MAX = 100000;

/** the request log between from and to (ISO, default the last 24 h), filtered */
const requestRange = async (query, now) => {
	const filters = parseTrafficFilters(query);
	const k = await knownDomains();
	const from = query.from ? new Date(query.from) : new Date(now.getTime() - 24 * HOUR);
	const to = query.to ? new Date(query.to) : now;
	if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()))
		throw new errs.ValidationError("from, to: ISO time");
	const b = applyFilters(db()(REQUEST_LOG_TABLE).where("time", ">=", from).where("time", "<=", to), filters, k);
	return { b, k };
};

/** counting of the request log stops here ("100000+") */
export const REQUEST_COUNT_CAP = 100000;

/** the count of a filtered query, up to cap + 1 */
const countOf = async (builder, cap) => {
	const knex = db();
	const row = await knex
		.count({ n: "*" })
		.from(
			builder
				.clearSelect()
				.select(knex.raw("1"))
				.limit(cap + 1)
				.as("c"),
		)
		.first();
	return Number(row?.n ?? 0);
};

/**
 * Requests of the log for Events → All, in its order (time, newest first; at the same time the events come first,
 * then the requests by id), after a cursor of that list, with their count. The filters are those Events and the
 * request log share: time range, hosts, addresses, search.
 * @param {{from: Date, to: Date, host: string[], ip: string[], q: string}} f
 * @param {{time: Date, id: string, src: "e"|"r"}|null} before
 * @returns {Promise<{rows: object[], total: number}>}
 */
export const requestFeed = async (f, before, limit, cap) => {
	const filters = parseTrafficFilters({ host: f.host.join(","), ip: f.ip.join(","), q: f.q });
	const k = await knownDomains();
	const base = () =>
		applyFilters(db()(REQUEST_LOG_TABLE).where("time", ">=", f.from).where("time", "<=", f.to), filters, k);
	const b = base();
	if (before) {
		// after an event at time t, every request of t is still to come
		if (before.src === "e") b.where("time", "<=", before.time);
		else
			b.where((q) =>
				q
					.where("time", "<", before.time)
					.orWhere((q2) => q2.where("time", before.time).where("id", "<", before.id)),
			);
	}
	const [rows, total] = await Promise.all([b.select().orderBy(NEWEST).limit(limit), countOf(base(), cap)]);
	return { rows: rows.map((r) => toApi(r, k)), total };
};

const internalTraffic = {
	/**
	 * One tab of Analytics.
	 * @param {Access} access
	 * @param {object} query  period, tab, filters (see parseTrafficFilters)
	 */
	get: async (access, query = {}, now = new Date()) => {
		await access.can("analytics:view");
		const tab = TABS.includes(query.tab) ? query.tab : "requests";
		const c = await context(query, now);
		const base = {
			tab,
			period: c.period,
			from: c.from.toISOString(),
			to: c.to.toISOString(),
			bucket: c.bucket / 1000,
			requestDays: c.requestDays,
			// details (top lists, percentiles, filters other than the host) start here
			detailFrom: c.covered ? null : c.logFrom.toISOString(),
		};
		if (!isPostgres()) return { ...base, unsupported: true };
		return { ...base, ...(await tabs[tab](c)) };
	},

	/**
	 * Requests of the log, newest first (Analytics → Requests log). Pages by a cursor: before = "<ISO time>|<id>".
	 * @param {Access} access
	 */
	list: async (access, query = {}, now = new Date()) => {
		await access.can("analytics:view");
		if (!isPostgres()) return { rows: [], next: null, unsupported: true };
		const { b, k } = await requestRange(query, now);
		const limit = Math.min(PAGE_MAX, Math.max(1, Number.parseInt(query.limit, 10) || 50));
		if (query.before) {
			const [t, id] = String(query.before).split("|");
			const time = new Date(t);
			if (!Number.isNaN(time.getTime()) && /^\d+$/.test(id ?? "")) {
				b.where((q) => q.where("time", "<", time).orWhere((q2) => q2.where("time", time).where("id", "<", id)));
			}
		}
		const count = requestRange(query, now).then((r) => countOf(r.b, REQUEST_COUNT_CAP));
		const [rows, total] = await Promise.all([
			b
				.select()
				.orderBy(NEWEST)
				.limit(limit + 1),
			count,
		]);
		const page = rows.slice(0, limit).map((r) => toApi(r, k));
		const last = page[page.length - 1];
		return {
			rows: page,
			next: rows.length > limit && last ? `${last.time}|${last.id}` : null,
			total: Math.min(total, REQUEST_COUNT_CAP),
			totalCapped: total > REQUEST_COUNT_CAP,
		};
	},

	/**
	 * Requests of the log for a file (Events → Requests → Export): the filters of list, newest first.
	 * @param {Access} access
	 * @returns {Promise<{rows: object[], capped: boolean}>}
	 */
	export: async (access, query = {}, now = new Date()) => {
		await access.can("analytics:view");
		if (!isPostgres()) return { rows: [], capped: false };
		const { b, k } = await requestRange(query, now);
		const rows = await b
			.select()
			.orderBy(NEWEST)
			.limit(EXPORT_MAX + 1);
		return { rows: rows.slice(0, EXPORT_MAX).map((r) => toApi(r, k)), capped: rows.length > EXPORT_MAX };
	},
};

export default internalTraffic;
