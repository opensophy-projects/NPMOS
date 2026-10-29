// WAF → Analytics (docs/ROADMAP.md, phase 4): what the cloud dashboard of open-appsec showed, from
// the stored events and their hourly aggregates. RBAC: analytics:view.
import db from "../../db.js";
import { isPostgres } from "../../lib/config.js";
import { IMPORTANT_SEVERITIES } from "./normalize.js";
import { EVENT_TABLE } from "./store.js";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const TOP = 10;

/** period → length and size of a timeline bucket */
export const PERIODS = {
	"1h": { length: HOUR, bucket: 5 * MINUTE },
	"24h": { length: DAY, bucket: HOUR },
	"7d": { length: 7 * DAY, bucket: 6 * HOUR },
	"30d": { length: 30 * DAY, bucket: DAY },
};

const isPrevent = (action) => action.toLowerCase() === "prevent";
const isDetect = (action) => action.toLowerCase() === "detect";

/**
 * Empty buckets from `from` to `to`, aligned to the bucket size (UTC).
 * @returns {{t: string, prevent: number, detect: number, other: number}[]}
 */
export const emptyTimeline = (from, to, bucket) => {
	const start = Math.floor(from.getTime() / bucket) * bucket;
	const buckets = [];
	for (let t = start; t <= to.getTime(); t += bucket) {
		buckets.push({ t: new Date(t).toISOString(), prevent: 0, detect: 0, other: 0 });
	}
	return buckets;
};

/** adds counted rows ({time, action, events}) to the buckets */
export const fillTimeline = (buckets, rows, bucket) => {
	if (!buckets.length) return buckets;
	const start = Date.parse(buckets[0].t);
	for (const row of rows) {
		const i = Math.floor((new Date(row.time).getTime() - start) / bucket);
		if (i < 0 || i >= buckets.length) continue;
		const key = isPrevent(row.action) ? "prevent" : isDetect(row.action) ? "detect" : "other";
		buckets[i][key] += Number(row.events);
	}
	return buckets;
};

const count = (rows, key, label) =>
	rows.map((r) => ({ [label]: r[key], events: Number(r.events) })).filter((r) => r[label] !== "");

const internalAnalytics = {
	/**
	 * @param {Access} access
	 * @param {{period?: string, host?: string}} query
	 */
	get: async (access, query = {}, now = new Date()) => {
		await access.can("analytics:view");
		const period = Object.hasOwn(PERIODS, query.period) ? query.period : "24h";
		const { length, bucket } = PERIODS[period];
		const to = now;
		// the start is aligned to a bucket: the timeline and the counts cover the same events
		const from = new Date(Math.floor((to.getTime() - length) / bucket) * bucket);
		const host = String(query.host ?? "")
			.trim()
			.toLowerCase();
		const knex = db();

		const events = () => {
			const b = knex(EVENT_TABLE).where("kind", "security").where("time", ">=", from).where("time", "<=", to);
			if (host) b.where("host", host);
			return b;
		};
		const important = (b) =>
			b.whereRaw(`lower(severity) in (${IMPORTANT_SEVERITIES.map(() => "?").join(",")})`, IMPORTANT_SEVERITIES);

		const crowdsecQuery = () => {
			const b = knex(EVENT_TABLE).where("kind", "crowdsec").where("time", ">=", from).where("time", "<=", to);
			if (host) b.where("host", host);
			return b
				.count({ alerts: "*" })
				.select(knex.raw("SUM(CASE WHEN action IN ('ban', 'captcha') THEN 1 ELSE 0 END) AS bans"))
				.first();
		};
		const crowdsec = await crowdsecQuery();

		// counts by action, severity, type and host: from the events (exact for any period they cover)
		const [byAction, bySeverity, byType, byHost, sources, uris, topSources, countries, lastBlocked] =
			await Promise.all([
				events().select("action").count({ events: "*" }).groupBy("action"),
				events().select("severity").count({ events: "*" }).groupBy("severity"),
				events()
					.select("incident_type")
					.count({ events: "*" })
					.groupBy("incident_type")
					.orderBy("events", "desc")
					.limit(TOP + 1),
				events()
					.select("host")
					.count({ events: "*" })
					.select(knex.raw("SUM(CASE WHEN lower(action) = 'prevent' THEN 1 ELSE 0 END) AS prevented"))
					.groupBy("host")
					.orderBy("events", "desc")
					.limit(TOP + 1),
				events().countDistinct({ n: "source_ip" }).first(),
				events()
					.select("host", "uri")
					.count({ events: "*" })
					.groupBy("host", "uri")
					.orderBy("events", "desc")
					.limit(TOP),
				important(events())
					.select("source_ip")
					.max({ country: "source_country" })
					.count({ events: "*" })
					.whereNot("source_ip", "")
					.groupBy("source_ip")
					.orderBy("events", "desc")
					.limit(TOP),
				events()
					.select("source_country")
					.count({ events: "*" })
					.whereNot("source_country", "")
					.groupBy("source_country")
					.orderBy("events", "desc")
					.limit(TOP),
				events()
					.select(
						"id",
						"time",
						"severity",
						"action",
						"incident_type",
						"source_ip",
						"host",
						"method",
						"uri",
						"score",
					)
					.whereRaw("lower(action) = 'prevent'")
					.orderBy([
						{ column: "time", order: "desc" },
						{ column: "id", order: "desc" },
					])
					.limit(TOP),
			]);

		// timeline: buckets of 5 min from the events, longer ones from the hourly aggregates
		let timelineRows;
		if (bucket < HOUR) {
			if (isPostgres()) {
				const b = events()
					.select(
						knex.raw("date_bin(?::interval, time, ?::timestamptz) AS time", [
							`${bucket / 1000} seconds`,
							from,
						]),
					)
					.select("action")
					.count({ events: "*" })
					.groupByRaw("1, 2");
				timelineRows = await b;
			} else {
				timelineRows = (await events().select("time", "action").limit(500000)).map((r) => ({
					...r,
					events: 1,
				}));
			}
		} else {
			const b = knex("npmos_event_hourly")
				.select({ time: "hour" }, "action")
				.sum({ events: "events" })
				.where("kind", "security")
				.where("hour", ">=", from)
				.where("hour", "<=", to)
				.groupBy("hour", "action");
			if (host) b.where("host", host);
			timelineRows = await b;
		}
		const timeline = fillTimeline(emptyTimeline(from, to, bucket), timelineRows, bucket);

		// requests seen by the agent ("WAAP telemetry", per asset and hour)
		const traffic = await knex("npmos_traffic_hourly")
			.sum({ requests: "requests", blocked: "blocked" })
			.where("hour", ">=", new Date(Math.floor(from.getTime() / HOUR) * HOUR))
			.where("hour", "<=", to)
			.modify((b) => host && b.where("asset", host))
			.first();

		const total = byAction.reduce((n, r) => n + Number(r.events), 0);
		const prevented = byAction.filter((r) => isPrevent(r.action)).reduce((n, r) => n + Number(r.events), 0);
		return {
			period,
			from: from.toISOString(),
			to: to.toISOString(),
			bucket: bucket / 1000,
			host: host || null,
			kpi: {
				requests:
					traffic?.requests === null || traffic?.requests === undefined ? null : Number(traffic.requests),
				attacks: total,
				prevented,
				detected: byAction.filter((r) => isDetect(r.action)).reduce((n, r) => n + Number(r.events), 0),
				sources: Number(sources?.n ?? 0),
				// readiness of learning per host: phase 8 (smartsync-tuning)
				readiness: null,
				// alerts of CrowdSec in the period, those with a ban or captcha (phase 7)
				crowdsec_alerts: Number(crowdsec?.alerts ?? 0),
				crowdsec_bans: Number(crowdsec?.bans ?? 0),
			},
			timeline,
			actions: count(byAction, "action", "action"),
			severities: count(bySeverity, "severity", "severity"),
			types: count(byType, "incident_type", "type").slice(0, TOP),
			hosts: byHost
				.filter((r) => r.host !== "")
				.slice(0, TOP)
				.map((r) => ({ host: r.host, events: Number(r.events), prevented: Number(r.prevented) })),
			uris: uris.map((r) => ({ host: r.host, uri: r.uri, events: Number(r.events) })),
			sources: topSources.map((r) => ({ ip: r.source_ip, country: r.country || "", events: Number(r.events) })),
			countries: count(countries, "source_country", "country"),
			lastBlocked: lastBlocked.map((r) => ({
				...r,
				id: String(r.id),
				time: new Date(r.time).toISOString(),
				score: r.score === null ? null : Number(r.score),
			})),
		};
	},

	/**
	 * Attacks per host and hour of the last 24 h (hosts table: a small chart in the row).
	 * @returns {Promise<{host: string, events: number, prevented: number, hours: number[]}[]>}
	 */
	hosts: async (access, now = new Date()) => {
		await access.can("analytics:view");
		const end = Math.floor(now.getTime() / HOUR) * HOUR;
		const from = new Date(end - 23 * HOUR);
		const rows = await db()("npmos_event_hourly")
			.select("host", { time: "hour" }, "action")
			.sum({ events: "events" })
			.where("kind", "security")
			.whereNot("host", "")
			.where("hour", ">=", from)
			.groupBy("host", "hour", "action");
		const byHost = new Map();
		for (const row of rows) {
			let entry = byHost.get(row.host);
			if (!entry) {
				entry = { host: row.host, events: 0, prevented: 0, hours: new Array(24).fill(0) };
				byHost.set(row.host, entry);
			}
			const i = Math.floor((new Date(row.time).getTime() - from.getTime()) / HOUR);
			const n = Number(row.events);
			if (i >= 0 && i < 24) entry.hours[i] += n;
			entry.events += n;
			if (isPrevent(row.action)) entry.prevented += n;
		}
		return [...byHost.values()];
	},
};

export default internalAnalytics;
