// Storage of security events: day partitions (Postgres), aggregates, retention.
import db from "../../db.js";
import { isMysql, isPostgres } from "../../lib/config.js";
import { enrich } from "../geoip/index.js";
import { dayOf, hourOf } from "./normalize.js";

export const EVENT_TABLE = "npmos_security_event";
const PARTITION = /^npmos_security_event_p(\d{4})(\d{2})(\d{2})$/;
const INSERT_BATCH = 500;
/** partitions created ahead, so that the first events of a day never wait for one */
const DAYS_AHEAD = 2;

const knownPartitions = new Set();

const partitionName = (day) => `${EVENT_TABLE}_p${day.replaceAll("-", "")}`;

const nextDay = (day) => {
	const date = new Date(`${day}T00:00:00Z`);
	date.setUTCDate(date.getUTCDate() + 1);
	return dayOf(date);
};

/** partition of a day (Postgres only), idempotent */
export const ensurePartition = async (day, knex = db()) => {
	if (!isPostgres() || knownPartitions.has(day)) return;
	await knex.raw(
		`CREATE TABLE IF NOT EXISTS ?? PARTITION OF ?? FOR VALUES FROM ('${day}T00:00:00Z') TO ('${nextDay(day)}T00:00:00Z')`,
		[partitionName(day), EVENT_TABLE],
	);
	knownPartitions.add(day);
};

/** today and the next days */
export const ensureCurrentPartitions = async (now = new Date()) => {
	let day = dayOf(now);
	for (let i = 0; i <= DAYS_AHEAD; i++) {
		await ensurePartition(day);
		day = nextDay(day);
	}
};

/** counter += excluded counter, in the dialect of the database */
const increment = (knex, table, column) =>
	isMysql()
		? knex.raw("?? + VALUES(??)", [column, column])
		: knex.raw("??.?? + excluded.??", [table, column, column]);

const EVENT_KEYS = ["hour", "node_id", "host", "kind", "action", "severity", "incident_type"];
const TRAFFIC_KEYS = ["hour", "node_id", "asset"];
const TRAFFIC_COUNTERS = ["requests", "sources", "blocked", "threat_low", "threat_medium", "threat_high"];
const REQUEST_KEYS = ["hour", "node_id", "host"];
export const REQUEST_COUNTERS = ["requests", "s2xx", "s3xx", "s4xx", "s5xx", "blocked", "bytes"];

/** rows of npmos_event_hourly for these events */
export const eventAggregates = (events) => {
	const groups = new Map();
	for (const e of events) {
		const row = {
			hour: hourOf(e.time),
			node_id: e.node_id,
			host: e.host,
			kind: e.kind,
			action: e.action,
			severity: e.severity,
			incident_type: e.incident_type,
		};
		const key = EVENT_KEYS.map((k) => (row[k] instanceof Date ? row[k].toISOString() : row[k])).join("\u0000");
		const group = groups.get(key);
		if (group) group.events += 1;
		else groups.set(key, { ...row, events: 1 });
	}
	return [...groups.values()];
};

/** telemetry rows of the same asset and hour summed up */
export const trafficAggregates = (rows) => {
	const groups = new Map();
	for (const row of rows) {
		const key = `${row.hour.toISOString()}\u0000${row.node_id}\u0000${row.asset}`;
		const group = groups.get(key);
		if (!group) {
			groups.set(key, { ...row });
			continue;
		}
		for (const counter of TRAFFIC_COUNTERS) group[counter] += row[counter];
	}
	return [...groups.values()];
};

/**
 * Stores what one read of the log files gave, with the new positions, in one transaction: a
 * restart never loses or doubles events.
 * @param {{events: object[], telemetry: object[], cursors: object[], requests?: object[]}} batch  requests: rows
 *   of npmos_request_hourly (counted from the access log of nginx)
 */
export const store = async ({ events, telemetry, cursors, requests = [] }) => {
	const knex = db();
	// the agent knows no countries offline: the GeoIP database of NPMOS fills them in
	await enrich(events);
	for (const day of new Set(events.map((e) => dayOf(e.time)))) {
		await ensurePartition(day, knex);
	}
	await knex.transaction(async (trx) => {
		for (let i = 0; i < events.length; i += INSERT_BATCH) {
			await trx(EVENT_TABLE).insert(events.slice(i, i + INSERT_BATCH));
		}
		for (const row of eventAggregates(events)) {
			await trx("npmos_event_hourly")
				.insert(row)
				.onConflict(EVENT_KEYS)
				.merge({ events: increment(trx, "npmos_event_hourly", "events") });
		}
		for (const row of trafficAggregates(telemetry)) {
			await trx("npmos_traffic_hourly")
				.insert(row)
				.onConflict(TRAFFIC_KEYS)
				.merge(Object.fromEntries(TRAFFIC_COUNTERS.map((c) => [c, increment(trx, "npmos_traffic_hourly", c)])));
		}
		for (const row of requests) {
			await trx("npmos_request_hourly")
				.insert(row)
				.onConflict(REQUEST_KEYS)
				.merge(Object.fromEntries(REQUEST_COUNTERS.map((c) => [c, increment(trx, "npmos_request_hourly", c)])));
		}
		for (const cursor of cursors) {
			await trx("npmos_log_cursor")
				.insert({ ...cursor, modified_on: new Date() })
				.onConflict("key")
				.merge();
		}
	});
};

/** @returns {Promise<Map<string, {key, file, offset, head, headLength}>>} */
export const loadCursors = async () => {
	const rows = await db()("npmos_log_cursor").select();
	return new Map(
		rows.map((r) => [
			r.key,
			{ key: r.key, file: r.file, offset: Number(r.offset), head: r.head, headLength: r.head_length },
		]),
	);
};

/** forget files that are gone */
export const dropCursors = async (keys) => {
	if (keys.length) await db()("npmos_log_cursor").whereIn("key", keys).delete();
};

/**
 * Removes events older than `days` days and aggregates older than `aggregateDays` days.
 * On Postgres whole partitions are dropped (no slow DELETE, no bloat).
 * @returns {Promise<{partitions: string[], events: number, aggregates: number}>}
 */
export const applyRetention = async ({ days, aggregateDays }, now = new Date()) => {
	const knex = db();
	const cutoff = oldestKeptDay(days, now);
	const result = { partitions: [], events: 0, aggregates: 0 };
	if (isPostgres()) {
		const { rows } = await knex.raw(
			"SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = ?",
			[EVENT_TABLE],
		);
		const oldest = dayOf(cutoff);
		for (const { name } of rows) {
			const m = PARTITION.exec(name);
			if (!m) continue;
			const day = `${m[1]}-${m[2]}-${m[3]}`;
			if (day < oldest) {
				await knex.raw("DROP TABLE IF EXISTS ??", [name]);
				knownPartitions.delete(day);
				result.partitions.push(name);
			}
		}
	} else {
		result.events = await knex(EVENT_TABLE).where("time", "<", cutoff).delete();
	}
	const aggregateCutoff = new Date(now.getTime() - aggregateDays * 24 * 3600 * 1000);
	result.aggregates =
		(await knex("npmos_event_hourly").where("hour", "<", aggregateCutoff).delete()) +
		(await knex("npmos_traffic_hourly").where("hour", "<", aggregateCutoff).delete()) +
		(await knex("npmos_request_hourly").where("hour", "<", aggregateCutoff).delete());
	return result;
};

/** the first day still kept (events older than that are not stored) */
export const oldestKeptDay = (days, now = new Date()) => {
	const cutoff = new Date(now);
	cutoff.setUTCHours(0, 0, 0, 0);
	cutoff.setUTCDate(cutoff.getUTCDate() - days + 1);
	return cutoff;
};
