// Requests of the hosts (Analytics): the access log of nginx (format alog of nginx.conf, on with LOGROTATE) is
// read every few seconds and counted per host and hour into npmos_request_hourly. The log is only read: CrowdSec
// reads it too and logrotate rotates it. The position is the cursor "nginx:access" in npmos_log_cursor.
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { global as logger } from "../../logger.js";
import { loadCursors, REQUEST_COUNTERS, store } from "./store.js";

export const LOG_FILE = process.env.NPMOS_ACCESS_LOG || "/data/nginx/logs/access.log";
const CURSOR = "nginx:access";
const INTERVAL_MS = 10000;
const MAX_BYTES = 4 * 1024 * 1024;
const HEAD_BYTES = 64;
const HOUR = 3600 * 1000;
/** answers of a refusal: the WAF and the bouncer (403), limits (429), dropped (444), mTLS (495, 496) */
const BLOCKED = new Set([403, 429, 444, 495, 496]);
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

const state = { running: false, timer: null, lastError: null, counted: 0 };
const hash = (b) => createHash("sha1").update(b).digest("hex");

/** "30/Oct/2026:08:36:30 +0000" → Date */
const parseTime = (text) => {
	const m = /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(text);
	if (!m || !(m[2] in MONTHS)) return null;
	const utc = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]);
	const offset = (m[7] === "-" ? -1 : 1) * (+m[8] * 60 + +m[9]) * 60000;
	return new Date(utc - offset);
};

/**
 * A line of the log: [time] host[:port] ip request_time "request" status body_bytes bytes_sent referer agent.
 * The admin interface (port 81) and the health check of the container are not requests of the hosts.
 * @returns {{time: Date, host: string, status: number, bytes: number}|null}
 */
export const parseLine = (line) => {
	const m = /^\[([^\]]+)\] (\S+) \S+ \S+ "[^"]*" (\d{3}) \d+ (\d+) /.exec(line);
	if (!m) return null;
	const time = parseTime(m[1]);
	if (!time) return null;
	const host = m[2].toLowerCase().replace(/:(80|443)$/, "");
	if (/:81$/.test(host) || line.endsWith(" NPMplus/healthcheck")) return null;
	return { time, host: host.slice(0, 255), status: Number(m[3]), bytes: Number(m[4]) };
};

/** rows of npmos_request_hourly for parsed lines */
export const requestAggregates = (lines, nodeId = "local") => {
	const groups = new Map();
	for (const l of lines) {
		const hour = new Date(Math.floor(l.time.getTime() / HOUR) * HOUR);
		const key = `${hour.toISOString()}\u0000${l.host}`;
		let row = groups.get(key);
		if (!row) {
			row = { node_id: nodeId, hour, host: l.host, ...Object.fromEntries(REQUEST_COUNTERS.map((c) => [c, 0])) };
			groups.set(key, row);
		}
		row.requests += 1;
		const cls = Math.floor(l.status / 100);
		if (cls >= 2 && cls <= 5) row[`s${cls}xx`] += 1;
		if (BLOCKED.has(l.status)) row.blocked += 1;
		row.bytes += l.bytes;
	}
	return [...groups.values()];
};

/** one round: new lines of the log → counters */
export const pollOnce = async ({ file = LOG_FILE } = {}) => {
	let handle;
	try {
		handle = await open(file, "r");
	} catch {
		return 0;
	}
	try {
		const { size } = await handle.stat();
		const cursor = (await loadCursors()).get(CURSOR);
		const headBuf = Buffer.alloc(Math.min(HEAD_BYTES, size));
		await handle.read(headBuf, 0, headBuf.length, 0);
		// rotated (a new file) or emptied: from the start
		let offset =
			cursor && cursor.offset <= size && cursor.head === hash(headBuf.subarray(0, cursor.headLength))
				? cursor.offset
				: 0;
		if (offset === size) return 0;
		const length = Math.min(MAX_BYTES, size - offset);
		const buf = Buffer.alloc(length);
		await handle.read(buf, 0, length, offset);
		const end = buf.lastIndexOf(0x0a);
		if (end < 0) return 0;
		const lines = buf.subarray(0, end).toString("utf8").split("\n").map(parseLine).filter(Boolean);
		offset += end + 1;
		await store({
			events: [],
			telemetry: [],
			requests: requestAggregates(lines),
			cursors: [{ key: CURSOR, file, offset, head: hash(headBuf), head_length: headBuf.length }],
		});
		state.counted += lines.length;
		return lines.length;
	} finally {
		await handle.close();
	}
};

const round = async () => {
	try {
		// a large backlog is read in several rounds without waiting
		while ((await pollOnce()) > 0 && state.running) {
			if (state.lastError) state.lastError = null;
		}
		state.lastError = null;
	} catch (err) {
		if (state.lastError !== err.message) logger.error(`NPMOS requests: ${err.message}`);
		state.lastError = err.message;
	} finally {
		if (state.running) state.timer = setTimeout(round, INTERVAL_MS);
	}
};

export const startRequests = () => {
	if (state.running) return;
	state.running = true;
	state.timer = setTimeout(round, 2000);
};

export const stopRequests = () => {
	state.running = false;
	clearTimeout(state.timer);
};

export const requestsStatus = () => ({ counted: state.counted, lastError: state.lastError });
