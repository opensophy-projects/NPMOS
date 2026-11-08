// Requests of the hosts (Analytics): the JSON log of nginx (log_format nginxions_requests of nginx.conf, written to
// nginxions-requests.log next to the access log) is read every few seconds. Every request becomes a row of
// nginxions_request_log (kept events.retention.requestDays days) and is counted per host and hour into
// nginxions_request_hourly and per country into nginxions_request_country_hourly. The log is only read: logrotate rotates
// it. The position is the cursor "nginx:requests" in nginxions_log_cursor.
import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import db from "../../db.js";
import { global as logger } from "../../logger.js";
import { countryCodes } from "../geoip/index.js";
import { classifyClient, scans } from "./client.js";
import { loadCursors, REQUEST_COUNTERS, REQUEST_LOG_TABLE, store } from "./store.js";
import { parseUserAgent } from "./useragent.js";

export const LOG_FILE = process.env.NGINXIONS_REQUEST_LOG || "/data/nginx/logs/nginxions-requests.log";
const CURSOR = "nginx:requests";
const INTERVAL_MS = 5000;
const MAX_BYTES = 4 * 1024 * 1024;
const HEAD_BYTES = 64;
const HOUR = 3600 * 1000;
/** answers of a refusal: the WAF and the bouncer (403), limits (429), dropped (444), mTLS (495, 496) */
const BLOCKED = new Set([403, 429, 444, 495, 496]);

/**
 * Refused: never reached the server behind the host. A refusal of the protection (BLOCKED), or any 4xx nginx
 * answered itself, with no answer of an upstream (a broken request 400, CONNECT 405, a 404 host, a basic auth 401).
 * Analytics count these as "Refused", not "Passed".
 */
export const refused = (status, upstreamStatus) =>
	BLOCKED.has(status) || (status >= 400 && status < 500 && (upstreamStatus === null || upstreamStatus === undefined));

const state = { running: false, timer: null, lastError: null };
// nosemgrep: nginxions-weak-hash -- recognizes a rotated log by its first bytes (a cursor stored in the database), not a secret
const hash = (b) => createHash("sha1").update(b).digest("hex");

/** "0.004, 0.002" (one value per upstream tried) or "-" → milliseconds of the last one, null when none */
const lastMs = (value) => {
	const parts = String(value ?? "")
		.split(/[,:]\s*/)
		.map((v) => v.trim())
		.filter((v) => v && v !== "-");
	if (!parts.length) return null;
	const n = Number(parts[parts.length - 1]);
	return Number.isFinite(n) ? Math.round(n * 1000) : null;
};

const lastStatus = (value) => {
	const parts = String(value ?? "")
		.split(/[,:]\s*/)
		.map((v) => Number.parseInt(v, 10))
		.filter((v) => Number.isInteger(v) && v >= 100 && v < 1000);
	return parts.length ? parts[parts.length - 1] : null;
};

const refererHost = (ref) => {
	if (!ref || ref === "-") return "";
	try {
		return new URL(ref).hostname.toLowerCase().slice(0, 255);
	} catch {
		return "";
	}
};

const text = (v, max) => {
	const s = String(v ?? "");
	return (s === "-" ? "" : s).slice(0, max);
};

/**
 * A line of the JSON log (log_format nginxions_requests). The admin interface (port 81) and the health check of the
 * container are not requests of the hosts; nor are the requests of a proxy host that opens the interface by a
 * domain (left out by pollOnce).
 * @returns {object|null}  a row of nginxions_request_log without the country
 */
export const parseLine = (line) => {
	if (line?.[0] !== "{") return null;
	let r;
	try {
		r = JSON.parse(line);
	} catch {
		return null;
	}
	const time = new Date(Number(r.t) * 1000);
	if (Number.isNaN(time.getTime())) return null;
	const port = Number.parseInt(r.port, 10) || null;
	const ua = text(r.ua, 512);
	if (port === 81 || ua === "NPMplus/healthcheck") return null;
	const host = text(r.h, 255).toLowerCase();
	const status = Number(r.s) || 0;
	const method = text(r.m, 16).toUpperCase();
	const contentType = text(r.ct, 100).split(";")[0].trim().toLowerCase();
	const referer = refererHost(r.ref);
	// a page view: a page (HTML) answered without error; a visit: a page view not coming from the same site
	const pageview = method === "GET" && status >= 200 && status < 400 && contentType === "text/html";
	const { browser, os, device } = parseUserAgent(ua);
	const row = {
		node_id: "local",
		time,
		host,
		port,
		ip: text(r.ip, 64),
		country: "",
		method,
		path: text(r.u, 2048),
		status,
		bytes: Number(r.b) || 0,
		request_bytes: Number(r.rl) || 0,
		duration_ms: Math.round((Number(r.rt) || 0) * 1000),
		upstream_ms: lastMs(r.ut),
		connect_ms: lastMs(r.uct),
		upstream_status: lastStatus(r.us),
		upstream_addr: text(
			String(r.ua_addr ?? "")
				.split(/,\s*/)
				.pop(),
			255,
		),
		cache: text(r.cache, 16).toUpperCase(),
		protocol: text(r.proto, 16),
		tls: text(r.tls, 16),
		content_type: contentType,
		referer_host: referer,
		user_agent: ua,
		browser,
		os,
		device,
		pageview,
		visit: pageview && referer !== host,
		mitigated: refused(status, lastStatus(r.us)),
	};
	// human, bot or scanner: Accept-Language is only read here (lines of before it was logged have none)
	row.client = classifyClient({ ...row, acceptLanguage: r.al === undefined ? undefined : text(r.al, 64) });
	return row;
};

const SCANNER_TTL = 24 * HOUR;
const SCANNER_MAX = 100000;
/** addresses seen scanning (ip → until when): their other requests are a scanner's too */
const scanners = new Map();

/**
 * Once an address scans, it is a scanner for a day: its requests in the same batch and later ones are marked so,
 * whatever they look like (a scanner opens the home page before it probes /.env). Returns the addresses new in
 * this batch, whose requests of the last hour are marked in the log too (pollOnce).
 */
export const spreadScanners = (lines, now = Date.now()) => {
	const fresh = new Set();
	for (const l of lines) {
		if (!l.ip || !scans(l)) continue;
		if (!((scanners.get(l.ip) ?? 0) > now)) fresh.add(l.ip);
		scanners.set(l.ip, now + SCANNER_TTL);
	}
	for (const l of lines) if (l.client !== "scanner" && (scanners.get(l.ip) ?? 0) > now) l.client = "scanner";
	if (scanners.size > SCANNER_MAX) {
		for (const [ip, until] of scanners) if (until <= now || scanners.size > SCANNER_MAX) scanners.delete(ip);
	}
	return [...fresh];
};

/** a proxy host that forwards to the interface of NginxionS itself (port 81 of this container) */
export const isInterfaceHost = ({ forward_host: host, forward_port: port }) =>
	Number(port) === 81 && ["127.0.0.1", "localhost", "::1", "[::1]"].includes(String(host || "").toLowerCase());

/**
 * Domains of the proxy hosts that open the interface of NginxionS by a domain: its pages poll the API every few
 * seconds while open, which is not traffic of a site (tens of thousands of "requests" a day per open tab).
 */
const interfaceDomains = async () => {
	const rows = await db()("proxy_host").where("is_deleted", 0).select("domain_names", "forward_host", "forward_port");
	const domains = new Set();
	for (const row of rows.filter(isInterfaceHost)) {
		let names = row.domain_names;
		try {
			names = typeof names === "string" ? JSON.parse(names) : names;
		} catch {
			names = [];
		}
		for (const name of names || []) domains.add(String(name).toLowerCase());
	}
	return domains;
};

/** rows of nginxions_request_hourly for parsed lines */
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
		if (l.mitigated) row.blocked += 1;
		row.bytes += l.bytes;
	}
	return [...groups.values()];
};

/** rows of nginxions_request_country_hourly for parsed lines with their countries */
export const countryAggregates = (lines, nodeId = "local") => {
	const groups = new Map();
	for (const l of lines) {
		const hour = new Date(Math.floor(l.time.getTime() / HOUR) * HOUR);
		const key = `${hour.toISOString()}\u0000${l.host}\u0000${l.country}`;
		let row = groups.get(key);
		if (!row) {
			row = { node_id: nodeId, hour, host: l.host, country: l.country, requests: 0, mitigated: 0, bytes: 0 };
			groups.set(key, row);
		}
		row.requests += 1;
		if (l.mitigated) row.mitigated += 1;
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
		const skip = await interfaceDomains();
		const lines = buf
			.subarray(0, end)
			.toString("utf8")
			.split("\n")
			.map(parseLine)
			.filter((l) => l && !skip.has(l.host));
		const countries = await countryCodes(new Set(lines.map((l) => l.ip)));
		for (const l of lines) l.country = countries.get(l.ip) || "";
		const newScanners = spreadScanners(lines);
		offset += end + 1;
		await store({
			events: [],
			telemetry: [],
			requests: requestAggregates(lines),
			requestLog: lines,
			countries: countryAggregates(lines),
			cursors: [{ key: CURSOR, file, offset, head: hash(headBuf), head_length: headBuf.length }],
		});
		// the requests an address made in the last hour before it was seen scanning
		if (newScanners.length)
			await db()(REQUEST_LOG_TABLE)
				.where("time", ">=", new Date(Date.now() - HOUR))
				.whereIn("ip", newScanners.slice(0, 1000))
				.whereNot("client", "scanner")
				.update({ client: "scanner" })
				.catch((err) => logger.warn(`NginxionS request log: marking scanners: ${err.message}`));
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
		if (state.lastError !== err.message) logger.error(`NginxionS requests: ${err.message}`);
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
