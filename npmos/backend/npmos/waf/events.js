// WAF -> Events: the open-appsec agent's security log, as the "Security Log" of open-appsec-npm.
// The agent writes one JSON event per line to /var/log/nano_agent/cp-nano-*.log<n> (volume
// appsec-logs, mounted read-only in npmos at /ext/appsec-logs). Only the tail of each file is read.
import fs from "node:fs/promises";
import path from "node:path";

const LOG_DIR = process.env.NPMOS_APPSEC_LOG_DIR || "/ext/appsec-logs";
const LOG_FILE = /^cp-nano-[a-z0-9-]+\.log\d*$/;
/** bytes read from the end of each file */
const TAIL_BYTES = 16 * 1024 * 1024;
const MAX_LIMIT = 1000;

export const VIEWS = ["important", "all"];

/** "Important events" of open-appsec-npm */
const IMPORTANT_SEVERITIES = ["critical", "high"];
/** periodic statistics, hidden from "All events" as in open-appsec-npm */
const TELEMETRY = ["waap telemetry", "waap attack type telemetry", "ips stats"];
/** the orchestration's reminder (every 30 s) to define an agent profile in the Check Point cloud */
const CLOUD_NOTICE = "cloud-notice";

const lower = (value) =>
	String(value ?? "")
		.trim()
		.toLowerCase();

const readTail = async (file) => {
	const handle = await fs.open(file, "r");
	try {
		const { size } = await handle.stat();
		const start = Math.max(0, size - TAIL_BYTES);
		const buffer = Buffer.alloc(size - start);
		await handle.read(buffer, 0, buffer.length, start);
		const lines = buffer.toString("utf8").split("\n");
		// the first line is cut when the file is longer than the tail
		return { lines: start > 0 ? lines.slice(1) : lines, truncated: start > 0 };
	} finally {
		await handle.close();
	}
};

/** agent time is UTC without a zone: "2026-10-27T05:44:40.123" */
const toIso = (time) => {
	if (!time) return null;
	const date = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(time) ? time : `${time}Z`);
	return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

const toEvent = (raw, source) => {
	const data = raw.eventData || {};
	const origin = raw.eventSource || {};
	return {
		time: toIso(raw.eventTime),
		name: raw.eventName || "",
		severity: raw.eventSeverity || "",
		priority: raw.eventPriority || "",
		level: raw.eventLevel || "",
		service: origin.serviceName || "",
		asset: origin.assetName || "",
		action: data.securityAction || "",
		incidentType: data.waapIncidentType || "",
		sourceIp: data.sourceIP || "",
		proxyIp: data.proxyIP || "",
		host: data.httpHostName || "",
		method: data.httpMethod || "",
		uri: data.httpUriPath || "",
		matchedLocation: data.matchedLocation || "",
		matchedParameter: data.matchedParameter || "",
		matchedSample: data.matchedSample || "",
		source: origin.source === "fog_communication" ? CLOUD_NOTICE : source,
		raw,
	};
};

const matchesView = (event, view) =>
	view === "important"
		? IMPORTANT_SEVERITIES.includes(lower(event.severity))
		: !TELEMETRY.includes(lower(event.name)) && event.source !== CLOUD_NOTICE;

/**
 * @param {string} [dir]
 * @returns {Promise<{events: object[], truncated: boolean, available: boolean}>}  newest first
 */
export const readEvents = async (dir = LOG_DIR) => {
	let files;
	try {
		files = (await fs.readdir(dir)).filter((f) => LOG_FILE.test(f));
	} catch {
		return { events: [], truncated: false, available: false };
	}
	const events = [];
	let truncated = false;
	for (const file of files) {
		let tail;
		try {
			tail = await readTail(path.join(dir, file));
		} catch {
			continue;
		}
		truncated ||= tail.truncated;
		const source = file.replace(/\.log\d*$/, "");
		for (const line of tail.lines) {
			if (!line.startsWith("{")) continue;
			try {
				const raw = JSON.parse(line);
				if (raw?.eventTime) events.push(toEvent(raw, source));
			} catch {
				// debug output or a line being written
			}
		}
	}
	events.sort((a, b) => (b.time || "").localeCompare(a.time || ""));
	return { events, truncated, available: true };
};

const internalWafEvents = {
	/**
	 * @param {Access} access
	 * @param {{view?: string, host?: string, query?: string, limit?: number}} options
	 * @returns {Promise<{events: object[], total: number, truncated: boolean, available: boolean}>}
	 */
	list: async (access, { view = "important", host = "", query = "", limit = 200 } = {}) => {
		await access.can("npmos_services:list");
		const { events, truncated, available } = await readEvents();
		const q = lower(query);
		const h = lower(host);
		const matching = events.filter(
			(e) =>
				matchesView(e, VIEWS.includes(view) ? view : "important") &&
				(!h || lower(e.host) === h) &&
				(!q || JSON.stringify(e.raw).toLowerCase().includes(q)),
		);
		return {
			events: matching.slice(0, Math.min(Math.max(limit, 1), MAX_LIMIT)),
			total: matching.length,
			truncated,
			available,
		};
	},
};

export default internalWafEvents;
