// Requests refused by mTLS → npmos_security_event (kind "mtls"): nginx writes them to their own log
// (_npmos_mtls.conf, format npmos_mtls of conf.d/npmos-mtls-log.conf), read here every few seconds.
// The position is the cursor "mtls:denied" in npmos_log_cursor, stored with the rows.
import { createHash } from "node:crypto";
import { open, truncate } from "node:fs/promises";
import { global as logger } from "../../logger.js";
import { emitEvents } from "../events/ingest.js";
import { loadCursors, oldestKeptDay, store } from "../events/store.js";
import { getSetting } from "../settings.js";

export const LOG_FILE = process.env.NPMOS_MTLS_LOG || "/data/nginx/logs/npmos-mtls.log";
const CURSOR = "mtls:denied";
const INTERVAL_MS = 5000;
const MAX_BYTES = 1024 * 1024;
const HEAD_BYTES = 64;
/** the log is emptied when everything is read and it is larger (logrotate may be off) */
const TRUNCATE_BYTES = 10 * 1024 * 1024;

const state = { running: false, timer: null, lastError: null, stored: 0 };

const str = (v, max = 255) => String(v ?? "").slice(0, max);
const hash = (b) => createHash("sha1").update(b).digest("hex");

/**
 * @param {object} line  a line of the log (JSON)
 * @returns {object|null} row of npmos_security_event
 */
export const toEvent = (line, nodeId = "local") => {
	if (!line?.time || !line.ip) return null;
	const time = new Date(line.time);
	if (Number.isNaN(time.getTime())) return null;
	const verify = str(line.verify, 255);
	const missing = verify === "NONE" || verify === "";
	const [uri, query = ""] = str(line.uri, 4096).split(/\?(.*)/s);
	return {
		node_id: nodeId,
		time,
		kind: "mtls",
		name: missing ? "mTLS: no client certificate" : "mTLS: client certificate not accepted",
		severity: "medium",
		priority: "",
		confidence: "",
		action: "denied",
		incident_type: missing ? "mTLS no certificate" : "mTLS certificate",
		source_ip: str(line.ip, 64),
		source_port: null,
		proxy_ip: "",
		source_country: "",
		host: str(line.host).toLowerCase(),
		asset: "",
		method: str(line.method, 16),
		uri: uri.slice(0, 2048),
		query: query.slice(0, 2048),
		response_code: 403,
		location: "",
		parameter: "",
		// SUCCESS here: the certificate is valid, but its issuer or a rule of the host refused it
		sample: str(
			[line.s_dn && `subject: ${line.s_dn}`, line.serial && `serial: ${line.serial}`].filter(Boolean).join("; "),
			2048,
		),
		indicators: "",
		score: null,
		rule: verify,
		practice: "",
		override: "",
		service: "nginx",
		raw: JSON.stringify(line).slice(0, 64 * 1024),
	};
};

/** one round: new lines of the log → events */
export const pollOnce = async ({ file = LOG_FILE, now = new Date() } = {}) => {
	let handle;
	try {
		handle = await open(file, "r");
	} catch {
		return [];
	}
	const events = [];
	try {
		const { size } = await handle.stat();
		const cursor = (await loadCursors()).get(CURSOR);
		const headBuf = Buffer.alloc(Math.min(HEAD_BYTES, size));
		await handle.read(headBuf, 0, headBuf.length, 0);
		// emptied (logrotate copytruncate, or by us) or another file: from the start
		let offset =
			cursor && cursor.offset <= size && cursor.head === hash(headBuf.subarray(0, cursor.headLength))
				? cursor.offset
				: 0;
		if (offset === size) {
			if (size > TRUNCATE_BYTES) {
				await truncate(file, 0);
				await store({
					events: [],
					telemetry: [],
					cursors: [{ key: CURSOR, file, offset: 0, head: hash(Buffer.alloc(0)), head_length: 0 }],
				});
			}
			return [];
		}
		const length = Math.min(MAX_BYTES, size - offset);
		const buf = Buffer.alloc(length);
		await handle.read(buf, 0, length, offset);
		const end = buf.lastIndexOf(0x0a);
		if (end < 0) return [];
		const oldest = oldestKeptDay((await getSetting("events.retention")).days, now);
		for (const text of buf.subarray(0, end).toString("utf8").split("\n")) {
			try {
				const e = toEvent(JSON.parse(text));
				if (e && e.time >= oldest) events.push(e);
			} catch {
				// a broken line
			}
		}
		offset += end + 1;
		await store({
			events,
			telemetry: [],
			cursors: [{ key: CURSOR, file, offset, head: hash(headBuf), head_length: headBuf.length }],
		});
	} finally {
		await handle.close();
	}
	state.stored += events.length;
	emitEvents(events);
	return events;
};

const round = async () => {
	try {
		await pollOnce();
		state.lastError = null;
	} catch (err) {
		if (state.lastError !== err.message) logger.error(`NPMOS mTLS denials: ${err.message}`);
		state.lastError = err.message;
	} finally {
		if (state.running) state.timer = setTimeout(round, INTERVAL_MS);
	}
};

export const startDenials = () => {
	if (state.running) return;
	state.running = true;
	state.timer = setTimeout(round, 1000);
};

export const stopDenials = () => {
	state.running = false;
	clearTimeout(state.timer);
};
