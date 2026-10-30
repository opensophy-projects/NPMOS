// Ingest of the open-appsec agent's security log (docs/ROADMAP.md, phase 4): every few seconds the
// new lines of the agent's log files (volume appsec-logs, read-only at /ext/appsec-logs) become rows
// of npmos_security_event and the hourly aggregates. Positions are kept in npmos_log_cursor in the
// same transaction as the rows, so a restart neither loses nor doubles events; the first start
// imports what the files already hold (up to the retention).
import { global as logger } from "../../logger.js";
import { getSetting } from "../settings.js";
import { classify, parseChunk } from "./normalize.js";
import { applyRetention, dropCursors, ensureCurrentPartitions, loadCursors, oldestKeptDay, store } from "./store.js";
import { scan } from "./tail.js";
import { startRequests, stopRequests } from "./requests.js";

const LOG_DIR = process.env.NPMOS_APPSEC_LOG_DIR || "/ext/appsec-logs";
const INTERVAL_MS = 2000;
/** bytes read per file and round; a backlog is read over several rounds */
const MAX_BYTES = 4 * 1024 * 1024;
const MAINTENANCE_MS = 60 * 60 * 1000;

const state = {
	running: false,
	timer: null,
	lastRun: null,
	lastError: null,
	lastMaintenance: 0,
	available: false,
	/** events stored since the start of the process */
	stored: 0,
	/** listeners of new events (notifications) */
	listeners: new Set(),
};

/**
 * One round: read, normalize, store.
 * @param {{dir?: string, now?: Date}} [options]
 * @returns {Promise<{events: object[], telemetry: number}>}
 */
export const ingestOnce = async ({ dir = LOG_DIR, now = new Date() } = {}) => {
	const retention = await getSetting("events.retention");
	const oldest = oldestKeptDay(retention.days, now);
	const cursors = await loadCursors();
	const { chunks, keys, available } = await scan(dir, cursors, MAX_BYTES);
	state.available = available;

	const events = [];
	const telemetry = [];
	const updates = [];
	for (const chunk of chunks) {
		let { lines, consumed } = parseChunk(chunk.buffer);
		// a line longer than a whole read is skipped, not waited for
		if (!consumed && chunk.buffer.length >= MAX_BYTES) consumed = chunk.buffer.length;
		for (const line of lines) {
			const item = classify(line);
			if (!item) continue;
			if (item.type === "telemetry") telemetry.push(item.row);
			else if (item.row.time >= oldest) events.push(item.row);
		}
		// the rest of a rotated file: its position is the one of the file it was rotated from
		if (chunk.rotated) continue;
		updates.push({
			key: chunk.key,
			file: chunk.file,
			offset: chunk.start + consumed,
			head: chunk.head,
			head_length: chunk.headLength,
		});
	}
	if (updates.length) {
		await store({ events, telemetry, cursors: updates });
		state.stored += events.length;
	}
	if (available) {
		// other sources keep their position here too (crowdsec:alerts, mtls:denied)
		await dropCursors([...cursors.keys()].filter((key) => !keys.includes(key) && !/^(crowdsec|mtls):/.test(key)));
	}
	return { events, telemetry: telemetry.length };
};

const maintenance = async (now = new Date()) => {
	await ensureCurrentPartitions(now);
	const result = await applyRetention(await getSetting("events.retention"), now);
	if (result.partitions.length || result.events || result.aggregates) {
		logger.info(
			`NPMOS events: retention removed ${result.partitions.length} day(s), ${result.events} event(s), ${result.aggregates} aggregate row(s)`,
		);
	}
};

const round = async () => {
	try {
		if (Date.now() - state.lastMaintenance >= MAINTENANCE_MS) {
			await maintenance();
			state.lastMaintenance = Date.now();
		}
		const { events } = await ingestOnce();
		state.lastRun = new Date();
		state.lastError = null;
		emitEvents(events);
	} catch (err) {
		if (state.lastError !== err.message) logger.error(`NPMOS events: ${err.message}`);
		state.lastError = err.message;
	} finally {
		if (state.running) state.timer = setTimeout(round, INTERVAL_MS);
	}
};

/** starts the ingest (never fails the start of the backend) */
export const start = () => {
	if (state.running) return;
	state.running = true;
	state.timer = setTimeout(round, 0);
	logger.info(`NPMOS events: reading the agent's security log in ${LOG_DIR}`);
	// requests of the hosts from the access log of nginx (Analytics)
	startRequests();
};

export const stop = () => {
	state.running = false;
	clearTimeout(state.timer);
	stopRequests();
};

/** retention changed in the GUI: applied now */
export const runMaintenance = async () => {
	await maintenance();
	state.lastMaintenance = Date.now();
};

/** new events stored by another source (CrowdSec alerts) */
export const emitEvents = (events) => {
	if (!events.length) return;
	for (const listener of state.listeners) {
		try {
			listener(events);
		} catch (err) {
			logger.error(`NPMOS events: listener failed: ${err.message}`);
		}
	}
};

/** @param {(events: object[]) => void} listener */
export const onEvents = (listener) => {
	state.listeners.add(listener);
	return () => state.listeners.delete(listener);
};

export const status = () => ({
	running: state.running,
	available: state.available,
	lastRun: state.lastRun,
	lastError: state.lastError,
	stored: state.stored,
});
