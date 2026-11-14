// A log of nginx with one JSON object a line (refusals of mTLS, findings of File Security...) → security events, read
// every few seconds. The position is a cursor of nginxions_log_cursor, stored with the rows; a log emptied or rotated
// (its first bytes differ) is read from the start, a log read to its end and larger than 10 MB is emptied.
import { createHash } from "node:crypto";
import { open, truncate } from "node:fs/promises";
import { global as logger } from "../../logger.js";
import { getSetting } from "../settings.js";
import { loadCursors, oldestKeptDay, store } from "./store.js";

const MAX_BYTES = 1024 * 1024;
const HEAD_BYTES = 64;
const TRUNCATE_BYTES = 10 * 1024 * 1024;

// nosemgrep: nginxions-weak-hash -- recognizes a rotated log by its first bytes (a cursor stored in the database), not a secret
const hash = (b) => createHash("sha1").update(b).digest("hex");

/**
 * One round: the new lines of the log → events.
 * @param {{file: string, cursor: string, toEvent: (line: object) => object|null, now?: Date}} options
 * @returns {Promise<object[]>} the events stored
 */
export const pollJsonLog = async ({ file, cursor: key, toEvent, now = new Date() }) => {
	let handle;
	try {
		handle = await open(file, "r");
	} catch {
		return [];
	}
	const events = [];
	try {
		const { size } = await handle.stat();
		const cursor = (await loadCursors()).get(key);
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
					cursors: [{ key, file, offset: 0, head: hash(Buffer.alloc(0)), head_length: 0 }],
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
			cursors: [{ key, file, offset, head: hash(headBuf), head_length: headBuf.length }],
		});
	} finally {
		await handle.close();
	}
	return events;
};

/**
 * Reads the log every few seconds from now on.
 * @param {{file: string, cursor: string, toEvent: Function, name: string, intervalMs?: number}} options
 */
export const startJsonLog = ({ name, intervalMs = 5000, ...options }) => {
	const state = { lastError: null };
	const round = async () => {
		try {
			await pollJsonLog(options);
			state.lastError = null;
		} catch (err) {
			if (state.lastError !== err.message) logger.error(`NginxionS ${name}: ${err.message}`);
			state.lastError = err.message;
		} finally {
			setTimeout(round, intervalMs).unref?.();
		}
	};
	setTimeout(round, 1000).unref?.();
	return state;
};
