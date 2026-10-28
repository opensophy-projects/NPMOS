// Reads what the open-appsec agent added to its log files since the last time.
// A file is known by its inode (it keeps it when it is renamed) and the hash of its first bytes (an
// inode can be reused by a new file). The agent rotates a log by copying it to "<name>.0.gz" and
// truncating it: what was not read yet is then read from that archive.
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";

const gunzipAsync = promisify(gunzip);

// "cp-nano-http-transaction-handler.log1", with the host name ".logdf9501d82fd4_1", ".1" if renamed
export const LOG_FILE = /^cp-nano-[a-z0-9-]+\.log[a-z0-9_]*(\.\d+)?$/;
const HEAD_BYTES = 128;

const hash = (buffer) => createHash("sha1").update(buffer).digest("hex");

const readAt = async (handle, position, length) => {
	const buffer = Buffer.alloc(length);
	const { bytesRead } = await handle.read(buffer, 0, length, position);
	return buffer.subarray(0, bytesRead);
};

/**
 * The part of a rotated file that was not read: from the newest archive of the file that starts as
 * the file did. Complete lines only (a last line without a newline gets one).
 * @returns {Promise<{file: string, buffer: Buffer} | null>}
 */
const rotatedRest = async (dir, name, cursor) => {
	let archives;
	try {
		archives = (await fs.readdir(dir)).filter((f) => f.startsWith(`${name}.`) && f.endsWith(".gz"));
	} catch {
		return null;
	}
	const dated = await Promise.all(
		archives.map(async (f) => ({ f, mtime: (await fs.stat(path.join(dir, f)).catch(() => null))?.mtimeMs ?? 0 })),
	);
	for (const { f } of dated.sort((a, b) => b.mtime - a.mtime)) {
		let data;
		try {
			data = await gunzipAsync(await fs.readFile(path.join(dir, f)));
		} catch {
			continue;
		}
		if (data.length < cursor.offset || hash(data.subarray(0, cursor.headLength)) !== cursor.head) continue;
		const rest = data.subarray(cursor.offset);
		if (!rest.length) return null;
		return { file: f, buffer: rest.at(-1) === 0x0a ? rest : Buffer.concat([rest, Buffer.from("\n")]) };
	}
	return null;
};

/**
 * @typedef {{key: string, file: string, offset: number, head: string, headLength: number}} Cursor
 * @typedef {{key: string, file: string, start: number, buffer: Buffer, head: string, headLength: number,
 *   rotated?: boolean}} Chunk  rotated: the rest of a rotated file, read completely, no position to keep
 */

/**
 * New data of every log file.
 * @param {string} dir
 * @param {Map<string, Cursor>} cursors  by key
 * @param {number} maxBytes  per file and call; the rest comes next time
 * @returns {Promise<{chunks: Chunk[], keys: string[], available: boolean}>}  keys: files present now
 */
export const scan = async (dir, cursors, maxBytes) => {
	let names;
	try {
		names = (await fs.readdir(dir)).filter((name) => LOG_FILE.test(name));
	} catch {
		return { chunks: [], keys: [], available: false };
	}
	const chunks = [];
	const keys = [];
	for (const name of names.sort()) {
		const file = path.join(dir, name);
		let handle;
		try {
			handle = await fs.open(file, "r");
		} catch {
			continue;
		}
		try {
			const stat = await handle.stat();
			const key = `${stat.dev}:${stat.ino}`;
			keys.push(key);
			const cursor = cursors.get(key);
			let start = 0;
			let head;
			let headLength;
			if (cursor && cursor.offset <= stat.size) {
				const now = await readAt(handle, 0, cursor.headLength);
				if (now.length === cursor.headLength && hash(now) === cursor.head) {
					start = cursor.offset;
					head = cursor.head;
					headLength = cursor.headLength;
				}
			}
			if (head !== undefined && headLength < HEAD_BYTES && stat.size > headLength) {
				// the file was short when it was first read: a longer head tells it apart better
				const first = await readAt(handle, 0, Math.min(HEAD_BYTES, stat.size));
				head = hash(first);
				headLength = first.length;
			}
			if (cursor && head === undefined) {
				const rest = await rotatedRest(dir, name, cursor);
				if (rest)
					chunks.push({ key, file: rest.file, start: cursor.offset, buffer: rest.buffer, rotated: true });
				if (!stat.size) {
					// truncated and still empty: the position moves to its start
					chunks.push({
						key,
						file: name,
						start: 0,
						buffer: Buffer.alloc(0),
						head: hash(Buffer.alloc(0)),
						headLength: 0,
					});
					continue;
				}
			}
			if (!stat.size) continue;
			if (head === undefined) {
				const first = await readAt(handle, 0, Math.min(HEAD_BYTES, stat.size));
				head = hash(first);
				headLength = first.length;
			}
			if (start >= stat.size) {
				if (cursor && headLength !== cursor.headLength) {
					chunks.push({ key, file: name, start, buffer: Buffer.alloc(0), head, headLength });
				}
				continue;
			}
			const buffer = await readAt(handle, start, Math.min(maxBytes, stat.size - start));
			chunks.push({ key, file: name, start, buffer, head, headLength });
		} finally {
			await handle.close();
		}
	}
	return { chunks, keys, available: true };
};
