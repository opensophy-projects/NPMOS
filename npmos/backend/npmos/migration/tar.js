// Reads a tar archive (plain or gzip) and extracts the members a filter accepts. Our own reader: an
// uploaded archive is untrusted, so only regular files and directories are written; links, devices
// and paths with ".." are skipped (the links of certbot live/ are made again from archive/).
import { createReadStream } from "node:fs";
import { mkdir, open } from "node:fs/promises";
import path from "node:path";
import { createGunzip } from "node:zlib";

const BLOCK = 512;

export class TarError extends Error {}

const text = (buf, start, length) => {
	const field = buf.subarray(start, start + length);
	const end = field.indexOf(0);
	return field.subarray(0, end < 0 ? field.length : end).toString("utf8");
};

const octal = (buf, start, length) => {
	// base-256 (GNU) for sizes over 8 GB
	if (buf[start] & 0x80) {
		let n = 0;
		for (let i = start + 1; i < start + length; i++) n = n * 256 + buf[i];
		return n;
	}
	const v = text(buf, start, length).trim();
	return v ? Number.parseInt(v, 8) : 0;
};

/** pax extended header: "<len> key=value\n" records */
const pax = (buf) => {
	const out = {};
	let pos = 0;
	while (pos < buf.length) {
		const space = buf.indexOf(0x20, pos);
		if (space < 0) break;
		const len = Number.parseInt(buf.subarray(pos, space).toString("utf8"), 10);
		if (!len) break;
		const record = buf.subarray(space + 1, pos + len - 1).toString("utf8");
		const eq = record.indexOf("=");
		if (eq > 0) out[record.slice(0, eq)] = record.slice(eq + 1);
		pos += len;
	}
	return out;
};

/**
 * A relative path inside the archive, or null when it is not safe ("..", absolute, empty).
 * "./data/x" → "data/x".
 */
export const cleanPath = (name) => {
	const parts = [];
	for (const part of String(name).replaceAll("\\", "/").split("/")) {
		if (part === "" || part === ".") continue;
		if (part === "..") return null;
		parts.push(part);
	}
	return parts.length ? parts.join("/") : null;
};

/** magic bytes → "gzip" | "tar" | "sqlite" | null */
export const sniff = (head) => {
	if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) return "gzip";
	if (head.length >= 16 && head.subarray(0, 16).toString("latin1") === "SQLite format 3\0") return "sqlite";
	if (head.length >= 262 && head.subarray(257, 262).toString("latin1") === "ustar") return "tar";
	return null;
};

/**
 * Extracts `file` into `dest`.
 * @param {string} file
 * @param {string} dest  an existing empty directory
 * @param {{gzip: boolean, accept: (rel: string) => boolean, maxBytes: number, maxEntries: number}} options
 * @returns {Promise<{files: number, bytes: number, skipped: number}>}
 */
export const extract = async (file, dest, { gzip, accept, maxBytes, maxEntries }) => {
	const input = createReadStream(file);
	const stream = gzip ? input.pipe(createGunzip()) : input;
	input.on("error", (err) => stream.destroy(err));

	let buffer = Buffer.alloc(0);
	let entry = null; // {rel, size, remaining, handle, padding}
	let longName = null;
	let paxHeader = {};
	let meta = null; // collecting the body of an L/K/x header: {kind, size, chunks}
	const result = { files: 0, bytes: 0, skipped: 0 };
	let entries = 0;
	let ended = false;

	const startEntry = async (header) => {
		const type = String.fromCharCode(header[156] || 0x30);
		const size = octal(header, 124, 12);
		const prefix = text(header, 345, 155);
		const name =
			longName ?? paxHeader.path ?? (prefix ? `${prefix}/${text(header, 0, 100)}` : text(header, 0, 100));
		const paxSize = paxHeader.size ? Number.parseInt(paxHeader.size, 10) : null;
		longName = null;
		paxHeader = {};
		const bodySize = paxSize ?? size;

		if (type === "L" || type === "K" || type === "x" || type === "g") {
			if (bodySize > 1024 * 1024) throw new TarError("Extended header is too large");
			meta = { kind: type, remaining: bodySize, padding: (BLOCK - (bodySize % BLOCK)) % BLOCK, chunks: [] };
			return;
		}

		entries += 1;
		if (entries > maxEntries) throw new TarError(`The archive has more than ${maxEntries} entries`);
		const rel = cleanPath(name);
		const padding = (BLOCK - (bodySize % BLOCK)) % BLOCK;
		const wanted = rel && accept(rel);
		const target = wanted ? path.join(dest, rel) : null;

		if (wanted && type === "5") {
			await mkdir(target, { recursive: true });
		} else if (wanted && (type === "0" || type === "7")) {
			if (result.bytes + bodySize > maxBytes) throw new TarError("The extracted files are too large");
			await mkdir(path.dirname(target), { recursive: true });
			// "wx": never through an existing symlink or over a file
			const handle = await open(target, "wx", 0o600).catch(() => null);
			if (handle) {
				result.files += 1;
				result.bytes += bodySize;
			} else {
				result.skipped += 1;
			}
			entry = { remaining: bodySize, padding, handle };
			return;
		} else {
			result.skipped += 1;
		}
		entry = { remaining: bodySize, padding, handle: null };
	};

	const finishMeta = () => {
		const body = Buffer.concat(meta.chunks);
		if (meta.kind === "L") longName = text(body, 0, body.length);
		else if (meta.kind === "x") paxHeader = pax(body);
		meta = null;
	};

	const consume = async () => {
		while (!ended) {
			if (meta) {
				if (meta.remaining > 0) {
					if (!buffer.length) return;
					const n = Math.min(meta.remaining, buffer.length);
					meta.chunks.push(buffer.subarray(0, n));
					buffer = buffer.subarray(n);
					meta.remaining -= n;
					continue;
				}
				if (buffer.length < meta.padding) return;
				buffer = buffer.subarray(meta.padding);
				finishMeta();
				continue;
			}
			if (entry) {
				if (entry.remaining > 0) {
					if (!buffer.length) return;
					const n = Math.min(entry.remaining, buffer.length);
					if (entry.handle) await entry.handle.write(buffer.subarray(0, n));
					buffer = buffer.subarray(n);
					entry.remaining -= n;
					continue;
				}
				if (buffer.length < entry.padding) return;
				buffer = buffer.subarray(entry.padding);
				if (entry.handle) await entry.handle.close();
				entry = null;
				continue;
			}
			if (buffer.length < BLOCK) return;
			const header = buffer.subarray(0, BLOCK);
			buffer = buffer.subarray(BLOCK);
			if (header.every((b) => b === 0)) {
				ended = true;
				return;
			}
			if (header.subarray(257, 262).toString("latin1") !== "ustar" && entries === 0 && !meta) {
				throw new TarError("Not a tar archive");
			}
			await startEntry(header);
		}
	};

	try {
		for await (const chunk of stream) {
			buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
			await consume();
			if (ended) break;
		}
	} catch (err) {
		if (entry?.handle) await entry.handle.close().catch(() => {});
		input.destroy();
		if (err instanceof TarError) throw err;
		throw new TarError(`The archive could not be read: ${err.message}`);
	}
	input.destroy();
	if (entry?.handle) await entry.handle.close().catch(() => {});
	if (!ended && (entry || meta)) throw new TarError("The archive is truncated");
	return result;
};
