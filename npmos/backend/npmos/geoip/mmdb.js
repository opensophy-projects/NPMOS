// Reader of MaxMind DB files (.mmdb: GeoLite2, DB-IP lite and others in that format), enough for
// country lookups. Format: https://maxmind.github.io/MaxMind-DB/ — a binary search tree over the
// bits of the address, then a data section of typed values.
import net from "node:net";

const METADATA_MARKER = Buffer.from("\xab\xcd\xefMaxMind.com", "latin1");
const DATA_SEPARATOR = 16;

export class MmdbError extends Error {}

/** decoder of the data section format, positions relative to `base` */
class Decoder {
	constructor(buf, base) {
		this.buf = buf;
		this.base = base;
	}

	/** @returns {[value, next offset]} */
	decode(start) {
		const buf = this.buf;
		let offset = start;
		const ctrl = buf[this.base + offset++];
		let type = ctrl >> 5;
		if (type === 1) {
			const [pointer, next] = this.pointer(ctrl, offset);
			return [this.decode(pointer)[0], next];
		}
		if (type === 0) type = 7 + buf[this.base + offset++];
		let size = ctrl & 0x1f;
		if (size >= 29) {
			const n = size - 28;
			let extra = 0;
			for (let i = 0; i < n; i++) extra = extra * 256 + buf[this.base + offset + i];
			offset += n;
			size = [0, 29, 285, 65821][n] + extra;
		}
		const at = this.base + offset;
		switch (type) {
			case 2:
				return [buf.toString("utf8", at, at + size), offset + size];
			case 3:
				return [buf.readDoubleBE(at), offset + 8];
			case 4:
				return [buf.subarray(at, at + size), offset + size];
			case 5:
			case 6:
			case 9:
			case 10: {
				let v = 0n;
				for (let i = 0; i < size; i++) v = (v << 8n) | BigInt(buf[at + i]);
				return [v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v, offset + size];
			}
			case 7: {
				const map = {};
				for (let i = 0; i < size; i++) {
					const [key, afterKey] = this.decode(offset);
					const [value, afterValue] = this.decode(afterKey);
					map[key] = value;
					offset = afterValue;
				}
				return [map, offset];
			}
			case 8: {
				let v = 0;
				for (let i = 0; i < size; i++) v = v * 256 + buf[at + i];
				return [size === 4 ? v | 0 : v, offset + size];
			}
			case 11: {
				const list = [];
				for (let i = 0; i < size; i++) {
					const [value, next] = this.decode(offset);
					list.push(value);
					offset = next;
				}
				return [list, offset];
			}
			case 14:
				return [size !== 0, offset];
			case 15:
				return [buf.readFloatBE(at), offset + 4];
			default:
				throw new MmdbError(`unknown data type ${type}`);
		}
	}

	pointer(ctrl, offset) {
		const buf = this.buf;
		const at = this.base + offset;
		const ss = (ctrl >> 3) & 3;
		const vvv = ctrl & 7;
		if (ss === 0) return [(vvv << 8) | buf[at], offset + 1];
		if (ss === 1) return [((vvv << 16) | (buf[at] << 8) | buf[at + 1]) + 2048, offset + 2];
		if (ss === 2) return [vvv * 0x1000000 + buf.readUIntBE(at, 3) + 526336, offset + 3];
		return [buf.readUInt32BE(at), offset + 4];
	}
}

/** address → array of bits as bytes (4 or 16) */
const addressBytes = (ip) => {
	const v = net.isIP(ip);
	if (v === 4) return Buffer.from(ip.split(".").map(Number));
	if (v !== 6) return null;
	let [head, tail = ""] = ip.split("::");
	if (!ip.includes("::")) tail = null;
	const part = (s) => (s ? s.split(":") : []);
	let groups = part(head);
	let tailGroups = tail === null ? [] : part(tail);
	// ::ffff:1.2.3.4
	const last = (tail === null ? groups : tailGroups).at(-1);
	if (last?.includes(".")) {
		const b = last.split(".").map(Number);
		const replace = [((b[0] << 8) | b[1]).toString(16), ((b[2] << 8) | b[3]).toString(16)];
		if (tail === null) groups = [...groups.slice(0, -1), ...replace];
		else tailGroups = [...tailGroups.slice(0, -1), ...replace];
	}
	const zeros = tail === null ? [] : Array(8 - groups.length - tailGroups.length).fill("0");
	const all = [...groups, ...zeros, ...tailGroups];
	const out = Buffer.alloc(16);
	for (const [i, g] of all.entries()) out.writeUInt16BE(Number.parseInt(g, 16), i * 2);
	return out;
};

export class Reader {
	/** @param {Buffer} buf  the whole .mmdb file */
	constructor(buf) {
		const at = buf.lastIndexOf(METADATA_MARKER);
		if (at < 0) throw new MmdbError("not a MaxMind DB file (no metadata)");
		const meta = new Decoder(buf, at + METADATA_MARKER.length).decode(0)[0];
		if (meta?.binary_format_major_version !== 2) throw new MmdbError("unsupported MaxMind DB version");
		if (![24, 28, 32].includes(meta.record_size))
			throw new MmdbError(`unsupported record size ${meta.record_size}`);
		this.buf = buf;
		this.metadata = meta;
		this.nodeCount = meta.node_count;
		this.recordSize = meta.record_size;
		this.nodeBytes = (meta.record_size * 2) / 8;
		const treeSize = this.nodeBytes * this.nodeCount;
		if (treeSize + DATA_SEPARATOR > at) throw new MmdbError("the search tree is larger than the file");
		this.decoder = new Decoder(buf, treeSize + DATA_SEPARATOR);
		this.cache = new Map();
		this.ipv4Start = 0;
		if (meta.ip_version === 6) {
			let node = 0;
			for (let i = 0; i < 96 && node < this.nodeCount; i++) node = this.record(node, 0);
			this.ipv4Start = node;
		}
	}

	record(node, bit) {
		const b = this.buf;
		const at = node * this.nodeBytes;
		if (this.recordSize === 24) return b.readUIntBE(at + bit * 3, 3);
		if (this.recordSize === 32) return b.readUInt32BE(at + bit * 4);
		// 28: the middle byte holds the high nibbles of both records
		const middle = b[at + 3];
		return bit === 0
			? ((middle & 0xf0) << 20) | b.readUIntBE(at, 3)
			: ((middle & 0x0f) << 24) | b.readUIntBE(at + 4, 3);
	}

	/** @returns {object|null} the data record of the address */
	get(ip) {
		const bytes = addressBytes(ip);
		if (!bytes) return null;
		if (bytes.length === 16 && this.metadata.ip_version === 4) return null;
		let node = bytes.length === 4 ? this.ipv4Start : 0;
		const bits = bytes.length * 8;
		for (let i = 0; i < bits && node < this.nodeCount; i++) {
			node = this.record(node, (bytes[i >> 3] >> (7 - (i & 7))) & 1);
		}
		if (node <= this.nodeCount) return null;
		// many networks share one record: decoded records are kept by their position
		const offset = node - this.nodeCount - DATA_SEPARATOR;
		let value = this.cache.get(offset);
		if (value === undefined) {
			value = this.decoder.decode(offset)[0];
			if (this.cache.size >= 20000) this.cache.clear();
			this.cache.set(offset, value);
		}
		return value;
	}
}
