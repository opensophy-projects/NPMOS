import assert from "node:assert/strict";
import { test } from "node:test";
import { MmdbError, Reader } from "./mmdb.js";

// a minimal writer of the format: maps, strings, unsigned integers, arrays
const ctrl = (type, size) => {
	const head = type <= 7 ? [(type << 5) | Math.min(size, 29)] : [Math.min(size, 29), type - 7];
	if (size < 29) return Buffer.from(head);
	return Buffer.from([...head, size - 29]);
};
const encode = (v) => {
	if (typeof v === "string") {
		const b = Buffer.from(v);
		return Buffer.concat([ctrl(2, b.length), b]);
	}
	if (typeof v === "number") {
		const b = Buffer.alloc(4);
		b.writeUInt32BE(v);
		return Buffer.concat([ctrl(6, 4), b]);
	}
	if (Array.isArray(v)) return Buffer.concat([ctrl(11, v.length), ...v.map(encode)]);
	const entries = Object.entries(v);
	return Buffer.concat([ctrl(7, entries.length), ...entries.flatMap(([k, x]) => [encode(k), encode(x)])]);
};

/** IPv4 tree, 24-bit records; networks: [[a.b.c.d, prefix, record]] */
const build = (networks, ipVersion = 4) => {
	const nodes = [[null, null]];
	const data = [];
	const offsets = [];
	let size = 0;
	for (const [, , record] of networks) {
		const b = encode(record);
		offsets.push(size);
		data.push(b);
		size += b.length;
	}
	const pending = [];
	networks.forEach(([ip, prefix], n) => {
		let bits = ip
			.split(".")
			.map(Number)
			.flatMap((x) => [7, 6, 5, 4, 3, 2, 1, 0].map((i) => (x >> i) & 1));
		if (ipVersion === 6) bits = [...Array(96).fill(0), ...bits];
		const len = ipVersion === 6 ? prefix + 96 : prefix;
		let node = 0;
		for (let i = 0; i < len - 1; i++) {
			if (nodes[node][bits[i]] === null) {
				nodes.push([null, null]);
				nodes[node][bits[i]] = nodes.length - 1;
			}
			node = nodes[node][bits[i]];
		}
		pending.push([node, bits[len - 1], n]);
	});
	const count = nodes.length;
	for (const [node, bit, n] of pending) nodes[node][bit] = { data: offsets[n] };
	const tree = Buffer.alloc(count * 6);
	for (const [i, pair] of nodes.entries()) {
		for (const [bit, r] of pair.entries()) {
			const value = r === null ? count : typeof r === "number" ? r : count + 16 + r.data;
			tree.writeUIntBE(value, i * 6 + bit * 3, 3);
		}
	}
	const meta = encode({
		binary_format_major_version: 2,
		binary_format_minor_version: 0,
		node_count: count,
		record_size: 24,
		ip_version: ipVersion,
		database_type: "Test-Country",
		languages: ["en"],
		build_epoch: 1760000000,
	});
	return Buffer.concat([tree, Buffer.alloc(16), ...data, Buffer.from("\xab\xcd\xefMaxMind.com", "latin1"), meta]);
};

const NETWORKS = [
	["1.2.3.0", 24, { country: { iso_code: "AU", names: { en: "Australia", ru: "Австралия" } } }],
	["77.88.0.0", 16, { country: { iso_code: "RU", names: { en: "Russia" } } }],
];

test("mmdb: countries of IPv4 addresses, unknown ones are null", () => {
	const r = new Reader(build(NETWORKS));
	assert.equal(r.metadata.database_type, "Test-Country");
	assert.equal(r.get("1.2.3.4").country.names.en, "Australia");
	assert.equal(r.get("1.2.3.4").country.names.ru, "Австралия");
	assert.equal(r.get("77.88.8.8").country.iso_code, "RU");
	assert.equal(r.get("1.2.4.1"), null);
	assert.equal(r.get("10.0.0.1"), null);
	assert.equal(r.get("not an ip"), null);
	assert.equal(r.get("2001:db8::1"), null);
});

test("mmdb: IPv4 addresses in an IPv6 tree, mapped addresses", () => {
	const r = new Reader(build(NETWORKS, 6));
	assert.equal(r.get("77.88.1.1").country.iso_code, "RU");
	assert.equal(r.get("::1.2.3.9").country.iso_code, "AU");
	assert.equal(r.get("::1"), null);
});

test("mmdb: a file that is not a database is refused", () => {
	assert.throws(() => new Reader(Buffer.from("hello")), MmdbError);
});
