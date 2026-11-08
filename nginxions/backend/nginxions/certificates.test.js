import assert from "node:assert/strict";
import { test } from "node:test";
import { filterRows, parseQuery, sortRows } from "./certificates.js";

const rows = [
	{
		key: "tls:1",
		source: "tls",
		kind: "letsencrypt",
		name: "shop",
		subjects: ["shop.example.com"],
		issuer: "",
		status: "valid",
		not_after: "2027-01-01T00:00:00Z",
		created_on: "2026-01-01T00:00:00Z",
		used_by: [{ name: "shop.example.com" }],
	},
	{
		key: "pki:2",
		source: "pki",
		kind: "client",
		name: "alice",
		subjects: [],
		issuer: "Office",
		status: "expiring",
		not_after: "2026-11-05T00:00:00Z",
		created_on: "2026-02-01T00:00:00Z",
		used_by: [],
	},
	{
		key: "file:/x",
		source: "file",
		kind: "file",
		name: "old",
		subjects: [],
		issuer: "",
		status: "expired",
		not_after: "2025-01-01T00:00:00Z",
		created_on: null,
		used_by: [],
		path: "/data/tls/custom/old.pem",
	},
];

test("certificates: query defaults and unknown values", () => {
	const f = parseQuery({ source: "tls,nope", status: "expired", used: "maybe", sort: "x" });
	assert.deepEqual(f.source, ["tls"]);
	assert.deepEqual(f.status, ["expired"]);
	assert.equal(f.used, "");
	assert.equal(f.sort, "expires");
});

test("certificates: filters by source, status, use and text (path, issuer, hosts)", () => {
	const keys = (q) => filterRows(rows, parseQuery(q)).map((r) => r.key);
	assert.deepEqual(keys({ source: "pki,file" }), ["pki:2", "file:/x"]);
	assert.deepEqual(keys({ status: "expiring,expired" }), ["pki:2", "file:/x"]);
	assert.deepEqual(keys({ used: "yes" }), ["tls:1"]);
	assert.deepEqual(keys({ q: "OFFICE" }), ["pki:2"]);
	assert.deepEqual(keys({ q: "custom/old" }), ["file:/x"]);
	assert.deepEqual(keys({ q: "shop.example" }), ["tls:1"]);
});

test("certificates: the soonest expiry first by default, newest created with -created", () => {
	assert.deepEqual(
		sortRows(rows, "expires").map((r) => r.key),
		["file:/x", "pki:2", "tls:1"],
	);
	assert.deepEqual(
		sortRows(rows, "-expires").map((r) => r.key),
		["tls:1", "pki:2", "file:/x"],
	);
	assert.deepEqual(
		sortRows(rows, "-created").map((r) => r.key),
		["pki:2", "tls:1", "file:/x"],
	);
});
