import assert from "node:assert/strict";
import { test } from "node:test";
import { PERIODS, parseFilters } from "./index.js";

test("audit filters: no period means the whole log", () => {
	const f = parseFilters({});
	assert.equal(f.from, null);
	assert.equal(f.to, null);
	assert.deepEqual(f.action, []);
});

test("audit filters: period, lists, text", () => {
	const now = new Date("2026-10-30T12:00:00Z");
	const f = parseFilters({ period: "7d", action: "created, deleted", object: "pki", user: "1,2", q: " ca " }, now);
	assert.equal(f.from.getTime(), now.getTime() - PERIODS["7d"]);
	assert.deepEqual(f.action, ["created", "deleted"]);
	assert.deepEqual(f.object, ["pki"]);
	assert.deepEqual(f.user, [1, 2]);
	assert.equal(f.q, "ca");
});

test("audit filters: bad values are refused", () => {
	assert.throws(() => parseFilters({ user: "x" }));
	assert.throws(() => parseFilters({ from: "2026-10-30", to: "2026-10-01" }));
	assert.throws(() => parseFilters({ from: "not a date" }));
});
