import assert from "node:assert/strict";
import test from "node:test";
import { attentionAt, DAY, renewWindow } from "./cert-terms.js";

const at = (iso) => new Date(iso).getTime();

test("a short-lived certificate NPMOS renews needs attention only when its renewal is late", () => {
	// 6 days: certbot renews 2 days ahead, attention 1 day before the end
	const c = { notBefore: "2026-11-01T00:00:00Z", notAfter: "2026-11-07T00:00:00Z", auto: true, renewDays: 0 };
	assert.equal(attentionAt(c), at("2026-11-06T00:00:00Z"));
});

test("90 and 47 days renewed by NPMOS: half of the renewal window (30 days, a third of 47)", () => {
	const ninety = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-04-01T00:00:00Z", auto: true, renewDays: 0 };
	assert.equal(attentionAt(ninety), at("2026-04-01T00:00:00Z") - 15 * DAY);
	const fortySeven = {
		notBefore: "2029-04-01T00:00:00Z",
		notAfter: "2029-05-18T00:00:00Z",
		auto: true,
		renewDays: 0,
	};
	assert.equal(attentionAt(fortySeven), at("2029-05-18T00:00:00Z") - (47 * DAY) / 6);
});

test("the renewal days of Settings -> ACME set the window", () => {
	assert.equal(renewWindow(90 * DAY, 10), 10 * DAY);
	const c = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-04-01T00:00:00Z", auto: true, renewDays: 10 };
	assert.equal(attentionAt(c), at("2026-04-01T00:00:00Z") - 5 * DAY);
});

test("a certificate replaced by hand: 14 days, a third of a shorter term", () => {
	const year = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", auto: false };
	assert.equal(attentionAt(year), at("2027-01-01T00:00:00Z") - 14 * DAY);
	const week = { notBefore: "2026-01-01T00:00:00Z", notAfter: "2026-01-07T00:00:00Z", auto: false };
	assert.equal(attentionAt(week), at("2026-01-07T00:00:00Z") - 2 * DAY);
	// without a start: 14 days
	assert.equal(attentionAt({ notAfter: "2027-01-01T00:00:00Z", auto: false }), at("2027-01-01T00:00:00Z") - 14 * DAY);
	assert.equal(attentionAt({ notAfter: null, auto: true }), null);
});
