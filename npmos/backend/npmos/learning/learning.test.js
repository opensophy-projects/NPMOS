import assert from "node:assert/strict";
import { test } from "node:test";
import {
	assetsOf,
	checkLabel,
	decisionEntries,
	defaultScopes,
	enforcedIds,
	exceptionActive,
	exceptionOf,
	groupKey,
	groupsOf,
	hostStats,
	mergeDecisions,
	reasonOf,
	ruleHost,
	statsOf,
	suggestionOf,
} from "./model.js";

test("rule names of proxy hosts and their locations", () => {
	assert.deepEqual(ruleHost("npm-managed-specific-rule-proxyhost-7"), { hostId: 7, location: null });
	assert.deepEqual(ruleHost("npm-managed-specific-rule-proxyhost-7.2"), { hostId: 7, location: null });
	assert.deepEqual(ruleHost("npm-managed-specific-rule-proxyhost-7-1"), { hostId: 7, location: 1 });
	assert.deepEqual(ruleHost("npm-managed-specific-rule-proxyhost-7-1.3"), { hostId: 7, location: 1 });
	assert.equal(ruleHost("default"), null);
	assert.equal(ruleHost(""), null);
});

const row = (extra = {}) => ({
	rule: "npm-managed-specific-rule-proxyhost-3",
	uri: "/search",
	parameter: "q",
	indicators: "select,union",
	events: 4,
	sources: 2,
	score: 4.5,
	blocked: 0,
	first: "2026-10-29T10:00:00Z",
	last: "2026-10-29T12:00:00Z",
	host: "shop.example",
	incident_type: "SQL Injection",
	sample: "1 union select",
	event_id: 10,
	...extra,
});

test("groups: the domains of a host are merged, labelled groups are left out, blocked first", () => {
	const now = new Date("2026-10-30T00:00:00Z");
	const rows = [
		row(),
		row({
			rule: "npm-managed-specific-rule-proxyhost-3.1",
			events: 2,
			score: 5.5,
			last: "2026-10-29T13:00:00Z",
			event_id: 12,
		}),
		row({ uri: "/login", parameter: "user", blocked: 1, score: 7, events: 1 }),
		row({ uri: "/other", score: 8 }),
		row({ rule: "something-else" }),
	];
	const groups = groupsOf(rows, new Set(), now);
	assert.equal(groups.length, 3);
	assert.equal(groups[0].reason, "blocked");
	assert.equal(groups[0].uri, "/login");
	const search = groups.find((g) => g.uri === "/search");
	assert.equal(search.events, 6);
	assert.equal(search.score, 5.5);
	assert.equal(search.reason, "grey");
	assert.equal(search.eventId, 12);
	assert.equal(search.last, "2026-10-29T13:00:00.000Z");
	assert.equal(search.new, true);
	assert.equal(groups.find((g) => g.uri === "/other").reason, "detected");

	const labelled = new Set([search.key]);
	assert.equal(groupsOf(rows, labelled, now).length, 2);
	assert.equal(search.key, groupKey({ hostId: 3, uri: "/search", parameter: "q", indicators: "select,union" }));
});

test("reasons", () => {
	assert.equal(reasonOf({ blocked: 2, score: 1 }), "blocked");
	assert.equal(reasonOf({ blocked: 0, score: 3 }), "grey");
	assert.equal(reasonOf({ blocked: 0, score: 6 }), "detected");
	assert.equal(reasonOf({ blocked: 0, score: null }), "detected");
});

test("default scopes: the parameter if there is one, else the URL", () => {
	assert.deepEqual(defaultScopes({ uri: "/a", parameter: "q", sample: "x" }), [
		{ type: "parameterValue", value: "x" },
		{ type: "parameterName", value: "q" },
	]);
	assert.deepEqual(defaultScopes({ uri: "/a", parameter: "", sample: "" }), [{ type: "url", value: "/a" }]);
});

test("labels are checked", () => {
	assert.ok(checkLabel({ decision: "maybe" }).errors);
	assert.ok(checkLabel({ decision: "benign", scopes: [] }).errors);
	assert.ok(checkLabel({ decision: "benign", scopes: [{ type: "source", value: "not an ip" }] }).errors);
	assert.ok(checkLabel({ decision: "malicious", scopes: [{ type: "url", value: "/a" }], ban: true }).errors);
	assert.ok(
		checkLabel({ decision: "benign", scopes: [{ type: "url", value: "/a" }], exception: true, ttl_days: 400 })
			.errors,
	);

	const dismiss = checkLabel({ decision: "dismiss", exception: true });
	assert.equal(dismiss.exception, false);
	assert.deepEqual(dismiss.scopes, []);

	const benign = checkLabel({
		decision: "benign",
		scopes: [
			{ type: "url", value: "/a" },
			{ type: "url", value: "/a" },
			{ type: "source", value: "10.0.0.0/8" },
		],
		exception: true,
		ttl_days: 7,
		ban: true,
	});
	assert.equal(benign.scopes.length, 2);
	assert.equal(benign.ttlDays, 7);
	assert.equal(benign.ban, false);

	const malicious = checkLabel({
		decision: "malicious",
		scopes: [{ type: "source", value: "203.0.113.7" }],
		exception: true,
		ban: true,
		ban_duration: "4h",
	});
	assert.equal(malicious.ttlDays, 0);
	assert.equal(malicious.ban, true);
	assert.equal(malicious.banDuration, "4h");
});

const labels = [
	{
		id: 1,
		decision: "benign",
		scopes: [
			{ type: "parameterValue", value: "a b" },
			{ type: "parameterName", value: "q" },
		],
	},
	{ id: 2, decision: "dismiss", scopes: [] },
	{ id: 3, decision: "malicious", scopes: [{ type: "source", value: "203.0.113.7" }] },
];

test("decisions.data: entries of NPMOS replace their own, others stay, enforced marks are kept", () => {
	const ours = decisionEntries(labels);
	assert.deepEqual(
		ours.map((d) => [d.id, d.decision, d.eventType, d.eventTitle]),
		[
			["npmos-1-0", "benign", "parameterValue", "a b"],
			["npmos-1-1", "benign", "parameterName", "q"],
			["npmos-3-0", "malicious", "source", "203.0.113.7"],
		],
	);
	const current = {
		decisions: [
			{ id: "tuning-1", decision: "benign", eventType: "url", eventTitle: "/x", enforced: true },
			{ id: "tuning-2", decision: "benign", eventType: "parameterName", eventTitle: "q", enforced: true },
			{ id: "npmos-1-0", decision: "benign", eventType: "parameterValue", eventTitle: "a b", enforced: true },
			{ id: "npmos-9-0", decision: "benign", eventType: "url", eventTitle: "/undone" },
		],
	};
	const merged = mergeDecisions(current, ours);
	assert.deepEqual(
		merged.decisions.map((d) => [d.id, d.enforced]),
		[
			["tuning-1", true],
			["npmos-1-0", true],
			["npmos-1-1", false],
			["npmos-3-0", false],
		],
	);
	assert.deepEqual([...enforcedIds(current)], ["npmos-1-0"]);
	assert.deepEqual(mergeDecisions(null, []), { decisions: [] });
});

test("exceptions of labels", () => {
	assert.deepEqual(exceptionOf({ ...labels[0], decision: "benign" }), {
		name: "npmos-learn-1",
		action: "accept",
		condition: [
			{ key: "paramValue", value: "a b" },
			{ key: "paramName", value: "q" },
		],
	});
	assert.equal(exceptionOf(labels[2]).action, "drop");
	const now = new Date("2026-10-30T00:00:00Z");
	assert.equal(exceptionActive({ exception: true, expires_on: "2026-11-01T00:00:00Z" }, now), true);
	assert.equal(exceptionActive({ exception: true, expires_on: "2026-10-29T00:00:00Z" }, now), false);
	assert.equal(exceptionActive({ exception: true, expires_on: null, undone_on: now }, now), false);
	assert.equal(exceptionActive({ exception: false }, now), false);
});

test("assets, statistics and suggestions of the tuning service", () => {
	assert.deepEqual(assetsOf(["a.example", "b.example"], ["/api"]), [
		"a.example",
		"b.example",
		"a.example/api",
		"b.example/api",
	]);
	const s = statsOf({ statistics: { status: "ready", readiness: 4, recommendation: 5, totalRequests: 120000 } });
	assert.equal(s.readiness, "graduate");
	assert.equal(s.recommendation, "prevent_high");
	assert.equal(s.ready, true);
	assert.equal(statsOf({}).readiness, "none");
	assert.equal(hostStats([statsOf({ readiness: 1, totalRequests: 5 }), s]).level, 4);
	assert.equal(hostStats([]), null);
	const item = suggestionOf(
		{
			id: "x",
			eventType: "url",
			eventTitle: "/a",
			severity: "Critical",
			metrics: [{ metric: "requests", count: 3 }],
		},
		"a.example",
	);
	assert.equal(item.type, "url");
	assert.equal(item.severity, "critical");
	assert.deepEqual(item.metrics, [{ name: "requests", value: 3 }]);
});
