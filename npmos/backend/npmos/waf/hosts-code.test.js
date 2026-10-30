import assert from "node:assert/strict";
import { test } from "node:test";
import { fromCode, toCode } from "./hosts-code.js";

const all = [
	{ id: 1, kind: "threat_prevention", name: "npmos-default" },
	{ id: 2, kind: "log_trigger", name: "npmos-log" },
	{ id: 3, kind: "exception", name: "office" },
];
const current = {
	enabled: true,
	mode: "prevent-learn",
	minimum_confidence: "high",
	objects: { threatPreventionPractices: [1], triggers: [2], exceptions: [3] },
	locations: [
		{
			path: "/api",
			inherit: false,
			enabled: true,
			mode: "detect-learn",
			minimum_confidence: "critical",
			objects: null,
		},
		{
			path: "/static",
			inherit: true,
			enabled: true,
			mode: "prevent-learn",
			minimum_confidence: "high",
			objects: null,
		},
	],
};

test("host code: objects by name, own locations only, read back the same", () => {
	const code = toCode("app.example.com", current, all);
	assert.match(code, /threatPreventionPractices:\n\s+- npmos-default/);
	assert.match(code, /path: \/api/);
	assert.doesNotMatch(code, /\/static/);
	const back = fromCode(code, current, all);
	assert.deepEqual(back.objects, current.objects);
	assert.equal(back.mode, "prevent-learn");
	assert.deepEqual(
		back.locations.map((l) => [l.path, l.inherit, l.mode ?? null]),
		[
			["/api", false, "detect-learn"],
			["/static", true, "prevent-learn"],
		],
	);
});

test("host code: unknown names, fields and locations are refused", () => {
	assert.throws(
		() => fromCode("mode: prevent\nobjects:\n  exceptions: [nope]\n", current, all),
		/no exception object named nope/,
	);
	assert.throws(() => fromCode("mode: prevent\ncolour: red\n", current, all), /unknown field colour/);
	assert.throws(() => fromCode("mode: prevent\nlocations:\n  - path: /x\n", current, all), /no location \/x/);
	assert.throws(() => fromCode("- a\n", current, all), /must be a map/);
});
