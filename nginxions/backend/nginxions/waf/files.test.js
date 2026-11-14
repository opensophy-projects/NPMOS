import assert from "node:assert/strict";
import { test } from "node:test";
import { fileRule, filesRules, toEvent } from "./files.js";

const doc = {
	policies: {
		default: { mode: "detect-learn", threatPreventionPractices: ["plain"] },
		specificRules: [
			{ name: "r1", host: "files.example.com", mode: "prevent-learn", threatPreventionPractices: ["scan"] },
			{ name: "r1.1", host: "www.files.example.com", mode: "prevent-learn", threatPreventionPractices: ["scan"] },
			{
				name: "r1-0",
				host: "files.example.com/public",
				mode: "prevent-learn",
				threatPreventionPractices: ["plain"],
			},
			{ name: "r2", host: "other.example.com", mode: "prevent", threatPreventionPractices: ["plain"] },
		],
	},
	threatPreventionPractices: [
		{ name: "plain", fileSecurity: { overrideMode: "inactive" } },
		{
			name: "scan",
			fileSecurity: {
				overrideMode: "inherited",
				lowConfidenceEventAction: "detect",
				largeFileInspection: {
					fileSizeLimit: 2,
					fileSizeLimitUnit: "MB",
					filesExceedingSizeLimitAction: "detect",
				},
			},
		},
	],
};

test("the rules of a host: its domains and locations, the default rule for the others; only hosts that scan", () => {
	const { hosts, enabled } = filesRules(doc, [
		{ id: 1, domains: ["files.example.com", "www.files.example.com"] },
		{ id: 2, domains: ["other.example.com"] },
		{ id: 3, domains: ["nowaf.example.com"] },
	]);
	assert.ok(enabled);
	assert.deepEqual(Object.keys(hosts), ["1"]);
	assert.deepEqual(
		hosts["1"].map((r) => [r.path, r.mode]),
		[
			["", "prevent"],
			["/public", "inactive"],
		],
	);
	assert.deepEqual(hosts["1"][0].actions, { high: "prevent", medium: "prevent", low: "detect" });
	assert.equal(hosts["1"][0].max_bytes, 2 * 1024 * 1024);
	assert.equal(hosts["1"][0].large_action, "detect");
});

test("no File Security anywhere: clamd is off", () => {
	const { enabled } = filesRules({ policies: { default: { mode: "prevent" } } }, [{ id: 1, domains: ["a.example"] }]);
	assert.equal(enabled, false);
});

test("an engine the practice does not set is off; inherited takes the mode of the rule", () => {
	const practices = new Map([["p", { fileSecurity: { overrideMode: "inherited" } }]]);
	assert.equal(fileRule({ mode: "detect", threatPreventionPractices: ["p"] }, practices, "").mode, "detect");
	assert.equal(fileRule({ mode: "prevent", threatPreventionPractices: ["none"] }, practices, "").mode, "inactive");
	const rule = fileRule({ mode: "prevent", threatPreventionPractices: ["p"] }, practices, "");
	// 10 MB by default, large files take the mode
	assert.equal(rule.max_bytes, 10 * 1024 * 1024);
	assert.equal(rule.large_action, "prevent");
	// the defaults of the schema: medium severity and up, archives not opened, unnamed files take the mode
	assert.equal(rule.min_severity, "medium");
	assert.deepEqual(rule.archives, {
		extract: false,
		max_bytes: 10 * 1024 * 1024,
		nested_action: "prevent",
		failed_action: "prevent",
	});
	assert.equal(rule.unnamed_action, "prevent");
	assert.equal(rule.deep, false);
	const set = new Map([
		[
			"p",
			{
				fileSecurity: {
					overrideMode: "detect",
					minSeverityLevel: "critical",
					unnamedFilesAction: "inactive",
					threatEmulationEnabled: true,
					archiveInspection: {
						extractArchiveFiles: true,
						scanMaxFileSize: 2,
						scanMaxFileSizeUnit: "KB",
						archivedFilesWithinArchivedFiles: "prevent",
					},
				},
			},
		],
	]);
	const custom = fileRule({ mode: "prevent", threatPreventionPractices: ["p"] }, set, "/up");
	assert.equal(custom.min_severity, "critical");
	assert.equal(custom.unnamed_action, "inactive");
	assert.equal(custom.deep, true);
	assert.deepEqual(custom.archives, {
		extract: true,
		max_bytes: 2048,
		nested_action: "prevent",
		failed_action: "detect",
	});
});

test("a finding of nginx becomes a security event", () => {
	const e = toEvent({
		time: "2026-11-14T10:00:00Z",
		ip: "10.0.0.5",
		host: "Files.Example.com",
		method: "POST",
		uri: "/upload?x=1",
		signature: "Win.Test.EICAR_HDB-1",
		confidence: "high",
		action: "prevent",
		size: 68,
	});
	assert.equal(e.kind, "security");
	assert.equal(e.incident_type, "File Security");
	assert.equal(e.name, "File Security: Win.Test.EICAR_HDB-1");
	assert.equal(e.action, "Prevent");
	assert.equal(e.host, "files.example.com");
	assert.equal(e.uri, "/upload");
	assert.equal(e.query, "x=1");
	assert.equal(e.response_code, 403);
	assert.equal(toEvent({ time: "x", ip: "1" }), null);
});
