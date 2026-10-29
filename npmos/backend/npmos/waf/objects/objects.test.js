import assert from "node:assert/strict";
import { test } from "node:test";
import { fromV1, isV1, needsV2, toV1, v2ExceptionLimits } from "./format.js";
import { BUILTIN, builtinSpec, KINDS, normalize, TEMPLATES } from "./model.js";

test("built-in objects are complete and valid", () => {
	for (const name of Object.keys(BUILTIN)) {
		const spec = builtinSpec(name);
		assert.ok(spec, name);
	}
	const practice = builtinSpec("npmos-recommended");
	assert.equal(practice.webAttacks.maxBodySizeKb, 1000000);
	assert.equal(practice.webAttacks.minimumConfidence, "high");
	assert.equal(builtinSpec("npmos-log").logDestination.cloud, false);
	for (const template of Object.values(TEMPLATES)) {
		for (const name of [...template.threatPreventionPractices, ...template.triggers, template.customResponse]) {
			assert.ok(BUILTIN[name], name);
		}
	}
});

test("specifications are checked against the schema of open-appsec", () => {
	assert.deepEqual(normalize("custom_response", { mode: "teapot" }).errors?.length > 0, true);
	assert.ok(normalize("exception", { action: "accept", condition: [] }).errors);
	assert.ok(normalize("exception", { action: "accept", condition: [{ key: "sourceIp", value: "10.0.0.1" }] }).spec);
	const trigger = normalize("log_trigger", { logDestination: { cloud: true } }).spec;
	assert.equal(trigger.logDestination.cloud, false);
	assert.deepEqual(trigger.logDestination.stdout, { format: "json" });
	assert.equal(normalize("nothing", {}).errors[0], "unknown kind nothing");
});

const example = {
	policies: {
		default: {
			mode: "detect-learn",
			threatPreventionPractices: ["p"],
			accessControlPractices: ["ac"],
			triggers: ["t"],
			customResponse: "r",
			exceptions: ["e1", "e2"],
		},
		specificRules: [
			{ name: "one", host: "a.example.com", mode: "prevent-learn", threatPreventionPractices: ["p"] },
		],
	},
	threatPreventionPractices: [{ name: "p", ...builtinSpec("npmos-strict") }],
	accessControlPractices: [{ name: "ac", ...builtinSpec("npmos-no-rate-limit") }],
	logTriggers: [{ name: "t", ...builtinSpec("npmos-log") }],
	customResponses: [{ name: "r", ...builtinSpec("npmos-block-page") }],
	exceptions: [
		{
			name: "e1",
			action: "accept",
			condition: [
				{ key: "sourceIp", value: "10.0.0.1" },
				{ key: "sourceIp", value: "10.0.0.2" },
				{ key: "url", value: "/health" },
			],
		},
		{ name: "e2", action: "suppressLog", condition: [{ key: "countryCode", value: "US" }] },
	],
	trustedSources: [{ name: "ts", minNumOfSources: 3, sourcesIdentifiers: ["si"] }],
	sourcesIdentifiers: [{ name: "si", sourcesIdentifiers: [{ identifier: "headerkey", value: ["x-user"] }] }],
};

test("v1beta2 → v1beta1 → v1beta2 keeps the meaning", () => {
	const v1 = toV1(example);
	assert.equal(isV1(v1), true);
	assert.equal(isV1(example), false);
	assert.deepEqual(v1.exceptions[0], {
		name: "e1",
		action: "accept",
		sourceIp: ["10.0.0.1", "10.0.0.2"],
		url: ["/health"],
	});
	assert.equal(v1.practices[0]["web-attacks"]["override-mode"], "as-top-level");
	assert.equal(v1.practices[0]["web-attacks"].protections["non-valid-http-methods"], true);
	// protections of "p" inherit the mode of the rule: a copy per mode in v1beta1
	assert.equal(v1.policies["specific-rules"][0].practices[0], "p.prevent-learn");
	assert.equal(v1.policies.default.practices[0], "p.detect-learn");
	const copy = v1.practices.find((p) => p.name === "p.prevent-learn");
	assert.equal(copy["web-attacks"].protections["csrf-enabled"], "prevent-learn");
	assert.equal(v1["custom-responses"][0]["message-title"], "Access denied");
	const back = fromV1(v1);
	assert.equal(back.threatPreventionPractices.length, 3);
	assert.deepEqual(back.exceptions, example.exceptions);
	assert.equal(back.threatPreventionPractices[0].webAttacks.overrideMode, "inherited");
	assert.equal(back.threatPreventionPractices[0].webAttacks.minimumConfidence, "medium");
	assert.deepEqual(back.sourcesIdentifiers, example.sourcesIdentifiers);
	assert.equal(back.policies.default.customResponse, "r");
});

test("fragments in either syntax, v1beta2 only when needed", () => {
	// the expert fragment of the closed-network test: v1beta2 conditions in a v1beta1 file
	const fragment = fromV1({
		exceptions: [{ name: "x", action: "accept", condition: [{ key: "sourceIp", value: "1.2.3.4" }] }],
		policies: { default: { exceptions: ["x"] } },
	});
	assert.deepEqual(toV1(fragment).exceptions[0], { name: "x", action: "accept", sourceIp: ["1.2.3.4"] });
	assert.deepEqual(needsV2(example), []);
	const limited = structuredClone(example);
	limited.accessControlPractices[0].rateLimit = {
		overrideMode: "prevent",
		rules: [{ uri: "/login", limit: 10, unit: "minute" }],
	};
	limited.customResponses[0] = { name: "r", mode: "redirect", redirectUrl: "https://x" };
	assert.deepEqual(needsV2(limited), ["rate-limit:ac", "redirect:r"]);
	assert.deepEqual(v2ExceptionLimits(example), ["default"]);
	assert.equal(Object.keys(KINDS).length, 7);
});

test("objects of the examples of open-appsec pass the schema", async () => {
	const { readFile } = await import("node:fs/promises");
	const YAML = (await import("yaml")).default;
	for (const name of ["default", "example", "prevent"]) {
		const file = new URL(
			`../../../../../reference/openappsec/config/linux/v1beta2/${name}/local_policy.yaml`,
			import.meta.url,
		);
		let doc;
		try {
			doc = YAML.parse(await readFile(file, "utf8"));
		} catch {
			continue;
		}
		for (const [kind, section] of Object.entries(KINDS)) {
			for (const item of doc[section] || []) {
				const result = normalize(kind, item);
				assert.ok(result.spec, `${name}/${section}/${item.name}: ${result.errors}`);
			}
		}
	}
});
