import assert from "node:assert/strict";
import { test } from "node:test";
import { asV2, danglingRefs, extraRefs, fromV1, isV1, toV1 } from "./format.js";
import { BUILTIN, builtinSpec, KINDS, normalize, TEMPLATES } from "./model.js";

test("built-in objects are complete and valid", () => {
	for (const name of Object.keys(BUILTIN)) {
		const spec = builtinSpec(name);
		assert.ok(spec, name);
	}
	const practice = builtinSpec("nginxions-recommended");
	assert.equal(practice.webAttacks.maxBodySizeKb, 1000000);
	assert.equal(practice.webAttacks.minimumConfidence, "high");
	assert.equal(builtinSpec("nginxions-log").logDestination.cloud, false);
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
	threatPreventionPractices: [{ name: "p", ...builtinSpec("nginxions-strict") }],
	accessControlPractices: [{ name: "ac", ...builtinSpec("nginxions-no-rate-limit") }],
	logTriggers: [{ name: "t", ...builtinSpec("nginxions-log") }],
	customResponses: [{ name: "r", ...builtinSpec("nginxions-block-page") }],
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

test("fragments in either syntax; the agent always gets v1beta2, without copies of practices", () => {
	// the expert fragment of the closed-network test: v1beta2 conditions in a v1beta1 file
	const fragment = fromV1({
		exceptions: [{ name: "x", action: "accept", condition: [{ key: "sourceIp", value: "1.2.3.4" }] }],
		policies: { default: { exceptions: ["x"] } },
	});
	assert.deepEqual(toV1(fragment).exceptions[0], { name: "x", action: "accept", sourceIp: ["1.2.3.4"] });
	const limited = structuredClone(example);
	limited.accessControlPractices[0].rateLimit = {
		overrideMode: "prevent",
		rules: [{ uri: "/login", limit: 10, unit: "minute" }],
	};
	limited.policies.specificRules.push({ name: "two", host: "b.example.com", accessControlPractices: ["ac"] });
	const v2 = asV2(limited);
	assert.equal(v2.apiVersion, "v1beta2");
	// the agent of NginxionS keeps a rate limit per asset: the same practice in two rules, no copies
	assert.deepEqual(v2.policies.default.accessControlPractices, ["ac"]);
	assert.deepEqual(v2.policies.specificRules[0].accessControlPractices, []);
	assert.deepEqual(v2.policies.specificRules[1].accessControlPractices, ["ac"]);
	assert.equal(v2.accessControlPractices.length, 1);
	// both keys of practices are in every rule (the agent requires them)
	assert.deepEqual(v2.policies.specificRules[1].threatPreventionPractices, []);

	assert.deepEqual(danglingRefs(example), []);
	const dangling = structuredClone(example);
	dangling.policies.specificRules[0].exceptions = ["gone"];
	dangling.trustedSources[0].sourcesIdentifiers = ["si", "nope"];
	assert.deepEqual(danglingRefs(dangling), ["one:gone", "ts:nope"]);
	assert.deepEqual(extraRefs(example), []);
	const extra = structuredClone(example);
	extra.policies.default.triggers = ["t", "t2"];
	assert.deepEqual(extraRefs(extra), ["default:triggers"]);
	assert.equal(Object.keys(KINDS).length, 7);
});

test("no silent fields: what the agent does not apply is an error, or dropped and named", () => {
	// threat emulation: the deep static analysis of ClamAV in NginxionS (macros, broken executables and media)
	const files = {
		webAttacks: { overrideMode: "inherited" },
		fileSecurity: { overrideMode: "inherited", threatEmulationEnabled: true },
	};
	assert.equal(normalize("threat_prevention", files).errors, undefined);
	const imported = normalize("threat_prevention", files, { lenient: true });
	assert.equal(imported.spec.fileSecurity.threatEmulationEnabled, true);
	assert.deepEqual(imported.dropped ?? [], []);
	// the IPS has the signatures of NginxionS
	const ips = { webAttacks: { overrideMode: "inherited" }, intrusionPrevention: { overrideMode: "prevent" } };
	assert.equal(normalize("threat_prevention", ips).errors, undefined);
	assert.deepEqual(
		normalize("threat_prevention", {
			webAttacks: { overrideMode: "inherited" },
			snortSignatures: { overrideMode: "inherited", configmap: ["k8s"], files: ["/etc/snort.rules"] },
		}).dropped,
		["/snortSignatures/configmap"],
	);
	assert.deepEqual(normalize("log_trigger", { logDestination: { cloud: true } }).dropped, ["/logDestination/cloud"]);

	const rule = (condition) => ({
		rateLimit: { overrideMode: "prevent", rules: [{ uri: "/", limit: 5, action: "detect", condition }] },
	});
	assert.ok(normalize("access_control", rule([{ key: "sourceIp", value: "10.0.0.1" }])).spec);
	assert.match(normalize("access_control", rule([{ key: "method", value: "POST" }])).errors.join(), /key: one of/);

	assert.match(normalize("custom_response", { mode: "redirect" }).errors.join(), /redirectUrl/);
	assert.ok(normalize("custom_response", { mode: "redirect", redirectUrl: "https://help.example.com/x" }).spec);
	assert.ok(normalize("custom_response", { mode: "redirect", redirectUrl: "/blocked" }).spec);

	assert.match(
		normalize("exception", { action: "accept", condition: [{ key: "cookie", value: "a" }] }).errors.join(),
		/condition\/0\/key/,
	);

	const syslog = (services) => normalize("log_trigger", { logDestination: { syslogService: services } });
	assert.ok(syslog([{ address: "10.0.0.5", port: 514 }]).spec);
	// several servers, names and IPv6 go through the relay of NginxionS (waf/syslog.js)
	assert.ok(syslog([{ address: "logs.example.com", port: 514 }]).spec);
	assert.ok(syslog([{ address: "2001:db8::5", port: 514 }]).spec);
	assert.ok(
		syslog([
			{ address: "10.0.0.5", port: 514 },
			{ address: "10.0.0.6", port: 514, proto: "tcp" },
		]).spec,
	);
	assert.match(syslog([{ address: "not a host", port: 514 }]).errors.join(), /host name/);
	assert.match(syslog([{ address: "10.0.0.5", port: 70000 }]).errors.join(), /1-65535/);
});

test("objects of the examples of open-appsec pass the schema", async () => {
	const { readFile } = await import("node:fs/promises");
	const YAML = (await import("yaml")).default;
	for (const name of ["default", "example", "prevent"]) {
		const file = new URL(`./examples/${name}.yaml`, import.meta.url);
		const doc = YAML.parse(await readFile(file, "utf8"));
		for (const [kind, section] of Object.entries(KINDS)) {
			for (const item of doc[section] || []) {
				// as an import: engines of the Premium edition are turned off and named
				const result = normalize(kind, item, { lenient: true });
				assert.ok(result.spec, `${name}/${section}/${item.name}: ${result.errors}`);
			}
		}
	}
});

test("objects of a location replace those of its host, exceptions add up", async () => {
	const { locationRule } = await import("./store.js");
	const host = { triggers: ["log-all"], exceptions: ["office"], customResponse: "page" };
	assert.deepEqual(locationRule(host, {}), host);
	assert.deepEqual(locationRule(host, { triggers: ["quiet"], exceptions: ["api", "office"] }), {
		triggers: ["quiet"],
		exceptions: ["office", "api"],
		customResponse: "page",
	});
	assert.deepEqual(locationRule({}, { exceptions: ["api"] }).exceptions, ["api"]);
	assert.deepEqual(locationRule({ threatPreventionPractices: ["p"] }, { threatPreventionPractices: [] }), {
		threatPreventionPractices: ["p"],
	});
});

test("the configuration the agent applies is compared with the generated policy", async () => {
	const { compareApplied } = await import("./compare.js");
	const doc = {
		policies: {
			default: {
				threatPreventionPractices: ["p"],
				accessControlPractices: [],
				customResponse: "r403",
			},
			specificRules: [
				{
					host: "shop.example.com",
					threatPreventionPractices: [],
					accessControlPractices: ["limit"],
					customResponse: "away",
				},
			],
		},
		customResponses: [
			{ name: "r403", mode: "response-code-only", httpResponseCode: 403 },
			{ name: "away", mode: "redirect", redirectUrl: "https://help.example.com/x" },
		],
		accessControlPractices: [
			{ name: "limit", rateLimit: { overrideMode: "prevent", rules: [{ uri: "/a" }, { uri: "/b" }] } },
		],
	};
	// as policy_maker_utils.cc writes it (only the keys compared)
	const applied = {
		"security apps": {
			rules: {
				rulebase: {
					rulesConfig: [
						{ assetName: "Any", practices: [] },
						{ assetName: "shop.example.com", practices: [] },
					],
				},
			},
			triggers: {
				rulebase: {
					webUserResponse: [
						{ triggerName: "local_policy/r403", "details level": "Response Code", "response code": 403 },
						{
							triggerName: "local_policy/away",
							"details level": "Redirect",
							"redirect URL": "https://help.example.com/x",
						},
					],
				},
			},
			accessControlV2: { rulebase: { rateLimit: [{ name: "local_policy/limit", rules: [{}, {}] }] } },
		},
	};
	assert.deepEqual(compareApplied(doc, applied), []);

	// the agent dropped the redirect (as before phase 11), lost a rule of the rate limit and the asset of the host
	const old = structuredClone(applied);
	old["security apps"].triggers.rulebase.webUserResponse[1] = {
		triggerName: "local_policy/away",
		"details level": "Redirect",
		"response code": 403,
	};
	old["security apps"].accessControlV2.rulebase.rateLimit[0].rules.pop();
	old["security apps"].rules.rulebase.rulesConfig.pop();
	assert.deepEqual(compareApplied(doc, old).sort(), ["asset:shop.example.com", "rate-limit:limit", "response:away"]);
});

test("dry run: a change of the policy changes the verdicts of recent events as the agent would", async () => {
	const { exceptionMatches, simulate, verdictOf } = await import("./simulate.js");
	const practice = (minimumConfidence) => ({
		name: "p",
		practiceMode: "inherited",
		webAttacks: { overrideMode: "inherited", minimumConfidence },
	});
	const doc = (over = {}) => ({
		policies: {
			default: { mode: "inactive", threatPreventionPractices: ["p"], exceptions: [] },
			specificRules: [
				{ host: "shop.example.com", mode: "prevent-learn", threatPreventionPractices: [], exceptions: [] },
				{ host: "shop.example.com/api", mode: "detect-learn", threatPreventionPractices: [], exceptions: [] },
				...(over.rules || []),
			],
		},
		threatPreventionPractices: [practice(over.confidence || "high")],
		exceptions: over.exceptions || [],
	});
	const event = (e) => ({
		host: "shop.example.com",
		uri: "/search",
		source_ip: "203.0.113.9",
		confidence: "High",
		parameter: "query.q",
		sample: "' or 1=1",
		incident_type: "SQL Injection",
		source_country: "Netherlands",
		...e,
	});

	// the rule of the longest host/path, its mode, the minimum confidence of the practice
	assert.equal(verdictOf(doc(), event()), "block");
	assert.equal(verdictOf(doc(), event({ uri: "/api/items" })), "detect");
	assert.equal(verdictOf(doc(), event({ confidence: "Medium" })), "detect");
	assert.equal(verdictOf(doc({ confidence: "medium" }), event({ confidence: "Medium" })), "block");
	assert.equal(verdictOf(doc(), event({ host: "other.example.com" })), "pass");

	// conditions: values of a key any, keys all; networks; regular expressions of the agent
	const office = { name: "office", action: "accept", condition: [{ key: "sourceIp", value: "203.0.113.0/24" }] };
	assert.equal(exceptionMatches(office, event()), true);
	assert.equal(exceptionMatches(office, event({ source_ip: "198.51.100.1" })), false);
	const both = {
		action: "accept",
		condition: [
			{ key: "url", value: "/search" },
			{ key: "url", value: "/find" },
			{ key: "paramName", value: "q" },
		],
	};
	assert.equal(exceptionMatches(both, event()), true);
	assert.equal(exceptionMatches(both, event({ uri: "/login" })), false);
	assert.equal(exceptionMatches({ condition: [{ key: "url", value: "/api/.*" }] }, event({ uri: "/api/x" })), true);
	// the events keep no country code: the dry run cannot tell
	assert.equal(exceptionMatches({ condition: [{ key: "countryCode", value: "NL" }] }, event()), null);

	const withOffice = doc({ exceptions: [office] });
	withOffice.policies.default.exceptions = ["office"];
	const events = [event(), event(), event({ confidence: "Medium" }), event({ source_ip: "198.51.100.1" })];
	const result = simulate(doc(), withOffice, events);
	// the two blocked and the one logged from the office pass; the other source is not touched
	assert.deepEqual(
		{ changed: result.changed, toPass: result.toPass, toBlock: result.toBlock, unknown: result.unknown },
		{ changed: 3, toPass: 3, toBlock: 0, unknown: 0 },
	);
	assert.equal(result.samples[0].count, 2);
	assert.deepEqual([result.samples[0].before, result.samples[0].after], ["block", "pass"]);

	const stricter = simulate(doc(), doc({ confidence: "medium" }), events);
	assert.deepEqual([stricter.changed, stricter.toBlock], [1, 1]);
});

test("dry run of switching a host to blocking changes its rules only", async () => {
	const { withHostMode } = await import("./simulate.js");
	const doc = {
		policies: {
			default: { mode: "inactive" },
			specificRules: [
				{ name: "npm-managed-specific-rule-proxyhost-3", host: "a.example.com", mode: "detect-learn" },
				{ name: "npm-managed-specific-rule-proxyhost-3.1", host: "www.a.example.com", mode: "detect-learn" },
				{ name: "npm-managed-specific-rule-proxyhost-3-0", host: "a.example.com/api", mode: "detect-learn" },
				{ name: "npm-managed-specific-rule-proxyhost-31", host: "b.example.com", mode: "detect-learn" },
			],
		},
	};
	const modes = withHostMode(doc, 3, "prevent-learn").policies.specificRules.map((r) => r.mode);
	assert.deepEqual(modes, ["prevent-learn", "prevent-learn", "detect-learn", "detect-learn"]);
	assert.equal(doc.policies.specificRules[0].mode, "detect-learn");
});

test("x-nginxions: keys and operators of the WAF beyond v1beta2 are checked, kept out of v1beta1, simulated", async () => {
	const { exceptionMatches } = await import("./simulate.js");
	const { usesExtension } = await import("./format.js");
	const ok = normalize("exception", {
		action: "drop",
		condition: [
			{ key: "countryName", op: "not-in", value: "Russia" },
			{ key: "method", value: "POST" },
			{ key: "headerName", op: "exist", value: "ignored" },
		],
	});
	assert.deepEqual(ok.errors, undefined);
	// exist has no value
	assert.equal(ok.spec.condition[2].value, undefined);
	assert.ok(usesExtension(ok.spec));
	assert.ok(
		!usesExtension({
			condition: [
				{ key: "url", value: "/a" },
				{ key: "url", op: "in", value: "/b" },
			],
		}),
	);
	assert.match(
		normalize("exception", {
			action: "accept",
			condition: [{ key: "url", op: "contains", value: "a" }],
		}).errors.join(),
		/condition\/0\/op/,
	);
	assert.match(normalize("exception", { action: "accept", condition: [{ key: "url" }] }).errors.join(), /value/);
	assert.match(
		normalize("exception", { action: "accept", condition: [{ key: "cookie", value: "a" }] }).errors.join(),
		/key/,
	);

	// v1beta1 cannot hold them: left out
	const v1 = toV1({
		policies: { default: { mode: "detect-learn" }, specificRules: [] },
		exceptions: [ok.spec, { name: "plain", action: "accept", condition: [{ key: "url", value: "/a" }] }],
	});
	assert.deepEqual(
		v1.exceptions.map((e) => e.name),
		["plain"],
	);

	// the dry run: none of the values (not-in), the method, a key the events do not keep
	const event = {
		host: "a.example",
		uri: "/x",
		source_ip: "203.0.113.9",
		source_country: "Netherlands",
		method: "POST",
	};
	const notRu = { condition: [{ key: "countryName", op: "not-in", value: "Russia" }] };
	assert.equal(exceptionMatches(notRu, event), true);
	assert.equal(exceptionMatches(notRu, { ...event, source_country: "Russia" }), false);
	assert.equal(exceptionMatches({ condition: [{ key: "method", value: "GET" }] }, event), false);
	assert.equal(exceptionMatches({ condition: [{ key: "url", op: "exist" }] }, event), true);
	assert.equal(exceptionMatches({ condition: [{ key: "headerName", value: "x-a" }] }, event), null);
	assert.equal(
		exceptionMatches(
			{ condition: [{ key: "indicator", value: "probing" }] },
			{ ...event, indicators: "[.env, probing]" },
		),
		true,
	);
});
