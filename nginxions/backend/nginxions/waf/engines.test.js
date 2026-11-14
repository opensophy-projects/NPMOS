import assert from "node:assert/strict";
import { test } from "node:test";
import YAML from "yaml";
import { appsecRules, engineMode, forAgent, ownExpr, renderAppsecPolicy, schemaRef, usesChallenge } from "./engines.js";

const doc = {
	policies: {
		default: { mode: "detect-learn", threatPreventionPractices: ["plain"] },
		specificRules: [
			{ name: "shop", host: "shop.example.com", mode: "prevent-learn", threatPreventionPractices: ["bots"] },
			{
				name: "shop-api",
				host: "shop.example.com/api",
				mode: "prevent-learn",
				threatPreventionPractices: ["api"],
			},
			{ name: "other", host: "other.example.com", mode: "prevent", threatPreventionPractices: ["plain"] },
		],
	},
	threatPreventionPractices: [
		{ name: "plain", webAttacks: { overrideMode: "inherited" } },
		{
			name: "bots",
			antiBot: { overrideMode: "inherited", injectedUris: [{ uri: "/" }], validatedUris: [{ uri: "/login" }] },
		},
		{
			name: "api",
			schemaValidation: { overrideMode: "detect", files: ["shop.yaml"], enforcementLevel: "endpointOnly" },
			antiBot: { overrideMode: "inactive" },
		},
	],
};

test("the mode of an engine: its own, else the one of the practice, else the one of the rule", () => {
	assert.equal(engineMode({ antiBot: { overrideMode: "detect" } }, "antiBot", "prevent"), "detect");
	assert.equal(
		engineMode({ practiceMode: "prevent", antiBot: { overrideMode: "inherited" } }, "antiBot", "detect"),
		"prevent",
	);
	assert.equal(engineMode({ antiBot: { overrideMode: "inherited" } }, "antiBot", "prevent-learn"), "prevent");
	assert.equal(engineMode({}, "antiBot", "prevent"), "inactive");
});

test("the rules whose practice turns an engine of CrowdSec on", () => {
	const { rules, engines } = appsecRules(doc);
	assert.equal(rules.length, 4);
	assert.deepEqual(
		engines.map((e) => [e.host, e.path, e.antiBot?.mode ?? null, e.schema?.mode ?? null]),
		[
			["shop.example.com", "", "prevent", null],
			["shop.example.com", "/api", null, "detect"],
		],
	);
	assert.deepEqual(engines[0].antiBot.validated, ["/login"]);
	assert.equal(engines[1].schema.endpointOnly, true);
	assert.ok(usesChallenge({ engines }));
});

test("a hook of a rule leaves out its more specific rules (the longest host[/path] wins, as in the agent)", () => {
	const { rules } = appsecRules(doc);
	const shop = ownExpr({ host: "shop.example.com", path: "" }, rules);
	assert.match(shop, /req\.URL\.Path startsWith "\/api"/);
	assert.match(shop, /&& !\(/);
	const def = ownExpr({ host: "*", path: "" }, rules);
	assert.match(def, /shop\.example\.com/);
	assert.match(def, /other\.example\.com/);
	assert.doesNotMatch(ownExpr({ host: "other.example.com", path: "" }, rules), /&& !\(/);
});

test("the appsec-config: challenge and refusal in prevent, a logged refusal in detect, schemas loaded", () => {
	const text = renderAppsecPolicy(appsecRules(doc));
	const config = YAML.parse(text);
	assert.equal(config.name, "nginxions/policy");
	assert.match(
		config.on_load[0].apply[0],
		/LoadAPISchemaWithOptions\("nginxions-shop\.yaml", "nginxions\/shop\.yaml"/,
	);
	assert.match(config.on_load[0].apply[0], /"on_route_not_found": "ignore"/);
	const [validated, schema] = config.inband.pre_eval;
	assert.match(schema.filter, /!\(ValidateRequestWithSchema\("nginxions-shop\.yaml"\)\)/);
	assert.deepEqual(schema.apply.slice(1), ['SetRemediation("allow")']);
	assert.match(validated.filter, /!HasValidChallengeCookie\(\)/);
	assert.equal(validated.apply.length, 1);
	assert.match(config.inband.post_eval[0].filter, /startsWith "\/"/);
	assert.deepEqual(config.inband.post_eval[0].apply, ["SendChallenge()"]);
	assert.ok(config.inband.on_challenge_submit.some((h) => /RejectSubmission/.test(h.apply[0])));
	assert.equal(schemaRef("my api.yaml"), "nginxions-my_api.yaml");
});

test("no engine: no appsec-config; detect never serves the challenge", () => {
	assert.equal(renderAppsecPolicy(appsecRules({ policies: { default: { mode: "prevent" } } })), null);
	const detect = structuredClone(doc);
	detect.threatPreventionPractices[1].antiBot.overrideMode = "detect";
	const config = YAML.parse(renderAppsecPolicy(appsecRules(detect)));
	assert.equal(config.inband.post_eval, undefined);
	assert.ok(config.inband.pre_eval.some((h) => h.apply.includes('SetRemediation("allow")')));
});

test("the policy of the agent has the engines of CrowdSec and File Security off", () => {
	const agent = forAgent({
		threatPreventionPractices: [
			{
				name: "p",
				antiBot: { overrideMode: "prevent" },
				fileSecurity: { overrideMode: "prevent" },
				webAttacks: {},
			},
		],
	});
	assert.equal(agent.threatPreventionPractices[0].antiBot.overrideMode, "inactive");
	assert.equal(agent.threatPreventionPractices[0].fileSecurity.overrideMode, "inactive");
	assert.deepEqual(agent.threatPreventionPractices[0].webAttacks, {});
});
