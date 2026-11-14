// Engines of a threat prevention practice NginxionS runs in AppSec of CrowdSec (docs/WAF-POLICY.md): open-appsec has
// them only in its Premium edition. The agent gets them turned off (forAgent); CrowdSec gets an appsec-config made of
// the rules of the policy that use them (renderAppsecPolicy, written by crowdsec/apply.js):
//   - antiBot: the bot challenge of CrowdSec (proof of work and fingerprint of the browser, signals of automation
//     scored as in its hub, a submission of 75 points or more refused). injectedUris: pages a browser gets the
//     challenge on (the cookie it earns lets it through after); validatedUris: requests that need the cookie (a
//     page in a browser is challenged, any other request is refused or, in detect, logged). Neither: every page.
//   - schemaValidation: the requests of the host are checked against its OpenAPI files (waf/schemas.js, copied into
//     the data of CrowdSec): path, method, parameters, body; enforcementLevel "endpointOnly" checks only the routes
//     of the files, "fullSchema" (default) refuses the others too.
// A rule of the policy is matched as the agent does: the longest host[/path] wins, so a hook of a rule leaves out the
// requests of its more specific rules. In detect a refused request is logged (an alert of CrowdSec) and let through.
import YAML from "yaml";

export const APPSEC_ENGINES = ["antiBot", "schemaValidation"];
/** engines turned off in the policy of the agent: CrowdSec runs them, or NginxionS (fileSecurity) */
export const NOT_IN_AGENT = ["antiBot", "schemaValidation", "fileSecurity"];
export const POLICY_CONFIG = "nginxions/policy";
/** where the OpenAPI files of the policy are in the data directory of CrowdSec (its "schemas" folder) */
export const SCHEMA_DIR = "nginxions";

// signals of automation of the fingerprint of the challenge and their points (crowdsecurity/appsec-bot-challenge-scoring
// of the CrowdSec hub, MIT); a submission of THRESHOLD points or more is refused (its "balanced" threshold)
const SIGNALS = [
	["cdp", 100],
	["webdriver", 100],
	["webdriver_writable", 100],
	["selenium", 100],
	["playwright", 100],
	["webdriver_iframe", 100],
	["webdriver_worker", 100],
	["bot_user_agent", 100],
	["headless_screen_resolution", 50],
	["missing_chrome_object", 50],
	["impossible_memory", 50],
	["inconsistent_etsl", 50],
	["mismatch_webgl_worker", 50],
	["mismatch_platform_iframe", 50],
	["mismatch_platform_worker", 50],
	["platform_mismatch", 30],
	["gpu_mismatch", 30],
	["high_cpu_count", 30],
	["utc_timezone", 15],
	["ua_mobile", 15],
	["accept_language", 15],
	["swiftshader_renderer", 5],
	["mismatch_languages", 5],
	["timezone_country", 5],
];
export const THRESHOLD = 75;
/** verified good bots (search engines...) get no challenge: configs of the CrowdSec hub, if installed */
export const GOOD_BOTS = [
	"crowdsecurity/appsec-bot-challenge-exclude-search-engines",
	"crowdsecurity/appsec-bot-challenge-exclude-ai-crawlers",
	"crowdsecurity/appsec-bot-challenge-exclude-google-ads",
	"crowdsecurity/appsec-bot-challenge-exclude-wikimedia-citation",
	"crowdsecurity/appsec-bot-challenge-exclude-social",
	"crowdsecurity/appsec-bot-challenge-exclude-monitoring",
];

const list = (v) => (Array.isArray(v) ? v : []);
const MODES = {
	"prevent-learn": "prevent",
	prevent: "prevent",
	"detect-learn": "detect",
	detect: "detect",
	inactive: "inactive",
};

/**
 * The mode of an engine of a practice in a rule: its own; "inherited": the one of the practice, else the one of the
 * rule. An engine the practice does not set is off (inactive is its default in the schema).
 */
export const engineMode = (practice, engine, ruleMode) => {
	const own = practice?.[engine]?.overrideMode;
	if (!own) return "inactive";
	if (own !== "inherited") return MODES[own] ?? "inactive";
	const mode = practice?.practiceMode;
	if (mode && mode !== "inherited") return MODES[mode] ?? "inactive";
	return MODES[ruleMode] ?? "inactive";
};

/** the policy for the agent: the engines it does not run are off (the rest of the practices as they are) */
export const forAgent = (doc) => ({
	...doc,
	threatPreventionPractices: list(doc.threatPreventionPractices).map((p) => {
		const out = { ...p };
		for (const engine of NOT_IN_AGENT) {
			if (out[engine]) out[engine] = { ...out[engine], overrideMode: "inactive" };
		}
		return out;
	}),
});

/** host[/path] of a rule: the host in lower case and the path ("" for the whole host) */
const splitHost = (value) => {
	const text = String(value || "*");
	const slash = text.indexOf("/");
	const host = (slash === -1 ? text : text.slice(0, slash)).toLowerCase();
	const path = slash === -1 ? "" : text.slice(slash);
	return { host, path: path === "/" ? "" : path };
};

/** a path of antiBot: "/x" or "x" → "/x" */
const uriOf = (u) => {
	const text = String(typeof u === "string" ? u : (u?.uri ?? "")).trim();
	if (!text) return null;
	return text.startsWith("/") ? text : `/${text}`;
};

/**
 * The rules of a policy (v1beta2, merged) and those of them whose practice turns an engine of CrowdSec on.
 * @param {object} doc
 * @returns {{rules: {host: string, path: string}[], engines: object[]}}
 *   engines: [{host, path, antiBot: {mode, injected, validated} | null, schema: {mode, files, endpointOnly} | null}]
 */
export const appsecRules = (doc) => {
	const practices = new Map(list(doc?.threatPreventionPractices).map((p) => [p.name, p]));
	const all = [
		{ ...(doc?.policies?.default ?? {}), host: "*" },
		...list(doc?.policies?.specificRules).filter((r) => r?.host),
	];
	const rules = all.map((r) => splitHost(r.host));
	const engines = [];
	all.forEach((rule, i) => {
		const practice = practices.get(list(rule.threatPreventionPractices)[0]);
		if (!practice) return;
		const out = { ...rules[i], antiBot: null, schema: null };
		const botMode = engineMode(practice, "antiBot", rule.mode);
		if (botMode !== "inactive") {
			out.antiBot = {
				mode: botMode,
				injected: [...new Set(list(practice.antiBot?.injectedUris).map(uriOf).filter(Boolean))],
				validated: [...new Set(list(practice.antiBot?.validatedUris).map(uriOf).filter(Boolean))],
			};
		}
		const schemaMode = engineMode(practice, "schemaValidation", rule.mode);
		const files = [...new Set(list(practice.schemaValidation?.files).map(String).filter(Boolean))];
		if (schemaMode !== "inactive" && files.length) {
			out.schema = {
				mode: schemaMode,
				files,
				endpointOnly: practice.schemaValidation?.enforcementLevel === "endpointOnly",
			};
		}
		if (out.antiBot || out.schema) engines.push(out);
	});
	return { rules, engines };
};

// ---------------------------------------------------------------- expressions of the hooks (expr of CrowdSec)

const str = (s) => JSON.stringify(String(s));
const HOST = "lower(req.Host)";

/** the request is on this host (with or without a port; *.example.com: its subdomains) */
const hostExpr = (host) => {
	if (host === "*") return "true";
	if (host.startsWith("*.")) {
		const suffix = host.slice(1);
		return `(${HOST} endsWith ${str(suffix)} || ${HOST} matches ${str(`^[^:]+${escapeRe(suffix)}:[0-9]+$`)})`;
	}
	return `(${HOST} == ${str(host)} || ${HOST} startsWith ${str(`${host}:`)})`;
};
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const pathExpr = (path) => (path ? `req.URL.Path startsWith ${str(path)}` : "true");
const ruleExpr = ({ host, path }) => `(${hostExpr(host)} && ${pathExpr(path)})`;

/** a rule is more specific than another one: the agent takes the longest host[/path] (a host before "*") */
const moreSpecific = (a, b) => {
	if (a.host === b.host) return a.path.length > b.path.length && a.path.startsWith(b.path);
	if (b.host === "*") return true;
	if (b.host.startsWith("*.") && !a.host.startsWith("*.")) return a.host.endsWith(b.host.slice(1));
	return false;
};

/** the request belongs to this rule: it matches it and none of its more specific rules */
export const ownExpr = (rule, rules) => {
	const others = rules.filter((r) => moreSpecific(r, rule));
	const base = ruleExpr(rule);
	return others.length ? `${base} && !(${others.map(ruleExpr).join(" || ")})` : base;
};

const anyPath = (paths) => `(${paths.map(pathExpr).join(" || ")})`;
/** a page a browser navigates to (a challenge page is useless to an API client) */
const BROWSER = 'req.Method == "GET" && (req.Header.Get("Accept") contains "text/html")';
/** a name of a schema (its reference in CrowdSec) */
export const schemaRef = (file) => `nginxions-${file.replace(/[^A-Za-z0-9_.-]/g, "_")}`;

/**
 * The appsec-config of the policy (crowdsec/apply.js writes it to appsec-configs/nginxions-policy.yaml), null when
 * no rule turns an engine on.
 * @param {{rules: object[], engines: object[]}} parsed  appsecRules
 */
export const renderAppsecPolicy = ({ rules, engines }) => {
	if (!engines.length) return null;
	const preEval = [];
	const postEval = [];
	const files = new Map();
	for (const e of engines) {
		const own = ownExpr(e, rules);
		const allow = (mode) => (mode === "detect" ? ['SetRemediation("allow")'] : []);
		if (e.schema) {
			for (const f of e.schema.files) files.set(f, e.schema.endpointOnly);
			// valid against one of the files of the rule
			const valid = e.schema.files.map((f) => `ValidateRequestWithSchema(${str(schemaRef(f))})`).join(" || ");
			preEval.push({
				filter: `${own} && !(${valid})`,
				apply: [
					`DropRequest("NginxionS schema validation (${e.schema.mode}): " + hook_vars.validation_error_message)`,
					...allow(e.schema.mode),
				],
			});
		}
		if (e.antiBot) {
			const { mode, injected, validated } = e.antiBot;
			if (validated.length) {
				// a request that needs the cookie and has none: a page of a browser is challenged (below), any other
				// request is refused (prevent) or logged (detect)
				preEval.push({
					filter: `${own} && ${anyPath(validated)} && !HasValidChallengeCookie() && !(${BROWSER})`,
					apply: [`DropRequest("NginxionS anti-bot (${mode}): no valid challenge cookie")`, ...allow(mode)],
				});
			}
			// the challenge itself changes what a browser gets: only in prevent
			if (mode === "prevent") {
				const challenged = [...injected, ...validated];
				postEval.push({
					filter: `${own} && ${challenged.length ? `${anyPath(challenged)} && ` : ""}${BROWSER}`,
					apply: ["SendChallenge()"],
				});
			}
		}
	}
	const config = { name: POLICY_CONFIG, default_remediation: "ban" };
	if (files.size) {
		config.on_load = [
			{
				apply: [...files].map(
					([f, endpointOnly]) =>
						`LoadAPISchemaWithOptions(${str(schemaRef(f))}, ${str(`${SCHEMA_DIR}/${f}`)}, {"on_route_not_found": ${str(endpointOnly ? "ignore" : "drop")}, "on_method_not_allowed": "drop", "on_unsupported_security_scheme": "ignore"})`,
				),
			},
		];
	}
	config.inband = {};
	if (preEval.length) config.inband.pre_eval = preEval;
	if (postEval.length) {
		config.inband.post_eval = postEval;
		config.inband.on_challenge_submit = [
			...SIGNALS.map(([signal, points]) => ({
				filter: `EvaluateMismatches().Has(${str(signal)})`,
				apply: [`AddRequestScore(${points}, ${str(signal)})`],
			})),
			{
				filter: `RequestScore() >= ${THRESHOLD}`,
				apply: ['RejectSubmission("NginxionS anti-bot: request score " + string(RequestScore()), "verbose")'],
			},
		];
	}
	return `# Generated by NginxionS from the WAF policy (WAF -> Policy): edits are overwritten.\n${YAML.stringify(config, { lineWidth: 0 })}`;
};

/** the policy turns the bot challenge on (the configs of good bots are added then) */
export const usesChallenge = ({ engines }) => engines.some((e) => e.antiBot?.mode === "prevent");
/** the OpenAPI files the policy uses */
export const schemaFiles = ({ engines }) => [...new Set(engines.flatMap((e) => e.schema?.files ?? []))];

// ---------------------------------------------------------------- the engines of the policy in force

let current = { rules: [], engines: [] };
/** set by waf/policy.js at every generation; read by crowdsec/apply.js */
export const setEngines = (parsed) => {
	const changed = JSON.stringify(parsed) !== JSON.stringify(current);
	current = parsed;
	return changed;
};
export const getEngines = () => current;
