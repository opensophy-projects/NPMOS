// local_policy.yaml of open-appsec in its two syntaxes. NPMOS keeps the policy in the terms of
// v1beta2 (camelCase, the objects of the policy editor); the agent gets v1beta1 unless the policy
// uses what only v1beta2 has (docs/adr/0008-waf-policy.md):
//   - v1beta1 applies every exception of a rule, v1beta2 only the first (policy_maker_utils.cc);
//   - v1beta2 adds rate limits (access control practices), redirect responses, IPS and file
//     security (the last two need the Premium edition of the agent).
// Pure functions, no database.

const SECTIONS_V2 = [
	"threatPreventionPractices",
	"accessControlPractices",
	"logTriggers",
	"customResponses",
	"exceptions",
	"trustedSources",
	"sourcesIdentifiers",
];

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const list = (v) => (Array.isArray(v) ? v : []);
/** v1beta2 "inherited" is v1beta1 "as-top-level" */
const modeToV1 = (mode) => (mode === "inherited" ? "as-top-level" : mode);
const modeFromV1 = (mode) => (mode === "as-top-level" ? "inherited" : mode);
const defined = (obj) => Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));

// ---------------------------------------------------------------- rules

const ruleToV1 = (rule) =>
	defined({
		name: rule.name,
		host: rule.host,
		mode: rule.mode,
		practices: rule.threatPreventionPractices,
		triggers: rule.triggers,
		"custom-response": rule.customResponse,
		// "" (none) only matters in v1beta2, where a rule inherits what it does not name
		"source-identifiers": rule.sourceIdentifiers || undefined,
		"trusted-sources": rule.trustedSources || undefined,
		exceptions: rule.exceptions,
	});

const ruleFromV1 = (rule) =>
	defined({
		name: rule.name,
		host: rule.host,
		mode: rule.mode,
		threatPreventionPractices: rule.practices ?? rule.threatPreventionPractices,
		accessControlPractices: rule.accessControlPractices,
		triggers: rule.triggers,
		customResponse: rule["custom-response"] ?? rule.customResponse,
		sourceIdentifiers: rule["source-identifiers"] ?? rule.sourceIdentifiers,
		trustedSources: rule["trusted-sources"] ?? rule.trustedSources,
		exceptions: rule.exceptions,
	});

// ---------------------------------------------------------------- objects

const practiceToV1 = (p) => {
	const w = p.webAttacks || {};
	const protections = w.protections || {};
	const bot = p.antiBot || {};
	return defined({
		name: p.name,
		"web-attacks": defined({
			"override-mode": modeToV1(w.overrideMode ?? "inherited"),
			"minimum-confidence": w.minimumConfidence,
			"max-body-size-kb": w.maxBodySizeKb,
			"max-header-size-bytes": w.maxHeaderSizeBytes,
			"max-object-depth": w.maxObjectDepth,
			"max-url-size-bytes": w.maxUrlSizeBytes,
			protections: defined({
				"csrf-enabled": modeToV1(protections.csrfProtection ?? "inactive"),
				"error-disclosure-enabled": modeToV1(protections.errorDisclosure ?? "inactive"),
				"open-redirect-enabled": modeToV1(protections.openRedirect ?? "inactive"),
				"non-valid-http-methods": protections.nonValidHttpMethods ?? false,
			}),
		}),
		"anti-bot": {
			"override-mode": modeToV1(bot.overrideMode ?? "inactive"),
			"injected-URIs": list(bot.injectedUris).map((uri) => ({ uri })),
			"validated-URIs": list(bot.validatedUris).map((uri) => ({ uri })),
		},
		"snort-signatures": {
			"override-mode": modeToV1(p.snortSignatures?.overrideMode ?? "inactive"),
			files: list(p.snortSignatures?.files),
		},
		"openapi-schema-validation": {
			"override-mode": modeToV1(p.schemaValidation?.overrideMode ?? "inactive"),
			files: list(p.schemaValidation?.files),
		},
	});
};

const uris = (items) =>
	list(items)
		.map((i) => (isObject(i) ? i.uri : i))
		.filter(Boolean);

const practiceFromV1 = (p) => {
	const w = p["web-attacks"] || {};
	const protections = w.protections || {};
	const bot = p["anti-bot"] || {};
	return {
		name: p.name,
		practiceMode: "inherited",
		webAttacks: defined({
			overrideMode: modeFromV1(w["override-mode"] ?? "inactive"),
			minimumConfidence: w["minimum-confidence"],
			maxBodySizeKb: w["max-body-size-kb"],
			maxHeaderSizeBytes: w["max-header-size-bytes"],
			maxObjectDepth: w["max-object-depth"],
			maxUrlSizeBytes: w["max-url-size-bytes"],
			protections: defined({
				csrfProtection: modeFromV1(protections["csrf-enabled"]),
				errorDisclosure: modeFromV1(protections["error-disclosure-enabled"]),
				openRedirect: modeFromV1(protections["open-redirect-enabled"]),
				nonValidHttpMethods: protections["non-valid-http-methods"],
			}),
		}),
		antiBot: {
			overrideMode: modeFromV1(bot["override-mode"] ?? "inactive"),
			injectedUris: uris(bot["injected-URIs"]),
			validatedUris: uris(bot["validated-URIs"]),
		},
		snortSignatures: {
			overrideMode: modeFromV1(p["snort-signatures"]?.["override-mode"] ?? "inactive"),
			files: list(p["snort-signatures"]?.files),
		},
		schemaValidation: {
			overrideMode: modeFromV1(p["openapi-schema-validation"]?.["override-mode"] ?? "inactive"),
			files: list(p["openapi-schema-validation"]?.files),
		},
		intrusionPrevention: { overrideMode: "inactive" },
		fileSecurity: { overrideMode: "inactive" },
	};
};

const triggerToV1 = (t) => {
	const dest = t.logDestination || {};
	return defined({
		name: t.name,
		"access-control-logging": {
			"allow-events": t.accessControlLogging?.allowEvents ?? false,
			"drop-events": t.accessControlLogging?.dropEvents ?? true,
		},
		"appsec-logging": {
			"detect-events": t.appsecLogging?.detectEvents ?? true,
			"prevent-events": t.appsecLogging?.preventEvents ?? true,
			"all-web-requests": t.appsecLogging?.allWebRequests ?? false,
		},
		"additional-suspicious-events-logging": {
			enabled: t.additionalSuspiciousEventsLogging?.enabled ?? true,
			"minimum-severity": t.additionalSuspiciousEventsLogging?.minSeverity ?? "high",
			"response-body": t.additionalSuspiciousEventsLogging?.responseBody ?? false,
			"response-code": t.additionalSuspiciousEventsLogging?.responseCode ?? true,
		},
		"extended-logging": {
			"url-path": t.extendedLogging?.urlPath ?? false,
			"url-query": t.extendedLogging?.urlQuery ?? false,
			"http-headers": t.extendedLogging?.httpHeaders ?? false,
			"request-body": t.extendedLogging?.requestBody ?? false,
		},
		"log-destination": defined({
			cloud: false,
			stdout: dest.stdout,
			"syslog-service": dest.syslogService?.length ? dest.syslogService : undefined,
			"cef-service": dest.cefService?.length ? dest.cefService : undefined,
		}),
	});
};

const triggerFromV1 = (t) => {
	const dest = t["log-destination"] || {};
	return {
		name: t.name,
		accessControlLogging: {
			allowEvents: t["access-control-logging"]?.["allow-events"] ?? false,
			dropEvents: t["access-control-logging"]?.["drop-events"] ?? true,
		},
		appsecLogging: {
			detectEvents: t["appsec-logging"]?.["detect-events"] ?? true,
			preventEvents: t["appsec-logging"]?.["prevent-events"] ?? true,
			allWebRequests: t["appsec-logging"]?.["all-web-requests"] ?? false,
		},
		additionalSuspiciousEventsLogging: {
			enabled: t["additional-suspicious-events-logging"]?.enabled ?? true,
			minSeverity: t["additional-suspicious-events-logging"]?.["minimum-severity"] ?? "high",
			responseBody: t["additional-suspicious-events-logging"]?.["response-body"] ?? false,
			responseCode: t["additional-suspicious-events-logging"]?.["response-code"] ?? true,
		},
		extendedLogging: {
			urlPath: t["extended-logging"]?.["url-path"] ?? false,
			urlQuery: t["extended-logging"]?.["url-query"] ?? false,
			httpHeaders: t["extended-logging"]?.["http-headers"] ?? false,
			requestBody: t["extended-logging"]?.["request-body"] ?? false,
		},
		// never the Check Point cloud
		logDestination: defined({
			cloud: false,
			stdout: dest.stdout ?? { format: "json" },
			syslogService: dest["syslog-service"],
			cefService: dest["cef-service"],
		}),
	};
};

const responseToV1 = (r) =>
	defined({
		name: r.name,
		mode: r.mode,
		"http-response-code": r.httpResponseCode,
		"message-title": r.messageTitle,
		"message-body": r.messageBody,
	});

const responseFromV1 = (r) =>
	defined({
		name: r.name,
		mode: r.mode,
		httpResponseCode: r["http-response-code"] ?? r.httpResponseCode,
		messageTitle: r["message-title"] ?? r.messageTitle,
		messageBody: r["message-body"] ?? r.messageBody,
		redirectUrl: r.redirectUrl,
		redirectAddXEventId: r.redirectAddXEventId,
	});

export const EXCEPTION_KEYS = [
	"countryCode",
	"countryName",
	"hostName",
	"paramName",
	"paramValue",
	"protectionName",
	"sourceIdentifier",
	"sourceIp",
	"url",
];

/** v1beta2 conditions [{key, value}] → v1beta1 lists per key (values of a key: any; keys: all) */
const exceptionToV1 = (e) => {
	const out = { name: e.name, action: e.action };
	for (const { key, value } of list(e.condition)) {
		if (!EXCEPTION_KEYS.includes(key)) continue;
		out[key] = [...(out[key] || []), String(value)];
	}
	return out;
};

/** accepts both forms: v1beta1 lists per key and v1beta2 conditions */
const exceptionFromV1 = (e) => {
	const condition = list(e.condition).filter((c) => isObject(c) && c.key !== undefined);
	for (const key of EXCEPTION_KEYS) {
		for (const value of list(e[key])) condition.push({ key, value: String(value) });
	}
	return defined({ name: e.name, action: e.action ?? "accept", condition });
};

const trustedToV1 = (t) => ({
	name: t.name,
	minNumOfSources: t.minNumOfSources,
	"sources-identifiers": list(t.sourcesIdentifiers),
});

const trustedFromV1 = (t) => ({
	name: t.name,
	minNumOfSources: t.minNumOfSources ?? 3,
	sourcesIdentifiers: list(t["sources-identifiers"] ?? t.sourcesIdentifiers),
});

const identifiersToV1 = (s) => ({
	name: s.name,
	identifiers: list(s.sourcesIdentifiers).map((i) =>
		defined({ "source-identifier": i.identifier, value: i.value?.length ? i.value : undefined }),
	),
});

const identifiersFromV1 = (s) => ({
	name: s.name,
	sourcesIdentifiers: list(s.identifiers ?? s.sourcesIdentifiers).map((i) =>
		defined({ identifier: i["source-identifier"] ?? i.identifier, value: i.value }),
	),
});

// ---------------------------------------------------------------- documents

/**
 * A v1beta2 document as v1beta1 (what v1beta1 lacks is left out: check needsV2 first).
 * @param {object} doc
 */
const PROTECTIONS = ["csrfProtection", "errorDisclosure", "openRedirect"];

/**
 * v1beta1 has no "inherited" for the protections of a practice (CSRF, error disclosure, open
 * redirect: the agent takes it as inactive), v1beta2 takes the mode of the rule. A rule gets a copy
 * "<practice>.<mode>" with the mode of the rule where the practice inherits one.
 */
const resolveProtections = (doc) => {
	const practices = new Map(list(doc.threatPreventionPractices).map((p) => [p.name, p]));
	const copies = new Map();
	const resolve = (rule) => {
		if (!rule?.threatPreventionPractices) return rule;
		const mode = rule.mode ?? doc.policies?.default?.mode ?? "inactive";
		const names = rule.threatPreventionPractices.map((name) => {
			const practice = practices.get(name);
			const inherited = PROTECTIONS.filter((k) => practice?.webAttacks?.protections?.[k] === "inherited");
			if (!inherited.length) return name;
			const copy = `${name}.${mode}`;
			if (!practices.has(copy) && !copies.has(copy)) {
				const derived = structuredClone(practice);
				derived.name = copy;
				for (const k of inherited) derived.webAttacks.protections[k] = mode;
				copies.set(copy, derived);
			}
			return copy;
		});
		return { ...rule, threatPreventionPractices: names };
	};
	const policies = {
		default: resolve(doc.policies?.default || {}),
		specificRules: list(doc.policies?.specificRules).map(resolve),
	};
	return {
		...doc,
		policies,
		threatPreventionPractices: [...list(doc.threatPreventionPractices), ...copies.values()],
	};
};

export const toV1 = (input) => {
	const doc = resolveProtections(input);
	return defined({
		policies: {
			default: ruleToV1(doc.policies?.default || {}),
			"specific-rules": list(doc.policies?.specificRules).map(ruleToV1),
		},
		practices: list(doc.threatPreventionPractices).map(practiceToV1),
		"log-triggers": list(doc.logTriggers).map(triggerToV1),
		"custom-responses": list(doc.customResponses).map(responseToV1),
		exceptions: list(doc.exceptions).map(exceptionToV1),
		"trusted-sources": list(doc.trustedSources).map(trustedToV1),
		"source-identifiers": list(doc.sourcesIdentifiers).map(identifiersToV1),
	});
};

const V1_KEYS = ["practices", "log-triggers", "custom-responses", "trusted-sources", "source-identifiers"];

/** a document (or fragment) in v1beta1 syntax? Parts written in v1beta2 terms are kept as they are */
export const isV1 = (doc) =>
	isObject(doc) &&
	doc.apiVersion !== "v1beta2" &&
	(V1_KEYS.some((k) => k in doc) || "specific-rules" in (doc.policies || {}));

/**
 * A document or fragment of either syntax in v1beta2 terms. Items already in v1beta2 terms pass
 * (each converter reads both spellings), so mixed fragments work.
 */
export const fromV1 = (doc) => {
	if (!isObject(doc)) return {};
	const out = {};
	if (isObject(doc.policies)) {
		out.policies = {};
		if (doc.policies.default) out.policies.default = ruleFromV1(doc.policies.default);
		const rules = doc.policies["specific-rules"] ?? doc.policies.specificRules;
		if (rules) out.policies.specificRules = list(rules).map(ruleFromV1);
	}
	const section = (v1, v2, convert) => {
		const items = doc[v1] ?? doc[v2];
		if (items !== undefined) out[v2] = list(items).map((i) => (v1 in doc ? convert(i) : i));
	};
	section("practices", "threatPreventionPractices", practiceFromV1);
	if (doc.accessControlPractices) out.accessControlPractices = list(doc.accessControlPractices);
	section("log-triggers", "logTriggers", triggerFromV1);
	section("custom-responses", "customResponses", responseFromV1);
	if (doc.exceptions !== undefined) out.exceptions = list(doc.exceptions).map(exceptionFromV1);
	section("trusted-sources", "trustedSources", trustedFromV1);
	section("source-identifiers", "sourcesIdentifiers", identifiersFromV1);
	return out;
};

/** the active ("not inactive") state of a mode of v1beta2 */
const active = (mode) => mode !== undefined && mode !== "inactive";

/**
 * Why a v1beta2 document can't be written as v1beta1 (empty: it can).
 * @returns {string[]} reasons
 */
export const needsV2 = (doc) => {
	const reasons = [];
	const rules = [doc.policies?.default, ...list(doc.policies?.specificRules)].filter(Boolean);
	const used = (field) => new Set(rules.flatMap((r) => (Array.isArray(r[field]) ? r[field] : [r[field]])));
	const accessUsed = used("accessControlPractices");
	for (const p of list(doc.accessControlPractices)) {
		if (accessUsed.has(p.name) && active(p.rateLimit?.overrideMode) && list(p.rateLimit?.rules).length) {
			reasons.push(`rate-limit:${p.name}`);
		}
	}
	const responses = used("customResponse");
	for (const r of list(doc.customResponses)) {
		if (responses.has(r.name) && r.mode === "redirect") reasons.push(`redirect:${r.name}`);
	}
	const practices = used("threatPreventionPractices");
	for (const p of list(doc.threatPreventionPractices)) {
		if (!practices.has(p.name)) continue;
		if (active(p.intrusionPrevention?.overrideMode)) reasons.push(`ips:${p.name}`);
		if (active(p.fileSecurity?.overrideMode)) reasons.push(`file-security:${p.name}`);
	}
	return reasons;
};

/** rules whose exceptions after the first are ignored by the agent in v1beta2 */
export const v2ExceptionLimits = (doc) =>
	[doc.policies?.default, ...list(doc.policies?.specificRules)]
		.filter((r) => r && list(r.exceptions).length > 1)
		.map((r) => r.name || r.host || "default");

/** a v1beta2 document ready to write: apiVersion first */
export const asV2 = (doc) => ({ apiVersion: "v1beta2", ...doc });

export { SECTIONS_V2 };
