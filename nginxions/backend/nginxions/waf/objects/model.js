// Objects of the open-appsec policy (WAF → Policy, docs/ROADMAP.md phase 5) in the terms of v1beta2:
// what each kind is, how its specification is completed and checked (the schema of open-appsec),
// the built-in objects and the templates made of them. Pure functions, no database.
import Ajv from "ajv/dist/2020.js";
import { EXCEPTION_KEYS, EXCEPTION_OPS } from "./format.js";
import schema from "./schema-v1beta2.json" with { type: "json" };

/** kind → section of local_policy.yaml (v1beta2) */
export const KINDS = {
	threat_prevention: "threatPreventionPractices",
	access_control: "accessControlPractices",
	log_trigger: "logTriggers",
	custom_response: "customResponses",
	exception: "exceptions",
	trusted_sources: "trustedSources",
	source_identifiers: "sourcesIdentifiers",
};

/** fields of a rule (default policy, host) that point to objects: kind and list or single */
export const RULE_FIELDS = {
	threatPreventionPractices: { kind: "threat_prevention", many: true },
	accessControlPractices: { kind: "access_control", many: true },
	triggers: { kind: "log_trigger", many: true },
	customResponse: { kind: "custom_response", many: false },
	sourceIdentifiers: { kind: "source_identifiers", many: false },
	trustedSources: { kind: "trusted_sources", many: false },
	exceptions: { kind: "exception", many: true },
};

export const POLICY_MODES = ["prevent-learn", "detect-learn", "prevent", "detect", "inactive"];
export const NAME = /^[a-z0-9]([a-z0-9._-]{0,98}[a-z0-9])?$/;
/** names of built-in objects; not available to the administrator's objects */
export const BUILTIN_PREFIX = "nginxions-";

const itemSchema = (kind) => schema.properties[KINDS[kind]].items;

const ajv = new Ajv({ allErrors: true, strict: false, allowUnionTypes: true });
const validators = Object.fromEntries(Object.keys(KINDS).map((kind) => [kind, ajv.compile(itemSchema(kind))]));

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Fills what is missing from the defaults of the schema; nested objects of the schema are created
 * (every one of them has defaults), lists are not.
 */
const withDefaults = (node, value) => {
	if (node?.type === "object" || node?.properties) {
		const out = isObject(value) ? { ...value } : {};
		for (const [key, child] of Object.entries(node.properties || {})) {
			if (key === "name" || key === "appsecClassName") continue;
			if (out[key] === undefined) {
				if (child.default !== undefined) out[key] = structuredClone(child.default);
				else if (child.type === "object" && child.properties) out[key] = withDefaults(child, undefined);
			} else if (child.type === "object") {
				out[key] = withDefaults(child, out[key]);
			}
		}
		return out;
	}
	return value;
};

/** the schema has defaults that are not values (customResponse "403" is a name) */
const fixups = {
	log_trigger: (s) => {
		// NginxionS reads the agent's log files: never the Check Point cloud, always stdout
		s.logDestination = { ...s.logDestination, cloud: false };
		if (!s.logDestination.stdout) s.logDestination.stdout = { format: "json" };
		return s;
	},
	exception: (s) => ({ ...s, condition: Array.isArray(s.condition) ? s.condition : [] }),
};

// ---------------------------------------------------------------- what the agent applies (docs/WAF-POLICY.md)

/**
 * Engines of a threat prevention practice NginxionS does not run yet (File Security is of the Premium edition of
 * open-appsec). The IPS has the signatures of NginxionS (CrowdSec virtual patching rules, waf/ips/vpatch.js) in place
 * of the ones of the Check Point cloud; antiBot and schemaValidation run in AppSec of CrowdSec (waf/engines.js).
 */
export const UNSUPPORTED_ENGINES = ["fileSecurity"];
/** a name of an OpenAPI file of schemaValidation (waf/schemas.js) */
const SCHEMA_FILE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.(ya?ml|json)$/;
/** a path of antiBot */
const URI = /^\/[^\s"\\]{0,1023}$/;
/** keys of a condition of a rate limit rule: what the rate limit engine matches (rate_limit.cc) */
export const RATE_LIMIT_KEYS = ["sourceIp", "sourceIdentifier", "countryCode", "countryName", "url"];
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/**
 * What a specification asks of the agent that it does not do: errors (it would be silently left out) and
 * parts dropped on purpose (Kubernetes: configmaps; the cloud).
 */
const unsupported = (kind, spec, lenient) => {
	const errors = [];
	const dropped = [];
	if (kind === "threat_prevention") {
		for (const engine of UNSUPPORTED_ENGINES) {
			const mode = spec[engine]?.overrideMode;
			if (!mode || mode === "inactive") continue;
			if (lenient) {
				// an imported file (the examples of open-appsec leave them "inherited"): turned off and named
				spec[engine].overrideMode = "inactive";
				dropped.push(`/${engine}`);
			} else {
				errors.push(`/${engine}: not in the agent of NginxionS (Premium edition or the Check Point cloud)`);
			}
		}
		// antiBot: paths ({uri} as in v1beta2; a plain string is taken too)
		for (const list of ["injectedUris", "validatedUris"]) {
			if (!spec.antiBot || !Array.isArray(spec.antiBot[list])) continue;
			spec.antiBot[list] = spec.antiBot[list].map((u) => (typeof u === "string" ? { uri: u } : u));
			spec.antiBot[list].forEach((u, i) => {
				if (!URI.test(String(u?.uri ?? ""))) errors.push(`/antiBot/${list}/${i}: a path that starts with /`);
			});
		}
		// schemaValidation: names of the OpenAPI files of WAF -> Policy
		if (spec.schemaValidation) {
			(spec.schemaValidation.files || []).forEach((f, i) => {
				if (!SCHEMA_FILE.test(String(f))) {
					errors.push(`/schemaValidation/files/${i}: the name of an OpenAPI file (api.yaml, api.json)`);
				}
			});
			const level = spec.schemaValidation.enforcementLevel;
			if (level !== undefined && level !== "" && !["fullSchema", "endpointOnly"].includes(level)) {
				errors.push("/schemaValidation/enforcementLevel: fullSchema or endpointOnly");
			}
			const mode = spec.schemaValidation.overrideMode;
			if (mode && mode !== "inactive" && !(spec.schemaValidation.files || []).length && !lenient) {
				errors.push("/schemaValidation/files: an OpenAPI file is needed to validate requests");
			}
		}
		for (const engine of ["snortSignatures", "schemaValidation"]) {
			if (Array.isArray(spec[engine]?.configmap) && spec[engine].configmap.length)
				dropped.push(`/${engine}/configmap`);
			if (spec[engine]) delete spec[engine].configmap;
		}
	}
	if (kind === "access_control") {
		(spec.rateLimit?.rules || []).forEach((rule, i) => {
			(rule.condition || []).forEach((c, j) => {
				if (!RATE_LIMIT_KEYS.includes(c?.key)) {
					errors.push(`/rateLimit/rules/${i}/condition/${j}/key: one of ${RATE_LIMIT_KEYS.join(", ")}`);
				}
			});
		});
	}
	if (kind === "custom_response" && spec.mode === "redirect") {
		if (!/^(https?:\/\/[^\s]+|\/[^\s]*)$/.test(spec.redirectUrl || "")) {
			errors.push("/redirectUrl: a redirect needs a URL (http://, https:// or a path)");
		}
	}
	if (kind === "exception") {
		spec.condition.forEach((c, j) => {
			if (!EXCEPTION_KEYS.includes(c?.key))
				errors.push(`/condition/${j}/key: one of ${EXCEPTION_KEYS.join(", ")}`);
			if (c?.op !== undefined && !EXCEPTION_OPS.includes(c.op))
				errors.push(`/condition/${j}/op: one of ${EXCEPTION_OPS.join(", ")}`);
			// exist has no value; every other operator compares one
			if (c?.op === "exist") delete c.value;
			else if (typeof c?.value !== "string") errors.push(`/condition/${j}/value: a value is needed`);
		});
	}
	if (kind === "log_trigger") {
		const dest = spec.logDestination || {};
		for (const service of ["syslogService", "cefService"]) {
			const list = Array.isArray(dest[service]) ? dest[service] : dest[service] ? [dest[service]] : [];
			// the agent keeps one stream of each kind (logging.cc) and opens sockets to IPv4 addresses only
			if (list.length > 1) errors.push(`/logDestination/${service}: the agent sends to one server`);
			list.forEach((s, i) => {
				if (!IPV4.test(s?.address || ""))
					errors.push(`/logDestination/${service}/${i}/address: an IPv4 address`);
			});
		}
		if (dest["k8s-service"] !== undefined) {
			dropped.push("/logDestination/k8s-service");
			delete dest["k8s-service"];
		}
	}
	return { errors, dropped };
};

/**
 * A complete specification of an object of a kind, or the problems found. Every field either works in the agent
 * of NginxionS or is an error; what only Kubernetes or the cloud has is dropped and named.
 * @param {{lenient?: boolean}} [options]  lenient (an import): engines the agent does not have are turned off and
 *   named in dropped instead of being errors
 * @returns {{spec?: object, errors?: string[], dropped?: string[]}}
 */
export const normalize = (kind, input, { lenient = false } = {}) => {
	if (typeof kind !== "string" || !Object.hasOwn(KINDS, kind)) return { errors: [`unknown kind ${kind}`] };
	const { name, appsecClassName, ...rest } = isObject(input) ? input : {};
	let spec = withDefaults(itemSchema(kind), rest);
	if (fixups[kind]) spec = fixups[kind](spec);
	const validate = validators[kind];
	if (!validate({ name: "x", ...spec })) {
		return { errors: validate.errors.map((e) => `${e.instancePath || "/"} ${e.message}`) };
	}
	if (kind === "exception" && !spec.condition.length) {
		return { errors: ["/condition: an exception needs at least one condition"] };
	}
	const { errors, dropped } = unsupported(kind, spec, lenient);
	if (errors.length) return { errors };
	if (appsecClassName !== undefined) dropped.push("/appsecClassName");
	// NginxionS reads the logs of the agent: never to the Check Point cloud (fixups)
	if (kind === "log_trigger" && rest.logDestination?.cloud === true) dropped.push("/logDestination/cloud");
	return dropped.length ? { spec, dropped } : { spec };
};

// ---------------------------------------------------------------- built-in objects

const practice = ({ confidence = "high", strictProtections = false, methods = false } = {}) => ({
	practiceMode: "inherited",
	webAttacks: {
		overrideMode: "inherited",
		minimumConfidence: confidence,
		protections: {
			csrfProtection: strictProtections ? "inherited" : "inactive",
			errorDisclosure: strictProtections ? "inherited" : "inactive",
			openRedirect: strictProtections ? "inherited" : "inactive",
			nonValidHttpMethods: methods,
		},
	},
	// off unless chosen (signatures of known vulnerabilities, NginxionS)
	intrusionPrevention: { overrideMode: "inactive" },
	fileSecurity: { overrideMode: "inactive" },
	snortSignatures: { overrideMode: "inactive", files: [] },
	schemaValidation: { overrideMode: "inactive", files: [] },
	antiBot: { overrideMode: "inactive", injectedUris: [], validatedUris: [] },
});

/** name → {kind, spec}; created at start, updated with NginxionS, read-only in the GUI */
export const BUILTIN = {
	// non-standard methods blocked: the agent blocked them always until it read the setting (openappsec/agent,
	// PracticeAdvancedConfig), the recommended practice keeps that
	"nginxions-recommended": { kind: "threat_prevention", spec: practice({ methods: true }) },
	"nginxions-strict": {
		kind: "threat_prevention",
		spec: practice({ confidence: "medium", strictProtections: true, methods: true }),
	},
	"nginxions-api": { kind: "threat_prevention", spec: practice({ methods: true }) },
	"nginxions-no-rate-limit": {
		kind: "access_control",
		spec: { practiceMode: "inherited", rateLimit: { overrideMode: "inactive", rules: [] } },
	},
	"nginxions-log": {
		kind: "log_trigger",
		spec: {
			accessControlLogging: { allowEvents: false, dropEvents: true },
			appsecLogging: { detectEvents: true, preventEvents: true, allWebRequests: false },
			additionalSuspiciousEventsLogging: {
				enabled: true,
				minSeverity: "high",
				responseBody: false,
				responseCode: true,
			},
			extendedLogging: { urlPath: true, urlQuery: true, httpHeaders: false, requestBody: false },
			logDestination: { cloud: false, "local-tuning": true, logToAgent: true, stdout: { format: "json" } },
		},
	},
	"nginxions-403": { kind: "custom_response", spec: { mode: "response-code-only", httpResponseCode: 403 } },
	"nginxions-block-page": {
		kind: "custom_response",
		spec: {
			mode: "block-page",
			httpResponseCode: 403,
			messageTitle: "Access denied",
			messageBody: "The request was blocked by the web application firewall.",
		},
	},
};

/** templates of the policy of a host: a mode and built-in objects */
export const TEMPLATES = {
	recommended: {
		mode: "prevent-learn",
		threatPreventionPractices: ["nginxions-recommended"],
		accessControlPractices: ["nginxions-no-rate-limit"],
		triggers: ["nginxions-log"],
		customResponse: "nginxions-403",
	},
	strict: {
		mode: "prevent-learn",
		threatPreventionPractices: ["nginxions-strict"],
		accessControlPractices: ["nginxions-no-rate-limit"],
		triggers: ["nginxions-log"],
		customResponse: "nginxions-block-page",
	},
	monitor: {
		mode: "detect-learn",
		threatPreventionPractices: ["nginxions-recommended"],
		accessControlPractices: ["nginxions-no-rate-limit"],
		triggers: ["nginxions-log"],
		customResponse: "nginxions-403",
	},
	api: {
		mode: "prevent-learn",
		threatPreventionPractices: ["nginxions-api"],
		accessControlPractices: ["nginxions-no-rate-limit"],
		triggers: ["nginxions-log"],
		customResponse: "nginxions-403",
	},
};

/** the default policy before the administrator changes it: everything not protected is inactive */
export const DEFAULT_POLICY = {
	mode: "inactive",
	threatPreventionPractices: ["nginxions-recommended"],
	accessControlPractices: ["nginxions-no-rate-limit"],
	triggers: ["nginxions-log"],
	customResponse: "nginxions-403",
	sourceIdentifiers: null,
	trustedSources: null,
	exceptions: [],
};

/** the complete specification of a built-in object */
export const builtinSpec = (name) => normalize(BUILTIN[name].kind, BUILTIN[name].spec).spec;
