// Objects of the open-appsec policy (WAF → Policy, docs/ROADMAP.md phase 5) in the terms of v1beta2:
// what each kind is, how its specification is completed and checked (the schema of open-appsec),
// the built-in objects and the templates made of them. Pure functions, no database.
import Ajv from "ajv/dist/2020.js";
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
export const BUILTIN_PREFIX = "npmos-";

const itemSchema = (kind) => schema.properties[KINDS[kind]].items;

const ajv = new Ajv({ allErrors: true, strict: false, allowUnionTypes: true });
const validators = Object.fromEntries(Object.keys(KINDS).map((kind) => [kind, ajv.compile(itemSchema(kind))]));

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Fills what is missing from the defaults of the schema; nested objects of the schema are created
 * (every one of them has defaults), lists are not.
 */
export const withDefaults = (node, value) => {
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
		// NPMOS reads the agent's log files: never the Check Point cloud, always stdout
		s.logDestination = { ...s.logDestination, cloud: false };
		if (!s.logDestination.stdout) s.logDestination.stdout = { format: "json" };
		return s;
	},
	exception: (s) => ({ ...s, condition: Array.isArray(s.condition) ? s.condition : [] }),
};

/**
 * A complete specification of an object of a kind, or the problems found.
 * @returns {{spec?: object, errors?: string[]}}
 */
export const normalize = (kind, input) => {
	if (!KINDS[kind]) return { errors: [`unknown kind ${kind}`] };
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
	return { spec };
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
	// Premium edition of the agent only
	intrusionPrevention: { overrideMode: "inactive" },
	fileSecurity: { overrideMode: "inactive" },
	snortSignatures: { overrideMode: "inactive", files: [] },
	schemaValidation: { overrideMode: "inactive", files: [] },
	antiBot: { overrideMode: "inactive", injectedUris: [], validatedUris: [] },
});

/** name → {kind, spec}; created at start, updated with NPMOS, read-only in the GUI */
export const BUILTIN = {
	"npmos-recommended": { kind: "threat_prevention", spec: practice() },
	"npmos-strict": {
		kind: "threat_prevention",
		spec: practice({ confidence: "medium", strictProtections: true, methods: true }),
	},
	"npmos-api": { kind: "threat_prevention", spec: practice({ methods: true }) },
	"npmos-no-rate-limit": {
		kind: "access_control",
		spec: { practiceMode: "inherited", rateLimit: { overrideMode: "inactive", rules: [] } },
	},
	"npmos-log": {
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
	"npmos-403": { kind: "custom_response", spec: { mode: "response-code-only", httpResponseCode: 403 } },
	"npmos-block-page": {
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
		threatPreventionPractices: ["npmos-recommended"],
		accessControlPractices: ["npmos-no-rate-limit"],
		triggers: ["npmos-log"],
		customResponse: "npmos-403",
	},
	strict: {
		mode: "prevent-learn",
		threatPreventionPractices: ["npmos-strict"],
		accessControlPractices: ["npmos-no-rate-limit"],
		triggers: ["npmos-log"],
		customResponse: "npmos-block-page",
	},
	monitor: {
		mode: "detect-learn",
		threatPreventionPractices: ["npmos-recommended"],
		accessControlPractices: ["npmos-no-rate-limit"],
		triggers: ["npmos-log"],
		customResponse: "npmos-403",
	},
	api: {
		mode: "prevent-learn",
		threatPreventionPractices: ["npmos-api"],
		accessControlPractices: ["npmos-no-rate-limit"],
		triggers: ["npmos-log"],
		customResponse: "npmos-403",
	},
};

/** the default policy before the administrator changes it: everything not protected is inactive */
export const DEFAULT_POLICY = {
	mode: "inactive",
	threatPreventionPractices: ["npmos-recommended"],
	accessControlPractices: ["npmos-no-rate-limit"],
	triggers: ["npmos-log"],
	customResponse: "npmos-403",
	sourceIdentifiers: null,
	trustedSources: null,
	exceptions: [],
};

/** the complete specification of a built-in object */
export const builtinSpec = (name) => normalize(BUILTIN[name].kind, BUILTIN[name].spec).spec;
