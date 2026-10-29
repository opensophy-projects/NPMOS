// Fields of the editor of each kind of object (WAF → Policy), from the schema of local_policy.yaml
// v1beta2 (npmos/backend/npmos/waf/objects/schema-v1beta2.json). Labels are the locale keys
// npmos.policy.f.<path>; what the form does not show is kept as it is (the backend completes it).
import type { Kind } from "./api";

export const MODES = ["prevent-learn", "detect-learn", "prevent", "detect", "inactive", "inherited"];
const ACTIONS = ["prevent", "detect", "inactive", "inherited"];

export const EXCEPTION_KEYS = [
	"sourceIp",
	"url",
	"hostName",
	"paramName",
	"paramValue",
	"protectionName",
	"countryCode",
	"countryName",
	"sourceIdentifier",
];

export type Field = {
	path: string;
	/** shown only for these values of the specification */
	showIf?: (spec: Record<string, any>) => boolean;
	/** a feature of the Premium edition of the agent: a note next to the field */
	premium?: boolean;
	/** needs local_policy.yaml v1beta2 (see the warning of the format) */
	v2?: boolean;
} & (
	| { type: "select"; options: string[]; modes?: boolean /** locale prefix of the options */; labels?: string }
	| { type: "bool" }
	| { type: "number"; min?: number; max?: number }
	| { type: "text" | "textarea" }
	| { type: "strings" }
	| { type: "conditions" }
	| { type: "rateRules" }
	| { type: "identifiers" }
	| { type: "names"; kind: Kind }
	| { type: "heading" }
);

export const FIELDS: Record<Kind, Field[]> = {
	threat_prevention: [
		{ path: "webAttacks", type: "heading" },
		{ path: "webAttacks.overrideMode", type: "select", options: MODES, modes: true },
		{
			path: "webAttacks.minimumConfidence",
			type: "select",
			options: ["medium", "high", "critical"],
			labels: "npmos.policy.confidence.",
		},
		{ path: "webAttacks.protections.csrfProtection", type: "select", options: MODES, modes: true },
		{ path: "webAttacks.protections.errorDisclosure", type: "select", options: MODES, modes: true },
		{ path: "webAttacks.protections.openRedirect", type: "select", options: MODES, modes: true },
		{ path: "webAttacks.protections.nonValidHttpMethods", type: "bool" },
		{ path: "webAttacks.maxUrlSizeBytes", type: "number", min: 1 },
		{ path: "webAttacks.maxHeaderSizeBytes", type: "number", min: 1 },
		{ path: "webAttacks.maxBodySizeKb", type: "number", min: 1 },
		{ path: "webAttacks.maxObjectDepth", type: "number", min: 1 },
		{ path: "snortSignatures", type: "heading" },
		{ path: "snortSignatures.overrideMode", type: "select", options: MODES, modes: true },
		{ path: "snortSignatures.files", type: "strings" },
		{ path: "premium", type: "heading" },
		{
			path: "intrusionPrevention.overrideMode",
			type: "select",
			options: MODES,
			modes: true,
			premium: true,
			v2: true,
		},
		{ path: "fileSecurity.overrideMode", type: "select", options: MODES, modes: true, premium: true, v2: true },
		{ path: "schemaValidation.overrideMode", type: "select", options: MODES, modes: true, premium: true },
		{ path: "antiBot.overrideMode", type: "select", options: MODES, modes: true, premium: true },
	],
	access_control: [
		{ path: "rateLimit.overrideMode", type: "select", options: ACTIONS, modes: true, v2: true },
		{ path: "rateLimit.rules", type: "rateRules" },
	],
	log_trigger: [
		{ path: "appsecLogging", type: "heading" },
		{ path: "appsecLogging.detectEvents", type: "bool" },
		{ path: "appsecLogging.preventEvents", type: "bool" },
		{ path: "appsecLogging.allWebRequests", type: "bool" },
		{ path: "accessControlLogging.allowEvents", type: "bool" },
		{ path: "accessControlLogging.dropEvents", type: "bool" },
		{ path: "additionalSuspiciousEventsLogging", type: "heading" },
		{ path: "additionalSuspiciousEventsLogging.enabled", type: "bool" },
		{
			path: "additionalSuspiciousEventsLogging.minSeverity",
			type: "select",
			options: ["high", "critical"],
			labels: "npmos.policy.confidence.",
			showIf: (s) => !!s.additionalSuspiciousEventsLogging?.enabled,
		},
		{ path: "additionalSuspiciousEventsLogging.responseCode", type: "bool" },
		{ path: "additionalSuspiciousEventsLogging.responseBody", type: "bool" },
		{ path: "extendedLogging", type: "heading" },
		{ path: "extendedLogging.urlPath", type: "bool" },
		{ path: "extendedLogging.urlQuery", type: "bool" },
		{ path: "extendedLogging.httpHeaders", type: "bool" },
		{ path: "extendedLogging.requestBody", type: "bool" },
	],
	custom_response: [
		{
			path: "mode",
			type: "select",
			options: ["response-code-only", "block-page", "redirect"],
			labels: "npmos.policy.response.",
		},
		{ path: "httpResponseCode", type: "number", min: 100, max: 599, showIf: (s) => s.mode !== "redirect" },
		{ path: "messageTitle", type: "text", showIf: (s) => s.mode === "block-page" },
		{ path: "messageBody", type: "textarea", showIf: (s) => s.mode === "block-page" },
		{ path: "redirectUrl", type: "text", showIf: (s) => s.mode === "redirect", v2: true },
		{ path: "redirectAddXEventId", type: "bool", showIf: (s) => s.mode === "redirect" },
	],
	exception: [
		{
			path: "action",
			type: "select",
			options: ["accept", "drop", "skip", "suppressLog"],
			labels: "npmos.policy.action.",
		},
		{ path: "condition", type: "conditions" },
	],
	trusted_sources: [
		{ path: "minNumOfSources", type: "number", min: 1 },
		{ path: "sourcesIdentifiers", type: "names", kind: "source_identifiers" },
	],
	source_identifiers: [{ path: "sourcesIdentifiers", type: "identifiers" }],
};

/** a new object: the backend completes the rest from the defaults of the schema */
export const NEW_SPEC: Record<Kind, () => Record<string, any>> = {
	threat_prevention: () => ({
		practiceMode: "inherited",
		webAttacks: { overrideMode: "inherited", minimumConfidence: "high" },
	}),
	access_control: () => ({ practiceMode: "inherited", rateLimit: { overrideMode: "inherited", rules: [] } }),
	log_trigger: () => ({ extendedLogging: { urlPath: true, urlQuery: true } }),
	custom_response: () => ({ mode: "response-code-only", httpResponseCode: 403 }),
	exception: () => ({ action: "accept", condition: [{ key: "sourceIp", value: "" }] }),
	trusted_sources: () => ({ minNumOfSources: 3, sourcesIdentifiers: [] }),
	source_identifiers: () => ({ sourcesIdentifiers: [{ identifier: "sourceip", value: [] }] }),
};

export const getPath = (obj: Record<string, any>, path: string) =>
	path.split(".").reduce<any>((o, k) => (o == null ? undefined : o[k]), obj);

export const setPath = (obj: Record<string, any>, path: string, value: unknown) => {
	const out = structuredClone(obj);
	const keys = path.split(".");
	let node: Record<string, any> = out;
	for (const k of keys.slice(0, -1)) {
		if (node[k] === null || typeof node[k] !== "object") node[k] = {};
		node = node[k];
	}
	node[keys[keys.length - 1]] = value;
	return out;
};

/** a short description of an object for the lists */
export const summary = (kind: Kind, spec: Record<string, any>): string[] => {
	switch (kind) {
		case "threat_prevention":
			return [spec.webAttacks?.overrideMode, spec.webAttacks?.minimumConfidence].filter(Boolean);
		case "access_control":
			return (spec.rateLimit?.rules || []).map((r: any) => `${r.uri} ${r.limit}/${r.unit}`);
		case "custom_response":
			return [spec.mode, spec.mode === "redirect" ? spec.redirectUrl : spec.httpResponseCode].filter(Boolean);
		case "exception":
			return [spec.action, ...(spec.condition || []).map((c: any) => `${c.key}=${c.value}`)];
		case "trusted_sources":
			return [`≥${spec.minNumOfSources}`, ...(spec.sourcesIdentifiers || [])];
		case "source_identifiers":
			return (spec.sourcesIdentifiers || []).map((s: any) => s.identifier);
		default:
			return [];
	}
};
