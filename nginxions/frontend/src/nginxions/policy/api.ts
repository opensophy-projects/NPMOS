// WAF → Policy (ADR-0008): objects of the open-appsec policy, the default policy, preview of a change,
// versions, import and export. Specifications are in the terms of local_policy.yaml v1beta2
// (webAttacks, "local-tuning"), so this client sends and reads JSON as it is: the common API client
// converts keys between camelCase and snake_case.
import * as base from "src/api/backend/base";
import AuthStore from "src/modules/AuthStore";
import { isNotJson, notJsonError } from "../apiErrors";

export type Kind =
	| "threat_prevention"
	| "access_control"
	| "log_trigger"
	| "custom_response"
	| "exception"
	| "trusted_sources"
	| "source_identifiers";

export const KINDS: Kind[] = [
	"threat_prevention",
	"access_control",
	"log_trigger",
	"custom_response",
	"exception",
	"trusted_sources",
	"source_identifiers",
];

type PolicyMode = "prevent-learn" | "detect-learn" | "prevent" | "detect" | "inactive";
export const POLICY_MODES: PolicyMode[] = ["prevent-learn", "detect-learn", "prevent", "detect", "inactive"];

export interface PolicyObject {
	id: number;
	kind: Kind;
	name: string;
	description: string;
	spec: Record<string, any>;
	builtin: boolean;
	created_on?: string;
	modified_on?: string;
}

/** references of a rule (default policy, host) to objects */
export interface RuleRefs {
	threatPreventionPractices?: number[];
	accessControlPractices?: number[];
	triggers?: number[];
	exceptions?: number[];
	customResponse?: number | null;
	sourceIdentifiers?: number | null;
	trustedSources?: number | null;
}

/** field of a rule → kind of the objects it refers to, list or one */
export const RULE_FIELDS: Record<keyof RuleRefs, { kind: Kind; many: boolean }> = {
	threatPreventionPractices: { kind: "threat_prevention", many: true },
	accessControlPractices: { kind: "access_control", many: true },
	triggers: { kind: "log_trigger", many: true },
	customResponse: { kind: "custom_response", many: false },
	exceptions: { kind: "exception", many: true },
	sourceIdentifiers: { kind: "source_identifiers", many: false },
	trustedSources: { kind: "trusted_sources", many: false },
};

export interface DefaultPolicy extends RuleRefs {
	mode: PolicyMode;
}

/** what the agent applies compared with the generated policy (backend waf/applied.js) */
export interface AppliedCheck {
	status: "ok" | "drift" | "pending" | "unknown";
	/** "asset:<host>", "response:<name>", "rate-limit:<practice>" */
	drift?: string[];
	modifiedAt?: string | null;
	error?: string;
}

interface PolicyState {
	file: string;
	generatedAt: string | null;
	hosts: number;
	/** always v1beta2: the agent of NginxionS applies every field of it (docs/WAF-POLICY.md) */
	format: "v1beta2" | null;
	/** "missing:<rule>:<name>", "extra:<rule>:<field>" (the agent takes the first), "unsupported:<object>:<engine>" */
	warnings: string[];
	applied: { ok: boolean; at: string; error: string | null } | null;
	check?: AppliedCheck;
}

export interface PolicyObjects {
	objects: PolicyObject[];
	policy: DefaultPolicy;
	templates: Record<string, DefaultPolicy>;
	state: PolicyState;
}

export interface DiffLine {
	op: " " | "+" | "-";
	line: string;
}

/** dry run of a change on recent WAF events (backend waf/objects/simulate.js) */
export interface Simulation {
	/** trial: the hours of a trial of blocking on a host */
	period: "1h" | "24h" | "7d" | "trial";
	error?: string;
	limited?: boolean;
	events?: number;
	changed?: number;
	toPass?: number;
	toBlock?: number;
	toDetect?: number;
	/** events the dry run cannot judge (a condition the events do not record, e.g. the country code) */
	unknown?: number;
	samples?: {
		host: string;
		uri: string;
		source_ip: string;
		time: string;
		confidence: string;
		before: Verdict;
		after: Verdict;
		count: number;
	}[];
}
export type Verdict = "pass" | "detect" | "block";

export interface Preview {
	valid: boolean;
	error?: string;
	changed?: boolean;
	diff?: DiffLine[];
	format?: "v1beta2";
	warnings?: string[];
	simulation?: Simulation | null;
}

export type Change =
	| { object: ObjectInput; id?: number }
	| { delete: number }
	| { policy: DefaultPolicy }
	| { host: { id: number; objects: HostObjects | null } };

interface ObjectInput {
	kind: Kind;
	name: string;
	description?: string;
	spec: Record<string, any>;
}

/** objects of a host: a template (built-in objects) or references; null: as the default policy */
export type HostObjects = ({ template?: string } & RuleRefs) | null;

export interface PolicyVersion {
	id: number;
	comment: string;
	created_on: string;
	user: string | null;
}

export interface ImportResult {
	applied: boolean;
	create: string[];
	update: string[];
	skipped: string[];
	errors: string[];
	/** left out on purpose: Kubernetes, the cloud, engines of the Premium edition, extra practices of a rule */
	dropped: string[];
	policy: Record<string, any> | null;
	rules: number;
	state?: PolicyState;
}

const request = async <T>(method: string, url: string, data?: unknown): Promise<T> => {
	const response = await fetch(`/api/nginxions/waf/policy${url}`, {
		method,
		headers: data === undefined ? {} : { "Content-Type": "application/json" },
		body: data === undefined ? undefined : JSON.stringify(data),
	});
	if (isNotJson(response)) throw notJsonError(response);
	const payload = await response.json();
	if (!response.ok) {
		if (response.status === 401) {
			AuthStore.clear();
			window.location.reload();
		}
		throw new Error(payload?.error?.message || response.statusText);
	}
	return payload as T;
};

/** an OpenAPI file of schemaValidation */
export interface SchemaFile {
	name: string;
	size: number;
	modifiedOn: string;
	version: string;
	title: string;
	paths: number;
	/** practices that name it */
	usedBy: string[];
}
export const getSchemaFiles = () => request<SchemaFile[]>("GET", "/schemas");
export const uploadSchemaFile = async (name: string, file: Blob) => {
	const response = await fetch(`/api/nginxions/waf/policy/schemas/${encodeURIComponent(name)}`, {
		method: "PUT",
		headers: { "Content-Type": "application/octet-stream" },
		body: file,
	});
	if (isNotJson(response)) throw notJsonError(response);
	const payload = await response.json();
	if (!response.ok) throw new Error(payload?.error?.message || response.statusText);
	return payload as SchemaFile;
};
export const deleteSchemaFile = (name: string) => request<boolean>("DELETE", `/schemas/${encodeURIComponent(name)}`);
export const downloadSchemaFile = (name: string) =>
	base.download({ url: `/nginxions/waf/policy/schemas/${encodeURIComponent(name)}` }, name);

export const getPolicyObjects = () => request<PolicyObjects>("GET", "/objects");
export const createObject = (data: ObjectInput) =>
	request<PolicyObject & { state: PolicyState }>("POST", "/objects", data);
export const updateObject = (id: number, data: ObjectInput) =>
	request<PolicyObject & { state: PolicyState }>("PUT", `/objects/${id}`, data);
export const deleteObject = (id: number) => request<{ state: PolicyState }>("DELETE", `/objects/${id}`);
export const setDefaultPolicy = (policy: DefaultPolicy) =>
	request<{ policy: DefaultPolicy; state: PolicyState }>("PUT", "/default", policy);
export const previewChange = (change: Change) => request<Preview>("POST", "/preview", change);
export const getVersions = () => request<PolicyVersion[]>("GET", "/versions");
export const rollbackVersion = (id: number) => request<{ state: PolicyState }>("POST", `/versions/${id}/rollback`);
export const importPolicy = (content: string, dryRun: boolean) =>
	request<ImportResult>("POST", `/import${dryRun ? "?dry_run=true" : ""}`, { content });
export const exportPolicy = (format: "v1beta2" | "v1beta1") =>
	base.download({ url: "/nginxions/waf/policy/export", params: { format } }, `nginxions-waf-policy-${format}.yaml`);

/** a YAML document of the policy as text: all of it, or the objects of one section (Agents → open-appsec → Code) */
export const getPolicyCode = async (section?: string) => {
	const params = new URLSearchParams({ format: "v1beta2", ...(section ? { section } : {}) });
	const response = await fetch(`/api/nginxions/waf/policy/export?${params}`);
	if (!response.ok) throw new Error(response.statusText);
	return response.text();
};

export const getHostCode = (id: number) =>
	base.get({ url: `/nginxions/waf/hosts/${id}/code` }) as Promise<{ content: string }>;
export const putHostCode = (id: number, content: string, dryRun: boolean) =>
	base.put({ url: `/nginxions/waf/hosts/${id}/code`, data: { content, dryRun } }) as Promise<{
		valid: boolean;
		error?: string;
		applied?: boolean;
	}>;
