// WAF → Policy (ADR-0008): objects of the open-appsec policy, the default policy, preview of a change,
// versions, import and export. Specifications are in the terms of local_policy.yaml v1beta2
// (webAttacks, "local-tuning"), so this client sends and reads JSON as it is: the common API client
// converts keys between camelCase and snake_case.
import * as base from "src/api/backend/base";
import AuthStore from "src/modules/AuthStore";

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

export type PolicyMode = "prevent-learn" | "detect-learn" | "prevent" | "detect" | "inactive";
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

export interface PolicyState {
	file: string;
	generatedAt: string | null;
	hosts: number;
	format: "v1beta1" | "v1beta2" | null;
	/** what needs v1beta2: "rate-limit:<name>", "redirect:<name>", "ips:<name>", "file-security:<name>" */
	reasons: string[];
	/** "exceptions:<rule>" (v1beta2 applies the first one), "missing:<rule>:<name>" */
	warnings: string[];
	applied: { ok: boolean; at: string; error: string | null } | null;
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

export interface Preview {
	valid: boolean;
	error?: string;
	changed?: boolean;
	diff?: DiffLine[];
	format?: "v1beta1" | "v1beta2";
	reasons?: string[];
	warnings?: string[];
}

export type Change =
	| { object: ObjectInput; id?: number }
	| { delete: number }
	| { policy: DefaultPolicy }
	| { host: { id: number; objects: HostObjects | null } };

export interface ObjectInput {
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
	policy: Record<string, any> | null;
	rules: number;
	state?: PolicyState;
}

const request = async <T>(method: string, url: string, data?: unknown): Promise<T> => {
	const response = await fetch(`/api/npmos/waf/policy${url}`, {
		method,
		headers: data === undefined ? {} : { "Content-Type": "application/json" },
		body: data === undefined ? undefined : JSON.stringify(data),
	});
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
	base.download({ url: "/npmos/waf/policy/export", params: { format } }, `npmos-waf-policy-${format}.yaml`);

/** a YAML document of the policy as text: all of it, or the objects of one section (Agents → open-appsec → Code) */
export const getPolicyCode = async (section?: string) => {
	const params = new URLSearchParams({ format: "v1beta2", ...(section ? { section } : {}) });
	const response = await fetch(`/api/npmos/waf/policy/export?${params}`);
	if (!response.ok) throw new Error(response.statusText);
	return response.text();
};

export const getHostCode = (id: number) =>
	base.get({ url: `/npmos/waf/hosts/${id}/code` }) as Promise<{ content: string }>;
export const putHostCode = (id: number, content: string, dryRun: boolean) =>
	base.put({ url: `/npmos/waf/hosts/${id}/code`, data: { content, dryRun } }) as Promise<{
		valid: boolean;
		error?: string;
		applied?: boolean;
	}>;
