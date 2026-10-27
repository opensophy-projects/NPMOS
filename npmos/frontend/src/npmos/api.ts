// NPMOS API client (/api/npmos/*), see npmos/backend/npmos/routes.js
import * as api from "src/api/backend/base";

export interface Service {
	id: string;
	service: string;
	name: string;
	image: string;
	version: string | null;
	state: "created" | "running" | "paused" | "restarting" | "removing" | "exited" | "dead";
	status: string;
	created: number;
	restartable: boolean;
}

export interface ServiceLogLine {
	stream: "stdout" | "stderr";
	line: string;
}

export interface RestartResult {
	service: string;
	restarted: boolean;
	restarting?: boolean;
}

export const getServices = (): Promise<Service[]> => api.get({ url: "/npmos/services" });

export const getServiceLogs = (service: string, tail = 200): Promise<ServiceLogLine[]> =>
	api.get({ url: `/npmos/services/${encodeURIComponent(service)}/logs`, params: { tail } });

export const restartService = (service: string): Promise<RestartResult> =>
	api.post({ url: `/npmos/services/${encodeURIComponent(service)}/restart` });

export const regenerateNginx = (): Promise<{ regenerated: boolean }> => api.post({ url: "/npmos/nginx/regenerate" });

export const downloadDiagnostics = () =>
	api.download({ url: "/npmos/diagnostics" }, `npmos-diagnostics-${new Date().toISOString().slice(0, 19)}.zip`);

export interface AgentStatus {
	reachable: boolean;
	error?: string;
	policyVersion?: string | null;
	lastPolicyUpdate?: string | null;
	lastUpdate?: string | null;
	lastUpdateStatus?: string | null;
	mode?: "local";
}

export interface WafPolicyState {
	file: string;
	generatedAt: string | null;
	hosts: number;
	applied: { ok: boolean; at: string; error: string | null } | null;
}

export interface WafStatus {
	enabled: boolean;
	active: boolean;
	restartRequired: boolean;
	restarting?: boolean;
	agent?: AgentStatus;
	policy?: WafPolicyState;
}

export type WafMode = "detect-learn" | "prevent-learn";
export type WafConfidence = "medium" | "high" | "critical";

export interface WafSettings {
	enabled: boolean;
	mode: WafMode;
	minimumConfidence: WafConfidence;
}

export interface WafLocationSettings extends WafSettings {
	path: string;
	/** no own settings: the location is protected like its host */
	inherit: boolean;
}

export interface WafHost extends WafSettings {
	locations: WafLocationSettings[];
}

export const WAF_DEFAULTS: WafSettings = { enabled: false, mode: "detect-learn", minimumConfidence: "high" };

export const getWafStatus = (): Promise<WafStatus> => api.get({ url: "/npmos/waf" });

export const setWafEnabled = (enabled: boolean, apply = true): Promise<WafStatus> =>
	api.put({ url: "/npmos/waf", data: { enabled, apply } });

/** WAF settings of all visible proxy hosts, by proxy host id (hosts without settings are missing) */
export const getWafHosts = (): Promise<Record<string, WafSettings>> => api.get({ url: "/npmos/waf/hosts" });

export const getWafHost = (id: number): Promise<WafHost> => api.get({ url: `/npmos/waf/hosts/${id}` });

export const setWafHost = (id: number, data: WafSettings & { locations?: WafLocationSettings[] }): Promise<WafHost> =>
	api.put({ url: `/npmos/waf/hosts/${id}`, data });

export const getWafPolicy = (): Promise<WafPolicyState & { content: string | null }> =>
	api.get({ url: "/npmos/waf/policy" });

export const applyWafPolicy = (): Promise<WafPolicyState & { changed: boolean }> =>
	api.post({ url: "/npmos/waf/policy/apply" });

export type WafEventsView = "important" | "all";

export interface WafEvent {
	time: string | null;
	name: string;
	severity: string;
	priority: string;
	level: string;
	service: string;
	asset: string;
	/** Prevent / Detect / ... */
	action: string;
	incidentType: string;
	sourceIp: string;
	proxyIp: string;
	host: string;
	method: string;
	uri: string;
	matchedLocation: string;
	matchedParameter: string;
	matchedSample: string;
	/** agent component that wrote it */
	source: string;
	raw: Record<string, any>;
}

export interface WafEvents {
	events: WafEvent[];
	total: number;
	/** only the tail of the agent's log files was read */
	truncated: boolean;
	/** the agent's log directory is readable */
	available: boolean;
}

export const getWafEvents = (params: { view: WafEventsView; host?: string; query?: string; limit?: number }) =>
	api.get({ url: "/npmos/waf/events", params }) as Promise<WafEvents>;
