// NPMOS API client (/api/npmos/*), see npmos/backend/npmos/routes.js
import * as api from "src/api/backend/base";
import type { HostObjects } from "./policy/api";

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
	/** template of the policy objects of the host (list of hosts only) */
	template?: string | null;
}

export interface WafLocationSettings extends WafSettings {
	path: string;
	/** no own settings: the location is protected like its host */
	inherit: boolean;
	/** own objects of the policy; null: those of the host */
	objects?: HostObjects;
}

export interface WafHost extends WafSettings {
	locations: WafLocationSettings[];
	/** objects of the policy (WAF → Policy): a template or own references; null: the default policy */
	objects?: HostObjects;
}

export const WAF_DEFAULTS: WafSettings = { enabled: false, mode: "detect-learn", minimumConfidence: "high" };

export const getWafStatus = (): Promise<WafStatus> => api.get({ url: "/npmos/waf" });

export const setWafEnabled = (enabled: boolean, apply = true): Promise<WafStatus> =>
	api.put({ url: "/npmos/waf", data: { enabled, apply } });

/** WAF settings of all visible proxy hosts, by proxy host id (hosts without settings are missing) */
export const getWafHosts = (): Promise<Record<string, WafSettings>> => api.get({ url: "/npmos/waf/hosts" });

export const getWafHost = (id: number): Promise<WafHost> => api.get({ url: `/npmos/waf/hosts/${id}` });

export const setWafHost = (
	id: number,
	data: WafSettings & { locations?: WafLocationSettings[]; objects?: HostObjects },
): Promise<WafHost> => api.put({ url: `/npmos/waf/hosts/${id}`, data });

export const getWafPolicy = (): Promise<WafPolicyState & { content: string | null }> =>
	api.get({ url: "/npmos/waf/policy" });

export const applyWafPolicy = (): Promise<WafPolicyState & { changed: boolean }> =>
	api.post({ url: "/npmos/waf/policy/apply" });

/** a stored security event of the open-appsec agent (WAF → Events) */
export interface SecurityEvent {
	id: string;
	time: string;
	/** security: an attack the WAF decided on; system: a notice of the agent */
	kind: "security" | "system";
	name: string;
	severity: string;
	priority: string;
	confidence: string;
	/** Prevent / Detect / Accept ... */
	action: string;
	incidentType: string;
	sourceIp: string;
	sourcePort: number | null;
	proxyIp: string;
	sourceCountry: string;
	host: string;
	asset: string;
	method: string;
	uri: string;
	query: string;
	responseCode: number | null;
	location: string;
	parameter: string;
	sample: string;
	indicators: string;
	score: number | null;
	rule: string;
	practice: string;
	override: string;
	/** agent component that wrote it */
	service: string;
}

export interface SecurityEventFull extends SecurityEvent {
	raw: Record<string, any>;
}

/** query parameters of /npmos/events (see pages/WafEvents/filters.ts) */
export type EventQuery = Record<string, string | number | boolean | undefined>;

export interface EventsPage {
	events: SecurityEvent[];
	/** cursor of the next (older) page */
	next: string | null;
	total: number;
	/** more than `total` events match */
	totalCapped: boolean;
	from: string;
	to: string;
	/** the agent's log directory is readable */
	available: boolean;
	ingestError: string | null;
}

export const getEvents = (params: EventQuery) => api.get({ url: "/npmos/events", params }) as Promise<EventsPage>;

export const getEvent = (id: string, time: string) =>
	api.get({ url: `/npmos/events/${id}`, params: { time } }) as Promise<SecurityEventFull>;

export const downloadEvents = (params: EventQuery, format: "csv" | "json") =>
	api.download(
		{ url: "/npmos/events/export", params: { ...params, format } },
		`npmos-events-${new Date().toISOString().slice(0, 19).replaceAll(":", "-")}.${format}`,
	);

export type AnalyticsPeriod = "1h" | "24h" | "7d" | "30d";

export interface Analytics {
	period: AnalyticsPeriod;
	from: string;
	to: string;
	/** size of a timeline bucket, seconds */
	bucket: number;
	host: string | null;
	kpi: {
		/** requests seen by the agent, null without its telemetry */
		requests: number | null;
		attacks: number;
		prevented: number;
		detected: number;
		sources: number;
		crowdsecAlerts: number;
		crowdsecBans: number;
		readiness: null;
	};
	timeline: { t: string; prevent: number; detect: number; other: number }[];
	actions: { action: string; events: number }[];
	severities: { severity: string; events: number }[];
	types: { type: string; events: number }[];
	hosts: { host: string; events: number; prevented: number }[];
	uris: { host: string; uri: string; events: number }[];
	sources: { ip: string; country: string; events: number }[];
	countries: { country: string; events: number }[];
	lastBlocked: Pick<
		SecurityEvent,
		"id" | "time" | "severity" | "action" | "incidentType" | "sourceIp" | "host" | "method" | "uri" | "score"
	>[];
}

export const getAnalytics = (period: AnalyticsPeriod, host?: string) =>
	api.get({ url: "/npmos/analytics", params: { period, host } }) as Promise<Analytics>;

/** attacks on a host per hour of the last 24 h (hosts table) */
export interface HostAttacks {
	host: string;
	events: number;
	prevented: number;
	hours: number[];
}

export const getHostAttacks = () => api.get({ url: "/npmos/analytics/hosts" }) as Promise<HostAttacks[]>;

export interface EventsSettings {
	retention: { days: number; aggregateDays: number };
	storage: { events: number; oldest: string | null; bytes: number | null };
	ingest: { running: boolean; available: boolean; lastRun: string | null; lastError: string | null };
}

export const getEventsSettings = () => api.get({ url: "/npmos/events/settings" }) as Promise<EventsSettings>;

export const setEventsSettings = (retention: EventsSettings["retention"]) =>
	api.put({ url: "/npmos/events/settings", data: retention }) as Promise<EventsSettings>;

export interface WafAgentModel {
	present: boolean;
	size?: number;
	modifiedOn?: string;
}

export interface WafAgentSettings {
	crowdsec: { enabled: boolean; mode: "prevent" | "detect" };
	failOpen: { enabled: boolean; timeoutMs: number };
}

export interface WafAgentState extends WafAgentSettings {
	/** null: the agent has not started with NPMOS settings yet */
	restartRequired: boolean | null;
	model: WafAgentModel;
	restarting?: boolean;
}

export const getWafAgent = (): Promise<WafAgentState> => api.get({ url: "/npmos/waf/agent" });

export const setWafAgent = (data: WafAgentSettings, apply = true): Promise<WafAgentState> =>
	api.put({ url: "/npmos/waf/agent", data: { ...data, apply } });

/** the file goes as the request body (up to 1 GB), not through the JSON client */
export const uploadWafModel = async (file: File): Promise<WafAgentModel & { restarting: boolean }> => {
	const response = await fetch("/api/npmos/waf/agent/model", {
		method: "PUT",
		headers: { "Content-Type": "application/octet-stream" },
		body: file,
	});
	const payload = await response.json().catch(() => ({ error: { message: response.statusText } }));
	if (!response.ok) {
		throw new Error(payload.error?.message || response.statusText);
	}
	return payload;
};

export interface WafCustomVersion {
	id: number;
	comment: string;
	createdOn: string;
	user: string | null;
	size: number;
}

export interface WafCustomPolicy {
	id: number | null;
	content: string;
	versions: WafCustomVersion[];
	policy: WafPolicyState;
}

export interface WafCustomCheck {
	valid: boolean;
	error?: string;
	changed?: boolean;
	diff?: { op: " " | "+" | "-"; line: string }[];
}

export const getWafCustomPolicy = (): Promise<WafCustomPolicy> => api.get({ url: "/npmos/waf/policy/custom" });

export const checkWafCustomPolicy = (content: string): Promise<WafCustomCheck> =>
	api.post({ url: "/npmos/waf/policy/custom/check", data: { content } });

export const saveWafCustomPolicy = (content: string, comment: string): Promise<WafCustomPolicy> =>
	api.put({ url: "/npmos/waf/policy/custom", data: { content, comment } });

export const rollbackWafCustomPolicy = (id: number): Promise<WafCustomPolicy> =>
	api.post({ url: `/npmos/waf/policy/custom/${id}/rollback` });

// ---- hosts table: changes from the audit log, upstream checks (npmos/backend/npmos/hosts.js) ----

/** object type of a host in the audit log */
export type HostObjectType = "proxy-host" | "redirection-host" | "dead-host" | "stream";

export interface HostChange {
	id: number;
	/** created, updated, enabled, disabled, deleted; updated-waf: WAF settings of a proxy host */
	action: string;
	createdOn: string;
	user: { id: number; name: string | null; avatar: string } | null;
	/** settings changed by an update (API field names; "meta.x" for meta fields) */
	fields: string[];
	waf?: { enabled: boolean; mode: WafMode | null };
}

export interface HostLastChange extends HostChange {
	type: HostObjectType;
	objectId: number;
}

export interface UpstreamCheck {
	type: HostObjectType;
	objectId: number;
	host: string;
	port: number;
	ok: boolean;
	ms?: number;
	/** ECONNREFUSED, ENOTFOUND, timeout… */
	error?: string;
}

export const getHostChanges = (): Promise<HostLastChange[]> => api.get({ url: "/npmos/hosts/changes" });

export const getHostHistory = (type: HostObjectType, id: number): Promise<HostChange[]> =>
	api.get({ url: `/npmos/hosts/changes/${type}/${id}` });

export const getUpstreamChecks = (): Promise<UpstreamCheck[]> => api.get({ url: "/npmos/hosts/upstreams" });
