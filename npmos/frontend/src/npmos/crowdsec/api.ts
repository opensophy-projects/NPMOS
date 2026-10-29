// CrowdSec API (/api/npmos/crowdsec), see npmos/backend/npmos/crowdsec. The common client converts
// keys (snake_case ↔ camelCase); names of hub items, scenarios and origins are values.
import { useQuery } from "@tanstack/react-query";
import * as api from "src/api/backend/base";

export const DECISION_TYPES = ["ban", "captcha"] as const;
export const SCOPES = ["Ip", "Range", "any"] as const;
export const LOG_LEVELS = ["error", "warning", "info", "debug"] as const;
export const CAPTCHA_PROVIDERS = ["", "recaptcha", "hcaptcha", "turnstile"] as const;
export const HUB_TYPES = [
	"collections",
	"parsers",
	"scenarios",
	"postoverflows",
	"contexts",
	"appsec-configs",
	"appsec-rules",
] as const;
export type HubType = (typeof HUB_TYPES)[number];
/** durations the GUI offers; the API takes any number of m, h or d */
export const DURATIONS = ["15m", "1h", "4h", "12h", "24h", "7d", "30d"] as const;

export interface CrowdsecProfile {
	name: string;
	enabled: boolean;
	scope: (typeof SCOPES)[number];
	scenarios: string[];
	filter: string;
	type: (typeof DECISION_TYPES)[number];
	duration: string;
	escalate: boolean;
}

export interface CrowdsecSettings {
	bouncer: {
		enabled: boolean;
		/** check the interface of NPMOS too */
		admin: boolean;
		mode: "live" | "stream";
		fallback: (typeof DECISION_TYPES)[number];
		updateFrequency: number;
		excludeLocations: string[];
		captcha: {
			provider: (typeof CAPTCHA_PROVIDERS)[number];
			siteKey: string;
			secretKey: string;
			hasSecret?: boolean;
		};
	};
	sources: { nginx: boolean; openappsec: boolean };
	appsec: { enabled: boolean; failureAction: "passthrough" | "deny"; configs: string[] };
	profiles: CrowdsecProfile[];
	allowlist: { ips: string[]; expressions: string[]; private: boolean };
	openappsecBan: { enabled: boolean; events: number; minutes: number };
	logLevel: (typeof LOG_LEVELS)[number];
	onlineHub: boolean;
}

export interface CrowdsecSettingsState extends CrowdsecSettings {
	/** files of CrowdSec that differ from the settings (not applied) */
	pending: string[];
	/** null: not known yet (bouncer never enabled) */
	perHost: boolean | null;
	shareEnabled: boolean;
}

export interface Machine {
	name: string;
	ipAddress: string;
	createdOn: string | null;
	lastPush: string | null;
	lastHeartbeat: string | null;
	validated: boolean;
	version: string;
	authType: string;
	os: string;
}

export interface Bouncer {
	name: string;
	ipAddress: string;
	createdOn: string | null;
	lastPull: string | null;
	valid: boolean;
	type: string;
	version: string;
	authType: string;
}

export interface Counter {
	key: string;
	value: number;
}

export interface CrowdsecMetrics {
	version: string;
	linesRead: Counter[];
	linesParsed: number;
	linesUnparsed: number;
	overflows: Counter[];
	bouncerRequests: Counter[];
	machineRequests: Counter[];
	decisions: Counter[];
	appsecRequests: number;
	appsecBlocked: number;
}

export interface CrowdsecOverview {
	settings: {
		bouncer: boolean;
		sources: { nginx: boolean; openappsec: boolean };
		appsec: boolean;
		openappsecBan: { enabled: boolean; events: number; minutes: number };
	};
	/** IP reputation in the WAF agent (WAF → Agent) */
	agent: { enabled: boolean; mode: "prevent" | "detect" };
	lapi: { healthy: boolean; error: string };
	metrics: CrowdsecMetrics | null;
	machines: Machine[];
	bouncers: Bouncer[];
	decisions: { total: number; byOrigin: Record<string, number>; byType: Record<string, number> };
	alerts24h: number;
	hub: { installed: number; outdated: number; error: string };
	pending: string[];
	errors: string[];
}

export interface Decision {
	id: number;
	origin: string;
	type: string;
	scope: string;
	value: string;
	duration: string;
	scenario: string;
}

export interface CrowdsecAlert {
	id: number;
	createdAt: string;
	startAt: string;
	stopAt: string;
	scenario: string;
	message: string;
	machineId: string;
	eventsCount: number;
	simulated: boolean;
	source: { ip?: string; value?: string; scope?: string; cn?: string; asName?: string; range?: string };
	decisions: { id: number; type: string; value: string; duration: string; origin: string }[];
	meta: { key: string; value: string }[];
}

export interface HubItem {
	type: HubType;
	name: string;
	description: string;
	latest: string;
	installed: false | "hub" | "local";
	version: string | null;
	status: "" | "up-to-date" | "outdated" | "tainted" | "local" | "broken";
	neededBy: string[];
	/** needed by the settings of NPMOS: not removable */
	required: boolean;
}

export interface Blocklist {
	id: number;
	createdOn: string;
	modifiedOn: string;
	name: string;
	enabled: boolean;
	source: "file" | "url";
	url: string;
	hasToken: boolean;
	insecure: boolean;
	lines: number | null;
	decision: (typeof DECISION_TYPES)[number];
	duration: string;
	refreshMinutes: number;
	syncedOn: string | null;
	count: number;
	error: string;
	sync?: { count?: number; invalid?: number; error?: string } | null;
}

export interface CrowdsecHosts {
	/** the bouncer of NPMOS (CrowdSec → Settings) */
	bouncerEnabled: boolean;
	perHost: boolean | null;
	/** bans of the last 24 h by domain */
	bans: Record<string, number>;
	/** hosts the bouncer leaves out */
	hosts: { hostType: string; hostId: number; bouncer: boolean }[];
}

export interface ApplyResult {
	applied?: boolean;
	changed: string[];
	installed: string[];
	restarted: boolean;
	healthy: boolean;
	bouncerChanged?: boolean;
}

export const getOverview = (): Promise<CrowdsecOverview> => api.get({ url: "/npmos/crowdsec" });
export const useCrowdsec = (options = {}) =>
	useQuery<CrowdsecOverview, Error>({
		queryKey: ["npmos-crowdsec"],
		queryFn: getOverview,
		staleTime: 5000,
		...options,
	});

export const getSettings = (): Promise<CrowdsecSettingsState> => api.get({ url: "/npmos/crowdsec/settings" });
export const useCrowdsecSettings = (options = {}) =>
	useQuery<CrowdsecSettingsState, Error>({
		queryKey: ["npmos-crowdsec-settings"],
		queryFn: getSettings,
		staleTime: 5000,
		...options,
	});

/** profile scenarios and allowlist expressions are values: the client keeps them as they are */
export const setSettings = (data: CrowdsecSettings): Promise<CrowdsecSettings & { result: ApplyResult }> => {
	const { pending: _p, perHost: _h, shareEnabled: _s, ...rest } = data as CrowdsecSettingsState;
	const { hasSecret: _x, ...captcha } = rest.bouncer.captcha;
	return api.put({ url: "/npmos/crowdsec/settings", data: { ...rest, bouncer: { ...rest.bouncer, captcha } } });
};

export const applySettings = (): Promise<ApplyResult> => api.post({ url: "/npmos/crowdsec/apply" });

export const getAlerts = (params: {
	ip?: string;
	scenario?: string;
	since?: string;
	limit?: number;
	active?: boolean;
}) => api.get({ url: "/npmos/crowdsec/alerts", params }) as Promise<CrowdsecAlert[]>;
export const useAlerts = (params: Parameters<typeof getAlerts>[0], options = {}) =>
	useQuery<CrowdsecAlert[], Error>({
		queryKey: ["npmos-crowdsec-alerts", params],
		queryFn: () => getAlerts(params),
		staleTime: 5000,
		...options,
	});

export const getDecisions = (params: { q?: string; type?: string; origin?: string; offset?: number; limit?: number }) =>
	api.get({ url: "/npmos/crowdsec/decisions", params }) as Promise<{ total: number; items: Decision[] }>;
export const useDecisions = (params: Parameters<typeof getDecisions>[0], options = {}) =>
	useQuery<{ total: number; items: Decision[] }, Error>({
		queryKey: ["npmos-crowdsec-decisions", params],
		queryFn: () => getDecisions(params),
		staleTime: 3000,
		...options,
	});

export const ban = (data: { values: string[]; type?: string; duration?: string; reason?: string }) =>
	api.post({ url: "/npmos/crowdsec/decisions", data }) as Promise<{ count: number }>;
export const unban = (data: { ids?: number[]; values?: string[] }) =>
	api.post({ url: "/npmos/crowdsec/decisions/delete", data }) as Promise<{ deleted: number }>;

export const getRegistry = (): Promise<{ machines: Machine[]; bouncers: Bouncer[]; ownMachine: string }> =>
	api.get({ url: "/npmos/crowdsec/registry" });
export const useRegistry = (options = {}) =>
	useQuery({ queryKey: ["npmos-crowdsec-registry"], queryFn: getRegistry, staleTime: 10000, ...options });

export const getHub = (params: { type?: string; q?: string; installed?: boolean }) =>
	api.get({ url: "/npmos/crowdsec/hub", params }) as Promise<HubItem[]>;
export const useHub = (params: Parameters<typeof getHub>[0], options = {}) =>
	useQuery<HubItem[], Error>({
		queryKey: ["npmos-crowdsec-hub", params],
		queryFn: () => getHub(params),
		staleTime: 10000,
		...options,
	});
export const hubItem = (data: { type: HubType; name: string; action: "install" | "remove" }) =>
	api.post({ url: "/npmos/crowdsec/hub", data }) as Promise<{ items: string[]; restarted: boolean }>;
export const hubUpgrade = () =>
	api.post({ url: "/npmos/crowdsec/hub/upgrade" }) as Promise<{ items: string[]; restarted: boolean }>;
export const hubOnline = () => api.post({ url: "/npmos/crowdsec/hub/online" }) as Promise<{ items: number }>;

/** raw upload: the common client sends JSON only */
const rawRequest = async (method: string, url: string, body: Blob | string, contentType: string) => {
	const response = await fetch(`/api${url}`, {
		method,
		headers: { "Content-Type": contentType },
		body,
	});
	const payload = await response.json().catch(() => ({}));
	if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
	return payload;
};

export const uploadHubSnapshot = (file: File): Promise<{ items: number; data_files: number }> =>
	rawRequest("POST", "/npmos/crowdsec/hub/snapshot", file, "application/octet-stream");

export const getBlocklists = (): Promise<Blocklist[]> => api.get({ url: "/npmos/crowdsec/blocklists" });
export const useBlocklists = (options = {}) =>
	useQuery<Blocklist[], Error>({ queryKey: ["npmos-crowdsec-blocklists"], queryFn: getBlocklists, ...options });

export interface BlocklistData {
	name: string;
	enabled: boolean;
	source: "file" | "url";
	url?: string;
	token?: string;
	insecure?: boolean;
	decision: string;
	duration: string;
	refreshMinutes?: number;
}

/** a file list goes as text/plain (up to 20 MB), its fields in the query string */
export const saveBlocklist = (id: number | null, data: BlocklistData, content?: string): Promise<Blocklist> => {
	if (data.source === "file" && content !== undefined) {
		const q = new URLSearchParams({
			name: data.name,
			enabled: String(data.enabled),
			decision: data.decision,
			duration: data.duration,
		});
		return rawRequest(
			id ? "PUT" : "POST",
			`/npmos/crowdsec/blocklists${id ? `/${id}` : ""}?${q}`,
			content,
			"text/plain",
		);
	}
	return id
		? api.put({ url: `/npmos/crowdsec/blocklists/${id}`, data })
		: api.post({ url: "/npmos/crowdsec/blocklists", data });
};
export const syncBlocklist = (id: number) =>
	api.post({ url: `/npmos/crowdsec/blocklists/${id}/sync` }) as Promise<{ count: number; invalid: number }>;
export const deleteBlocklist = (id: number) => api.del({ url: `/npmos/crowdsec/blocklists/${id}` });

export const setShare = (enabled: boolean): Promise<{ enabled: boolean; token: string }> =>
	api.put({ url: "/npmos/crowdsec/share", data: { enabled } });
/** address other NPMOS nodes download the decisions of this one from */
export const shareUrl = () => `${window.location.origin}/api/npmos/crowdsec/public/decisions`;

export const getCrowdsecHosts = (): Promise<CrowdsecHosts> => api.get({ url: "/npmos/crowdsec/hosts" });
export const useCrowdsecHosts = (options = {}) =>
	useQuery<CrowdsecHosts, Error>({
		queryKey: ["npmos-crowdsec-hosts"],
		queryFn: getCrowdsecHosts,
		staleTime: 15000,
		...options,
	});
export const setHostBouncer = (hostType: string, hostId: number, bouncer: boolean) =>
	api.put({ url: `/npmos/crowdsec/hosts/${hostType}/${hostId}`, data: { bouncer } });
