// Filters of WAF → Events, kept in the URL so that a filtered view can be shared or opened from
// another page (a host's events, the events of an IP).
import type { EventQuery } from "../../api";

export const PERIODS = ["1h", "24h", "7d", "30d", "custom"] as const;
export type Period = (typeof PERIODS)[number];
// "agents": open-appsec (attacks and the notices of its agent) and CrowdSec in one list, the agent named in each row
export const KINDS = ["agents", "mtls", "all"] as const;
export type Kind = (typeof KINDS)[number];
// open-appsec (Prevent, Detect, Accept), CrowdSec (decision type, an alert without one, a simulated one), mTLS
export const ACTIONS = ["Prevent", "Detect", "Accept", "ban", "captcha", "alert", "simulated", "denied"] as const;
export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
export const AGENTS = ["open-appsec", "crowdsec"] as const;
/** Events → All: nginx is the agent of the requests of the log */
export const AGENTS_OF_ALL = [...AGENTS, "nginx"] as const;
/** the agent of an event by its kind */
export const AGENT_OF: Record<string, string> = {
	security: "open-appsec",
	crowdsec: "crowdsec",
	mtls: "mtls",
	system: "open-appsec",
};
/** list filters: comma-separated in the URL and the API */
/** status and client: of the requests of the log (Events → All) */
export const LIST_FIELDS = ["agent", "host", "ip", "action", "severity", "type", "status", "client"] as const;
export type ListField = (typeof LIST_FIELDS)[number];

export interface EventFilters {
	period: Period;
	/** ISO, with period "custom" */
	from: string;
	to: string;
	kind: Kind;
	important: boolean;
	q: string;
	agent: string[];
	host: string[];
	ip: string[];
	action: string[];
	severity: string[];
	type: string[];
	status: string[];
	client: string[];
	minScore: string;
	maxScore: string;
	/** requests of the log (Events → All): refused or passed, "" for both */
	outcome: "" | "refused" | "passed";
}

export const DEFAULT_FILTERS: EventFilters = {
	period: "24h",
	from: "",
	to: "",
	kind: "agents",
	important: false,
	q: "",
	agent: [],
	host: [],
	ip: [],
	action: [],
	severity: [],
	type: [],
	status: [],
	client: [],
	minScore: "",
	maxScore: "",
	outcome: "",
};
/** Events → All: classes of the answer and who sent the requests */
export const STATUS_CLASSES = ["2xx", "3xx", "4xx", "5xx"] as const;
export const CLIENTS = ["human", "bot", "scanner"] as const;
export const OUTCOMES = ["refused", "passed"] as const;

const split = (value: string | null) =>
	(value ?? "")
		.split(",")
		.map((v) => v.trim())
		.filter(Boolean);

const validDate = (value: string | null) => (value && !Number.isNaN(Date.parse(value)) ? value : "");
const validScore = (value: string | null) => (value && /^\d{1,2}(\.\d+)?$/.test(value) ? value : "");

export const filtersFromParams = (params: URLSearchParams): EventFilters => {
	const period = PERIODS.find((p) => p === params.get("period")) ?? DEFAULT_FILTERS.period;
	const from = validDate(params.get("from"));
	// links of before: kind=security, kind=system (open-appsec) and kind=crowdsec are the agents with one agent
	const old = { security: "open-appsec", system: "open-appsec", crowdsec: "crowdsec" }[params.get("kind") ?? ""];
	const agent = split(params.get("agent")).filter((a) => (AGENTS_OF_ALL as readonly string[]).includes(a));
	// a period written backwards (from after to) is the same period: the dates are swapped
	let to = validDate(params.get("to"));
	let start = from;
	if (start && to && Date.parse(start) > Date.parse(to)) [start, to] = [to, start];
	return {
		period: period === "custom" && !from ? DEFAULT_FILTERS.period : period,
		from: period === "custom" ? start : "",
		to: period === "custom" ? to : "",
		kind: KINDS.find((k) => k === params.get("kind")) ?? DEFAULT_FILTERS.kind,
		important: params.get("important") === "1",
		q: (params.get("q") ?? "").slice(0, 200),
		agent: old && !agent.includes(old) ? [...agent, old] : agent,
		host: split(params.get("host")),
		ip: split(params.get("ip")),
		action: split(params.get("action")),
		severity: split(params.get("severity")),
		type: split(params.get("type")),
		minScore: validScore(params.get("min")),
		maxScore: validScore(params.get("max")),
		status: split(params.get("status")).filter((v) => (STATUS_CLASSES as readonly string[]).includes(v)),
		client: split(params.get("client")).filter((v) => (CLIENTS as readonly string[]).includes(v)),
		outcome: OUTCOMES.find((o) => o === params.get("outcome")) ?? "",
	};
};

/** the filters in URL parameters; defaults are left out, other parameters kept */
export const filtersToParams = (f: EventFilters, base = new URLSearchParams()) => {
	const params = new URLSearchParams(base);
	const set = (key: string, value: string, isDefault: boolean) => {
		if (isDefault || !value) params.delete(key);
		else params.set(key, value);
	};
	set("period", f.period, f.period === DEFAULT_FILTERS.period);
	set("from", f.period === "custom" ? f.from : "", false);
	set("to", f.period === "custom" ? f.to : "", false);
	set("kind", f.kind, f.kind === DEFAULT_FILTERS.kind);
	set("important", f.important ? "1" : "", false);
	set("q", f.q.trim(), false);
	for (const field of LIST_FIELDS) set(field, f[field].join(","), false);
	set("min", f.minScore, false);
	set("max", f.maxScore, false);
	set("outcome", f.outcome, false);
	return params;
};

/** parameters of the events API */
export const filtersToQuery = (f: EventFilters): EventQuery => {
	const query: EventQuery = { kind: f.kind };
	if (f.period === "custom") {
		query.from = f.from;
		if (f.to) query.to = f.to;
	} else {
		query.period = f.period;
	}
	if (f.important) query.important = true;
	if (f.q.trim()) query.q = f.q.trim();
	for (const field of LIST_FIELDS) if (f[field].length) query[field] = f[field].join(",");
	if (f.minScore) query.minScore = f.minScore;
	if (f.maxScore) query.maxScore = f.maxScore;
	if (f.outcome) query.outcome = f.outcome;
	return query;
};

/** number of filters set besides the period, the kind and the search */
export const activeCount = (f: EventFilters) =>
	LIST_FIELDS.reduce((n, field) => n + f[field].length, 0) +
	(f.important ? 1 : 0) +
	(f.minScore ? 1 : 0) +
	(f.maxScore ? 1 : 0) +
	(f.outcome ? 1 : 0);

/** adds a value to a list filter (from a cell of the table or the event card) */
export const withValue = (f: EventFilters, field: ListField, value: string): EventFilters =>
	!value || f[field].includes(value) ? f : { ...f, [field]: [...f[field], value] };

export const withoutValue = (f: EventFilters, field: ListField, value: string): EventFilters => ({
	...f,
	[field]: f[field].filter((v) => v !== value),
});

const OPENAPPSEC_ACTIONS = ["Prevent", "Detect", "Accept"];
const CROWDSEC_ACTIONS = ["ban", "captcha", "alert", "simulated"];

/** the filters a kind of events has: mTLS refusals have no attack type or score, notices have only a severity */
export const FILTERS_OF: Record<Kind, { fields: ListField[]; score: boolean }> = {
	agents: { fields: ["agent", "host", "ip", "action", "severity", "type"], score: true },
	mtls: { fields: ["host", "ip"], score: false },
	all: { fields: [...LIST_FIELDS], score: true },
};

/** the actions to choose from: those of the agents chosen (open-appsec, CrowdSec), of all with none chosen */
export const actionsFor = (f: EventFilters): string[] => {
	if (f.kind === "mtls") return [];
	const agents = f.agent.length ? f.agent : [...AGENTS];
	return [
		...(agents.includes("open-appsec") ? OPENAPPSEC_ACTIONS : []),
		...(agents.includes("crowdsec") ? CROWDSEC_ACTIONS : []),
		...(f.kind === "all" ? ["denied"] : []),
	];
};

/** another kind: the filters it does not have are dropped (they would hide every event of it) */
export const forKind = (f: EventFilters, kind: Kind): EventFilters => {
	const { fields, score } = FILTERS_OF[kind];
	const next: EventFilters = { ...f, kind };
	for (const field of LIST_FIELDS) if (!fields.includes(field)) next[field] = [];
	// nginx (the requests) is an agent of Events → All only
	if (kind !== "all") next.agent = next.agent.filter((a) => a !== "nginx");
	if (kind !== "all") next.outcome = "";
	if (!score) {
		next.minScore = "";
		next.maxScore = "";
	}
	const actions = actionsFor(next);
	next.action = next.action.filter((a) => actions.includes(a));
	return next;
};
