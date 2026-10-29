// Filters of WAF → Events, kept in the URL so that a filtered view can be shared or opened from
// another page (a host's events, the events of an IP).
import type { EventQuery } from "../../api";

export const PERIODS = ["1h", "24h", "7d", "30d", "custom"] as const;
export type Period = (typeof PERIODS)[number];
export const KINDS = ["security", "crowdsec", "system", "all"] as const;
export type Kind = (typeof KINDS)[number];
export const ACTIONS = ["Prevent", "Detect", "Accept"] as const;
export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
/** list filters: comma-separated in the URL and the API */
export const LIST_FIELDS = ["host", "ip", "action", "severity", "type"] as const;
export type ListField = (typeof LIST_FIELDS)[number];

export interface EventFilters {
	period: Period;
	/** ISO, with period "custom" */
	from: string;
	to: string;
	kind: Kind;
	important: boolean;
	q: string;
	host: string[];
	ip: string[];
	action: string[];
	severity: string[];
	type: string[];
	minScore: string;
	maxScore: string;
}

export const DEFAULT_FILTERS: EventFilters = {
	period: "24h",
	from: "",
	to: "",
	kind: "security",
	important: false,
	q: "",
	host: [],
	ip: [],
	action: [],
	severity: [],
	type: [],
	minScore: "",
	maxScore: "",
};

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
	return {
		period: period === "custom" && !from ? DEFAULT_FILTERS.period : period,
		from: period === "custom" ? from : "",
		to: period === "custom" ? validDate(params.get("to")) : "",
		kind: KINDS.find((k) => k === params.get("kind")) ?? DEFAULT_FILTERS.kind,
		important: params.get("important") === "1",
		q: (params.get("q") ?? "").slice(0, 200),
		host: split(params.get("host")),
		ip: split(params.get("ip")),
		action: split(params.get("action")),
		severity: split(params.get("severity")),
		type: split(params.get("type")),
		minScore: validScore(params.get("min")),
		maxScore: validScore(params.get("max")),
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
	return query;
};

/** number of filters set besides the period, the kind and the search */
export const activeCount = (f: EventFilters) =>
	LIST_FIELDS.reduce((n, field) => n + f[field].length, 0) +
	(f.important ? 1 : 0) +
	(f.minScore ? 1 : 0) +
	(f.maxScore ? 1 : 0);

/** adds a value to a list filter (from a cell of the table or the event card) */
export const withValue = (f: EventFilters, field: ListField, value: string): EventFilters =>
	!value || f[field].includes(value) ? f : { ...f, [field]: [...f[field], value] };

export const withoutValue = (f: EventFilters, field: ListField, value: string): EventFilters => ({
	...f,
	[field]: f[field].filter((v) => v !== value),
});
