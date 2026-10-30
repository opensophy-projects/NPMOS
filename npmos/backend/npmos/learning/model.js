// Learning of the agent (docs/ROADMAP.md, phase 8; docs/adr/0011-learning.md): pure functions, no database.
//
// The queue groups events the agent is not sure about by host, URL, parameter and indicators, so that a group
// is labelled at once. A label is benign, malicious or dismiss, for some of: the value of the parameter, its
// name, the URL, the sources. The agent reads labels from tuning/decisions.data of each asset in the shared
// storage (every 30 min, TuningDecision.cc): benign counts as another trusted source of learning (a benign
// source weighs as many sources), malicious keeps the request out of learning. Instantly (optional), benign
// becomes an exception (accept) for the host until the model has learnt, malicious an exception (drop) and/or
// a ban of the sources in CrowdSec.
import { createHash } from "node:crypto";

export const DECISIONS = ["benign", "malicious", "dismiss"];
/** scopes of a label: eventType of decisions.data */
export const SCOPES = ["parameterValue", "parameterName", "url", "source"];
/** key of an exception condition (WAF → Policy) for each scope */
export const EXCEPTION_KEYS = {
	parameterValue: "paramValue",
	parameterName: "paramName",
	url: "url",
	source: "sourceIp",
};
/** prefix of the ids of NPMOS in decisions.data: other entries (tuning suggestions) are left as they are */
export const ID_PREFIX = "npmos-";
/** prefix of the exceptions NPMOS adds to the policy of a host */
export const EXCEPTION_PREFIX = "npmos-learn-";
export const MAX_SOURCES = 50;
export const MAX_TTL_DAYS = 90;
export const BAN_DURATIONS = ["1h", "4h", "24h", "168h", "720h"];
// waapFinalScore of the agent: < 3 low, 3..6 medium (the grey zone), >= 6 high (WaapConversions.cc)
export const GREY_MIN = 3;
export const GREY_MAX = 6;

/** rule name of a proxy host (policy.js) → its id and the index of the location, or null */
export const ruleHost = (rule) => {
	const m = /^npm-managed-specific-rule-proxyhost-(\d+)(?:-(\d+))?(?:\.\d+)?$/.exec(String(rule || ""));
	return m ? { hostId: Number(m[1]), location: m[2] === undefined ? null : Number(m[2]) } : null;
};

/** key of a group: host, URL, parameter, indicators */
export const groupKey = ({ hostId, uri, parameter, indicators }) =>
	createHash("sha256")
		.update(JSON.stringify([hostId, uri || "", parameter || "", indicators || ""]))
		.digest("hex")
		.slice(0, 32);

/**
 * Why a group is in the queue: blocked (requests were refused: a false positive hurts users), grey (detected
 * with a medium score: blocked or not depending on the minimum confidence), detected (high score on a host
 * that learns or detects).
 */
export const reasonOf = ({ blocked, score }) => {
	if (blocked > 0) return "blocked";
	if (score !== null && score >= GREY_MIN && score < GREY_MAX) return "grey";
	return "detected";
};

const num = (v) => (v === null || v === undefined || v === "" ? null : Number(v));
const time = (v) => (v ? new Date(v).toISOString() : null);

/**
 * Groups of the queue from rows grouped by asset, URI, parameter and indicators (one asset per domain of a host:
 * they are merged), without the groups already labelled.
 * @param {object[]} rows  {asset, rule, uri, parameter, indicators, events, sources, score, blocked, first, last,
 *   host, incident_type, sample, event_id}
 * @param {Set<string>} labelled  keys of the groups with a label in force
 * @param {Date} now
 * @param {(row: object) => number|undefined} hostOf  the proxy host of a row (default: by the rule name)
 */
export const groupsOf = (
	rows,
	labelled = new Set(),
	now = new Date(),
	hostOf = (row) => ruleHost(row.rule)?.hostId,
) => {
	const groups = new Map();
	for (const row of rows) {
		const hostId = hostOf(row);
		if (!hostId) continue;
		const fields = {
			hostId,
			uri: row.uri || "",
			parameter: row.parameter || "",
			indicators: row.indicators || "",
		};
		const key = groupKey(fields);
		if (labelled.has(key)) continue;
		const g = groups.get(key) || {
			key,
			...fields,
			host: row.host || "",
			incidentType: row.incident_type || "",
			sample: row.sample || "",
			eventId: row.event_id ?? null,
			events: 0,
			sources: 0,
			blocked: 0,
			score: null,
			first: null,
			last: null,
		};
		g.events += Number(row.events) || 0;
		// distinct per rule: an upper bound when a host has several domains
		g.sources += Number(row.sources) || 0;
		g.blocked += Number(row.blocked) || 0;
		const score = num(row.score);
		if (score !== null && (g.score === null || score > g.score)) g.score = score;
		const first = time(row.first);
		const last = time(row.last);
		if (first && (!g.first || first < g.first)) g.first = first;
		if (last && (!g.last || last > g.last)) {
			g.last = last;
			g.host = row.host || g.host;
			g.sample = row.sample || g.sample;
			g.eventId = row.event_id ?? g.eventId;
		}
		groups.set(key, g);
	}
	const day = now.getTime() - 24 * 3600 * 1000;
	return [...groups.values()]
		.map((g) => ({ ...g, reason: reasonOf(g), new: !!g.first && new Date(g.first).getTime() >= day }))
		.sort(
			(a, b) =>
				REASON_ORDER[a.reason] - REASON_ORDER[b.reason] ||
				b.events - a.events ||
				(b.last || "").localeCompare(a.last || ""),
		);
};

const REASON_ORDER = { blocked: 0, grey: 1, detected: 2 };

/** what a label applies to by default: the parameter (value and name) if there is one, else the URL */
export const defaultScopes = (group) =>
	group.parameter
		? [
				...(group.sample ? [{ type: "parameterValue", value: group.sample }] : []),
				{ type: "parameterName", value: group.parameter },
			]
		: [{ type: "url", value: group.uri }];

const isIp = (v) => /^[0-9a-f.:]+(\/\d{1,3})?$/i.test(v);

/**
 * A label to save: decision, scopes and instant effects checked.
 * @param {object} input  {decision, scopes: [{type, value}], exception?: boolean, ttl_days?: number,
 *   ban?: boolean, ban_duration?: string, note?: string}
 * @returns {{decision, scopes, exception, ttlDays, ban, banDuration, note}}
 */
export const checkLabel = (input = {}) => {
	const errors = [];
	const decision = input.decision;
	if (!DECISIONS.includes(decision)) errors.push(`decision: one of ${DECISIONS.join(", ")}`);
	const seen = new Set();
	const scopes = [];
	for (const s of Array.isArray(input.scopes) ? input.scopes : []) {
		const type = s?.type;
		const value = typeof s?.value === "string" ? s.value.slice(0, 2000) : "";
		if (!SCOPES.includes(type)) {
			errors.push(`scope: one of ${SCOPES.join(", ")}`);
			continue;
		}
		if (!value) {
			errors.push(`scope ${type}: a value is needed`);
			continue;
		}
		if (type === "source" && !isIp(value)) {
			errors.push(`scope source: ${value} is not an address`);
			continue;
		}
		const id = `${type}\n${value}`;
		if (seen.has(id)) continue;
		seen.add(id);
		scopes.push({ type, value });
	}
	if (decision !== "dismiss" && !scopes.length) errors.push("scopes: at least one");
	if (scopes.filter((s) => s.type === "source").length > MAX_SOURCES)
		errors.push(`scopes: up to ${MAX_SOURCES} sources`);
	const exception = decision !== "dismiss" && !!input.exception;
	const ttlDays = Number.isInteger(input.ttl_days) ? input.ttl_days : 14;
	if (exception && decision === "benign" && (ttlDays < 0 || ttlDays > MAX_TTL_DAYS)) {
		errors.push(`ttl_days: 0 (no end) to ${MAX_TTL_DAYS}`);
	}
	const ban = decision === "malicious" && !!input.ban;
	const banDuration = input.ban_duration || "24h";
	if (ban && !BAN_DURATIONS.includes(banDuration)) errors.push(`ban_duration: one of ${BAN_DURATIONS.join(", ")}`);
	if (ban && !scopes.some((s) => s.type === "source")) errors.push("ban: choose the sources to ban");
	if (errors.length) return { errors };
	return {
		decision,
		scopes,
		exception,
		// a drop stays until it is undone; an accept ends when the model has learnt
		ttlDays: exception && decision === "benign" ? ttlDays : 0,
		ban,
		banDuration,
		note: String(input.note || "").slice(0, 500),
	};
};

/** entries of decisions.data for the labels of an asset (dismiss has none: the agent ignores it) */
export const decisionEntries = (labels) =>
	labels
		.filter((l) => l.decision !== "dismiss")
		.flatMap((l) =>
			l.scopes.map((s, i) => ({
				id: `${ID_PREFIX}${l.id}-${i}`,
				decision: l.decision,
				eventType: s.type,
				eventTitle: s.value,
				severity: "",
				logQuery: "",
				metrics: [],
				attackTypes: [],
				enforced: false,
				policyVersion: 0,
			})),
		);

/**
 * decisions.data with the entries of NPMOS replaced by `ours`; the entries of others (the tuning service) stay.
 * An entry of ours that the tuning service has marked enforced keeps the mark. A decision of others for the
 * same type and title gives way to ours (the agent keeps the last one).
 * @param {{decisions?: object[]}|null} current
 * @param {object[]} ours
 */
export const mergeDecisions = (current, ours) => {
	const old = Array.isArray(current?.decisions) ? current.decisions : [];
	const enforced = new Set(old.filter((d) => d?.enforced && String(d.id).startsWith(ID_PREFIX)).map((d) => d.id));
	const taken = new Set(ours.map((d) => `${d.eventType}\n${d.eventTitle}`));
	const others = old.filter(
		(d) => d && !String(d.id || "").startsWith(ID_PREFIX) && !taken.has(`${d.eventType}\n${d.eventTitle}`),
	);
	return { decisions: [...others, ...ours.map((d) => ({ ...d, enforced: enforced.has(d.id) }))] };
};

/** ids of our entries the tuning service has marked enforced (the agent has a policy since they were written) */
export const enforcedIds = (current) =>
	new Set(
		(Array.isArray(current?.decisions) ? current.decisions : [])
			.filter((d) => d?.enforced && String(d.id).startsWith(ID_PREFIX))
			.map((d) => d.id),
	);

/** the exception (WAF → Policy) of a label: all its scopes must match */
export const exceptionOf = (label) => ({
	name: `${EXCEPTION_PREFIX}${label.id}`,
	action: label.decision === "malicious" ? "drop" : "accept",
	condition: label.scopes.map((s) => ({ key: EXCEPTION_KEYS[s.type], value: s.value })),
});

/** a label's exception is in force */
export const exceptionActive = (label, now = new Date()) =>
	!!label.exception && !label.undone_on && (!label.expires_on || new Date(label.expires_on) > now);

/**
 * Assets of a host as the agent names them (url + uri of a rule: local_policy_mgmt_gen): its domains, and
 * domain + path for each location with its own rule.
 */
export const assetsOf = (domains, paths = []) => [...domains, ...domains.flatMap((d) => paths.map((p) => `${d}${p}`))];

/** readiness of the tuning service (0 no data … 6 PhD) → steps of the GUI */
export const READINESS = ["none", "kindergarten", "primary", "high", "graduate", "master", "phd"];
/** recommendation of the tuning service → key of the GUI */
export const RECOMMENDATIONS = [
	"send_traffic",
	"keep_learning",
	"review_critical",
	"prevent_critical",
	"review",
	"prevent_high",
];

/** the statistics of the tuning service for an asset, in the terms of the GUI */
export const statsOf = (raw) => {
	const s = raw?.statistics ?? raw ?? {};
	const readiness = Number.isInteger(s.readiness) ? s.readiness : 0;
	const recommendation = Number.isInteger(s.recommendation) ? s.recommendation : 0;
	return {
		readiness: READINESS[readiness] ?? "none",
		level: readiness,
		recommendation: RECOMMENDATIONS[recommendation] ?? "send_traffic",
		ready: s.status === "ready",
		requests: Number(s.totalRequests) || 0,
		elapsed: s.elapsedTime || "",
		sources: Number(s.uniqueSources) || 0,
		urls: Number(s.uniqueUrls) || 0,
		legitimate: Number(s.legitimateRequests) || 0,
		malicious: Number(s.maliciousRequests) || 0,
		mitigation: s.mitigationMode || "",
	};
};

/** the best statistics of the assets of a host (one domain may have seen all the traffic) */
export const hostStats = (list) =>
	list.reduce(
		(best, s) =>
			!best || s.level > best.level || (s.level === best.level && s.requests > best.requests) ? s : best,
		null,
	);

/** a tuning suggestion of the tuning service as an item of the queue */
export const suggestionOf = (raw, asset) => ({
	id: String(raw.id || ""),
	asset,
	type: SCOPES.includes(raw.eventType) ? raw.eventType : "parameterValue",
	title: String(raw.eventTitle || ""),
	severity: String(raw.severity || "").toLowerCase(),
	attackTypes: Array.isArray(raw.attackTypes) ? raw.attackTypes.map(String) : [],
	metrics: Array.isArray(raw.metrics)
		? raw.metrics.map((m) => ({ name: String(m.metric ?? m.name ?? ""), value: m.count ?? m.value }))
		: [],
});
