// Dry run of a change of the policy (phase 12, docs/WAF-POLICY.md): what the agent would do with recent security
// events of the WAF under the current policy and under the candidate one. The verdict follows the agent: the rule of
// the host (the longest host/path), its exceptions (values of a key: any; keys: all), its mode and the minimum
// confidence of its practice. The machine learning is not run again: an event keeps its confidence.
// Pure functions, no database.

const list = (v) => (Array.isArray(v) ? v : []);

/** confidence of an event (eventConfidence of the agent) and the minimum confidence of a practice, as ranks */
const CONFIDENCE = { low: 1, medium: 2, high: 3, "very high": 4, critical: 4 };
const rank = (value) => CONFIDENCE[String(value || "").toLowerCase()] ?? 0;

const ipv4 = (ip) => {
	const parts = String(ip).split(".");
	if (parts.length !== 4) return null;
	let n = 0;
	for (const p of parts) {
		const v = Number(p);
		if (!/^\d{1,3}$/.test(p) || v > 255) return null;
		n = n * 256 + v;
	}
	return n;
};

/** an IP address or an IPv4 network (a.b.c.d/n) against the address of the event */
const ipMatches = (value, ip) => {
	if (value === ip) return true;
	const [net, bits] = String(value).split("/");
	const a = ipv4(net);
	const b = ipv4(ip);
	const n = Number(bits);
	if (a === null || b === null || !bits || !Number.isInteger(n) || n < 0 || n > 32) return false;
	const size = 2 ** (32 - n);
	return Math.floor(a / size) === Math.floor(b / size);
};

/** values of the dynamic keys of the agent are regular expressions (match_query.cc) */
const textMatches = (value, text) => {
	if (value === text) return true;
	try {
		return new RegExp(`^(?:${value})$`).test(text);
	} catch {
		return false;
	}
};

/** key of a condition → does a value match the event; null: the event does not tell */
const CONDITION = {
	sourceIp: (v, e) => ipMatches(v, e.source_ip),
	sourceIdentifier: (v, e) => ipMatches(v, e.source_ip),
	url: (v, e) => textMatches(v, e.uri),
	hostName: (v, e) => textMatches(v.toLowerCase(), e.host),
	paramName: (v, e) =>
		e.parameter ? textMatches(v, e.parameter.split(".").pop()) || textMatches(v, e.parameter) : false,
	paramValue: (v, e) => (e.sample ? textMatches(v, e.sample) : false),
	protectionName: (v, e) => textMatches(v, e.incident_type),
	countryName: (v, e) => (e.source_country ? v.toLowerCase() === e.source_country.toLowerCase() : null),
	// the events keep the name of the country only
	countryCode: () => null,
	// x-nginxions (docs/WAF-POLICY.md 5.2)
	method: (v, e) => (e.method ? textMatches(v, e.method) : null),
	paramLocation: (v, e) => (e.location ? textMatches(v, e.location) : false),
	indicator: (v, e) => indicatorsOf(e).some((i) => textMatches(v, i)),
	// the events do not keep the headers
	headerName: () => null,
	headerValue: () => null,
};

/** indicators of an event ("a, b" or "[a, b]", as the agent logs them) */
const indicatorsOf = (e) =>
	String(e.indicators || "")
		.replace(/^\[|\]$/g, "")
		.split(", ")
		.filter(Boolean);

/** does the event have a value for the key (op exist); null: the event does not tell */
const HAS = {
	url: (e) => !!e.uri,
	sourceIp: (e) => !!e.source_ip,
	sourceIdentifier: (e) => !!e.source_ip,
	hostName: (e) => !!e.host,
	method: (e) => (e.method ? true : null),
	paramName: (e) => !!e.parameter,
	paramValue: (e) => !!e.sample,
	paramLocation: (e) => !!e.location,
	indicator: (e) => indicatorsOf(e).length > 0,
	protectionName: (e) => !!e.incident_type,
};

/** equals and in: any of the values; not-equals and not-in: none of them (as MatchQuery of the agent) */
const OP_GROUP = { equals: "equals", in: "equals", "not-equals": "not-in", "not-in": "not-in", exist: "exist" };

/** true, false, or null when the event does not tell */
export const exceptionMatches = (exception, event) => {
	// a key with an operator: its values (the agent groups them so, objects/format.js)
	const groups = new Map();
	for (const c of list(exception.condition)) {
		const op = OP_GROUP[c.op ?? "equals"];
		if (!op) return null;
		const id = `${c.key}\u0000${op}`;
		if (!groups.has(id)) groups.set(id, { key: c.key, op, values: [] });
		groups.get(id).values.push(String(c.value ?? ""));
	}
	if (!groups.size) return false;
	let unknown = false;
	for (const { key, op, values } of groups.values()) {
		let result;
		if (op === "exist") {
			result = HAS[key] ? HAS[key](event) : null;
		} else {
			const test = CONDITION[key];
			if (!test) return null;
			const results = values.map((v) => test(v, event));
			const any = results.includes(true) ? true : results.includes(null) ? null : false;
			result = op === "not-in" && any !== null ? !any : any;
		}
		if (result === null) unknown = true;
		else if (!result) return false;
	}
	return unknown ? null : true;
};

/** the rule of the agent for an event: the specific rule of the longest host[/path] it falls in, else the default */
export const ruleOf = (doc, event) => {
	const target = `${event.host}${event.uri || "/"}`;
	let best = null;
	for (const rule of list(doc.policies?.specificRules)) {
		const host = String(rule.host || "").toLowerCase();
		if (!host) continue;
		const hit = host.includes("/") ? target.startsWith(host) : event.host === host;
		if (hit && (!best || host.length > best.host.length)) best = rule;
	}
	return best ?? doc.policies?.default ?? {};
};

const MODE_VERDICT = (mode) =>
	mode === "inactive" ? "pass" : String(mode).startsWith("prevent") ? "prevent" : "detect";

/**
 * What the agent would do with an event under a policy.
 * @returns {"pass"|"detect"|"block"|"unknown"}
 */
export const verdictOf = (doc, event) => {
	const defaults = doc.policies?.default || {};
	const rule = ruleOf(doc, event);
	const exceptionNames = list(rule.exceptions).length ? rule.exceptions : list(defaults.exceptions);
	const exceptions = new Map(list(doc.exceptions).map((e) => [e.name, e]));
	let unknown = false;
	for (const name of exceptionNames) {
		const exception = exceptions.get(name);
		if (!exception) continue;
		const hit = exceptionMatches(exception, event);
		if (hit === null) {
			unknown = true;
			continue;
		}
		if (!hit) continue;
		if (exception.action === "accept" || exception.action === "skip") return "pass";
		if (exception.action === "drop") return "block";
		// suppressLog: the verdict stays, the log goes
	}
	const mode = rule.mode || defaults.mode || "inactive";
	const practices = new Map(list(doc.threatPreventionPractices).map((p) => [p.name, p]));
	const practiceName = list(rule.threatPreventionPractices)[0] ?? list(defaults.threatPreventionPractices)[0];
	const practice = practices.get(practiceName);
	const override = practice?.webAttacks?.overrideMode;
	const practiceMode = practice?.practiceMode && practice.practiceMode !== "inherited" ? practice.practiceMode : mode;
	const effective = override && override !== "inherited" ? override : practiceMode;
	let verdict = MODE_VERDICT(effective);
	if (verdict === "prevent") {
		const minimum = practice?.webAttacks?.minimumConfidence || "high";
		verdict = rank(event.confidence) >= rank(minimum) ? "block" : "detect";
	}
	return unknown ? "unknown" : verdict;
};

/**
 * The policy with another mode for the rules of a proxy host (its domains, not its locations): what "switch to
 * blocking" would do. Rule names as objects/store.js writes them.
 */
export const withHostMode = (doc, hostId, mode) => {
	const base = `npm-managed-specific-rule-proxyhost-${hostId}`;
	const out = structuredClone(doc);
	for (const rule of list(out.policies?.specificRules)) {
		if (rule.name === base || String(rule.name).startsWith(`${base}.`)) rule.mode = mode;
	}
	return out;
};

const SAMPLES = 20;

/**
 * How a change of the policy changes the verdicts of recent events.
 * @param {object} current    the policy in force (objects/format.js terms)
 * @param {object} candidate  the policy with the change
 * @param {object[]} events   rows of nginxions_security_event (WAF events)
 * @returns {{events: number, changed: number, toPass: number, toBlock: number, toDetect: number, unknown: number,
 *   samples: object[]}}
 */
export const simulate = (current, candidate, events) => {
	const out = { events: events.length, changed: 0, toPass: 0, toBlock: 0, toDetect: 0, unknown: 0, samples: [] };
	// one sample per host, path and verdicts: the list shows kinds of change, not a hundred of the same
	const groups = new Map();
	for (const event of events) {
		const before = verdictOf(current, event);
		const after = verdictOf(candidate, event);
		if (before === after) continue;
		if (after === "unknown" || before === "unknown") {
			out.unknown++;
			continue;
		}
		out.changed++;
		if (after === "pass") out.toPass++;
		else if (after === "block") out.toBlock++;
		else out.toDetect++;
		const key = `${event.host}|${event.uri}|${before}|${after}`;
		const group = groups.get(key);
		if (group) group.count++;
		else
			groups.set(key, {
				host: event.host,
				uri: event.uri,
				source_ip: event.source_ip,
				time: event.time,
				confidence: event.confidence,
				before,
				after,
				count: 1,
			});
	}
	out.samples = [...groups.values()].sort((a, b) => b.count - a.count).slice(0, SAMPLES);
	return out;
};
