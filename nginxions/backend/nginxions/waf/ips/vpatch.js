// Virtual patching rules of the CrowdSec hub (appsec-rules, MIT) → IPS protections of the agent (docs/WAF-POLICY.md,
// "IPS"). The IPS engine of open-appsec is in the open source agent, its signatures came only from the Check Point
// cloud: NginxionS gives it these instead (openappsec/agent/nginxions/ips-protections.json, made by
// scripts/update-ips-signatures.mjs), so that intrusionPrevention of a practice works with all its fields (severity,
// confidence, performance impact, CVE year, actions) and its events are events of the agent.
//
// A rule of the hub is a list of rules (any of them), each a condition or and/or of conditions; a condition matches a
// value of zones (URI, ARGS, HEADERS...) after transforms (lowercase, urldecode...). A protection of the agent is
// keywords (data, pcre) on contexts of the request (HTTP_PATH_DECODED, HTTP_QUERY_DECODED, HTTP_REQUEST_HEADER,
// HTTP_REQUEST_BODY...), all of them. So a rule becomes one protection per way it can match: a zone of several
// contexts (ARGS: the query or the body) and "or" give several. The IPS has the decoded path and query but the raw
// body: a value of the body is matched as sent (form, JSON or multipart), not decoded. A rule that needs what the IPS
// cannot do (libinjection, b64decode, length, counts) is left out and listed.
import { parse } from "yaml";

/** a condition the IPS cannot express */
export class Unsupported extends Error {}

const MAX_WAYS = 64;
const CONTEXT = {
	path: "HTTP_PATH_DECODED",
	url: "HTTP_COMPLETE_URL_DECODED",
	query: "HTTP_QUERY_DECODED",
	method: "HTTP_METHOD",
	headers: "HTTP_REQUEST_HEADER",
	body: "HTTP_REQUEST_BODY",
};
// transforms the IPS does itself (the path and query are decoded) or that change nothing a pattern sees
const HARMLESS = new Set(["lowercase", "uppercase", "urldecode", "trim", "normalizepath", "normalize_path"]);
const NOCASE = new Set(["lowercase", "uppercase"]);

/** a literal in a PCRE pattern (the keyword engine keeps backslashes, a quote must be escaped for it) */
export const escapeRegex = (s) =>
	[...String(s)]
		.map((c) => {
			const code = c.codePointAt(0);
			if (code < 0x20 || code === 0x7f) return `\\x${code.toString(16).padStart(2, "0")}`;
			return /[\\^$.|?*+()[\]{}/"-]/.test(c) ? `\\${c}` : c;
		})
		.join("");

/** a literal in a data keyword: \ " | escaped, the rest printable or as |hex| */
export const escapeData = (s) =>
	[...Buffer.from(String(s), "utf8")]
		.map((b) => {
			if (b < 0x20 || b >= 0x7f) return `|${b.toString(16).padStart(2, "0")}|`;
			const c = String.fromCharCode(b);
			return c === "\\" || c === '"' || c === "|" ? `\\${c}` : c;
		})
		.join("")
		.replaceAll("||", "");

/** a regular expression of a rule (RE2) for PCRE: quotes escaped for the keyword engine */
const fromRe2 = (re) => {
	let out = "";
	for (let i = 0; i < re.length; i++) {
		const c = re[i];
		if (c === "\\") {
			out += c + (re[i + 1] ?? "");
			i++;
		} else if (c === '"') out += '\\"';
		else out += c;
	}
	return out;
};

/**
 * The value a condition matches, as a regular expression: body without its anchors and whether it is anchored at
 * the start or the end of the value; literal for a match a data keyword can do (contains).
 */
export const matchValue = (match) => {
	const value = String(match?.value ?? "");
	switch (match?.type) {
		case "equals":
			return { body: escapeRegex(value), start: true, end: true };
		case "contains":
			return { body: escapeRegex(value), start: false, end: false, literal: value };
		case "startsWith":
			return { body: escapeRegex(value), start: true, end: false };
		case "endsWith":
			return { body: escapeRegex(value), start: false, end: true };
		case "regex": {
			let re = value;
			let start = false;
			let end = false;
			// a leading (?i) of RE2: the flag i of the pattern
			const nocase = re.startsWith("(?i)");
			if (nocase) re = re.slice(4);
			if (re.startsWith("^")) {
				start = true;
				re = re.slice(1);
			}
			// a $ at the end, not escaped
			if (/(^|[^\\])(\\\\)*\$$/.test(re)) {
				end = true;
				re = re.slice(0, -1);
			}
			return { body: `(?:${fromRe2(re)})`, start, end, nocase };
		}
		default:
			throw new Unsupported(`match ${match?.type}`);
	}
};

/** quotes of a pattern escaped (the keyword engine reads the pattern as a quoted string) */
const quoted = (pattern) => {
	let out = "";
	for (let i = 0; i < pattern.length; i++) {
		const c = pattern[i];
		if (c === "\\") {
			out += c + (pattern[i + 1] ?? "");
			i++;
		} else out += c === '"' ? '\\"' : c;
	}
	return out;
};
const pcre = (pattern, flags, context) => ({
	keyword: `pcre: "/${quoted(pattern)}/${flags}", part ${context}`,
	context,
});
const data = (literal, nocase, context) => ({
	keyword: `data: "${escapeData(literal)}"${nocase ? ", nocase" : ""}, part ${context}`,
	context,
});

/** the value of a whole buffer (path, method...) */
const whole = (v, nocase, context) =>
	v.literal !== undefined
		? data(v.literal, nocase, context)
		: pcre(`${v.start ? "^" : ""}${v.body}${v.end ? "$" : ""}`, nocase ? "i" : "", context);

/**
 * A regular expression kept inside a value: an unescaped "." and a negated class [^...] of it do not match the
 * delimiters of the value (a value "[^0-9]+" of a form argument would otherwise run into the next argument).
 */
export const bounded = (body, delims) => {
	let out = "";
	let inClass = false;
	for (let i = 0; i < body.length; i++) {
		const c = body[i];
		if (c === "\\") {
			out += c + (body[i + 1] ?? "");
			i++;
		} else if (inClass) {
			if (c === "]") inClass = false;
			out += c;
		} else if (c === "[") {
			const negated = body[i + 1] === "^";
			out += negated ? "[^" : "[";
			if (negated) i++;
			// a ] first in a class is a character
			if (body[i + 1] === "]") {
				out += "\\]";
				i++;
			}
			// the delimiters first: at the end they could make a range with a "-" before them
			if (negated) out += delims;
			inClass = true;
		} else if (c === ".") out += `[^${delims}]`;
		else out += c;
	}
	return out;
};

/** a value between delimiters: before it anything but them (if not anchored), after it a lookahead */
const inValue = (v, delims, after) =>
	`${v.start ? "" : `[^${delims}]*?`}${v.literal !== undefined ? v.body : bounded(v.body, delims)}${v.end ? `(?=${after})` : ""}`;

const names = (variables, other) =>
	variables?.length ? `(?:${variables.map((n) => escapeRegex(n)).join("|")})` : other;

/** the keywords (one per way) of a value of arguments in the query, the body, or both */
const args = (where, v, variables, nocase) => {
	const flags = nocase ? "i" : "";
	const out = [];
	const form = `(?:^|&)${names(variables, "[^=&]+")}=${inValue(v, "&", "&|$")}`;
	// no name and contains: anywhere in the buffer (a value of any argument)
	const anywhere = !variables?.length && v.literal !== undefined;
	if (where.includes("query"))
		out.push(anywhere ? data(v.literal, nocase, CONTEXT.query) : pcre(form, flags, CONTEXT.query));
	if (where.includes("body")) {
		if (anywhere) out.push(data(v.literal, nocase, CONTEXT.body));
		else {
			const n = names(variables, '[^"=&]+');
			const json = `"${n}"\\s*:\\s*"?${inValue(v, '"', '["},\\]\\s]')}`;
			const multipart = `name="${n}"[^\\r\\n]*\\r?\\n(?:[^\\r\\n]+\\r?\\n)*\\r?\\n${inValue(v, "\\r\\n", "\\r?\\n")}`;
			out.push(pcre(`${form}|${json}|${multipart}`, flags, CONTEXT.body));
		}
	}
	return out;
};

/** the keywords of the names of arguments */
const argNames = (where, v, nocase) => {
	const flags = nocase ? "i" : "";
	const out = [];
	const form = `(?:^|&)${inValue(v, "=&", "=|&|$")}`;
	if (where.includes("query")) out.push(pcre(form, flags, CONTEXT.query));
	if (where.includes("body")) {
		const json = `"${inValue(v, '"', '"\\s*:')}"\\s*:`;
		const multipart = `name="${inValue(v, '"', '"')}"`;
		out.push(pcre(`${form}|${json}|${multipart}`, flags, CONTEXT.body));
	}
	return out;
};

/**
 * The ways a condition matches: each a list of keywords (all of them).
 * @param {{zones: string[], variables?: string[], transform?: string[], match: {type: string, value: string}}} cond
 */
export const conditionWays = (cond) => {
	const transforms = (cond.transform ?? []).map((t) => String(t).toLowerCase());
	for (const t of transforms) if (!HARMLESS.has(t)) throw new Unsupported(`transform ${t}`);
	const v = matchValue(cond.match);
	const nocase = v.nocase || transforms.some((t) => NOCASE.has(t));
	const variables = (cond.variables ?? []).map(String);
	const ways = [];
	for (const zone of cond.zones ?? []) {
		switch (zone) {
			case "URI":
				ways.push(whole(v, nocase, CONTEXT.path));
				break;
			case "URI_FULL":
				ways.push(whole(v, nocase, CONTEXT.url));
				break;
			case "METHOD":
				ways.push(whole(v, nocase, CONTEXT.method));
				break;
			case "RAW_BODY":
				ways.push(whole(v, nocase, CONTEXT.body));
				break;
			case "ARGS":
				ways.push(...args(["query", "body"], v, variables, nocase));
				break;
			case "ARGS_GET":
				ways.push(...args(["query"], v, variables, nocase));
				break;
			case "BODY_ARGS":
			case "ARGS_POST":
				ways.push(...args(["body"], v, variables, nocase));
				break;
			case "ARGS_NAMES":
				ways.push(...argNames(["query", "body"], v, nocase));
				break;
			case "BODY_ARGS_NAMES":
				ways.push(...argNames(["body"], v, nocase));
				break;
			case "HEADERS": {
				// the IPS keeps the headers as "Name: value\r\n" lines; names in any case
				const n = variables.length ? `(?i:${variables.map((x) => escapeRegex(x)).join("|")})` : "[^:\\r\\n]+";
				ways.push(pcre(`^${n}:[ \\t]*${inValue(v, "\\r\\n", "\\r?$")}`, nocase ? "mi" : "m", CONTEXT.headers));
				break;
			}
			case "HEADERS_NAMES":
				ways.push(pcre(`^${inValue(v, ":\\r\\n", ":")}:`, "mi", CONTEXT.headers));
				break;
			case "COOKIES": {
				const n = names(variables, "[^=;\\s]+");
				const value = inValue(v, ";\\r\\n", ";|\\r?$");
				ways.push(
					pcre(`^(?i:cookie):[^\\r\\n]*?(?:[:;][ \\t]*)${n}=${value}`, nocase ? "mi" : "m", CONTEXT.headers),
				);
				break;
			}
			case "COOKIES_NAMES":
				ways.push(
					pcre(
						`^(?i:cookie):[^\\r\\n]*?(?:[:;][ \\t]*)${inValue(v, "=;\\r\\n", "=")}=`,
						nocase ? "mi" : "m",
						CONTEXT.headers,
					),
				);
				break;
			case "FILENAMES":
				ways.push(pcre(`filename="${inValue(v, '"', '"')}"`, nocase ? "i" : "", CONTEXT.body));
				break;
			case "FILES_NAMES":
				ways.push(pcre(`name="${inValue(v, '"', '"')}"; *filename=`, nocase ? "i" : "", CONTEXT.body));
				break;
			default:
				throw new Unsupported(`zone ${zone}`);
		}
	}
	if (!ways.length) throw new Unsupported("no zone");
	return ways.map((w) => [w]);
};

/** the ways of a node of a rule: a condition, and (all), or (any) */
export const nodeWays = (node) => {
	if (Array.isArray(node?.and)) {
		let ways = [[]];
		for (const operand of node.and) {
			const next = [];
			for (const a of ways) for (const b of nodeWays(operand)) next.push([...a, ...b]);
			if (next.length > MAX_WAYS) throw new Unsupported(`more than ${MAX_WAYS} ways to match`);
			ways = next;
		}
		return ways;
	}
	if (Array.isArray(node?.or)) {
		const ways = node.or.flatMap(nodeWays);
		if (ways.length > MAX_WAYS) throw new Unsupported(`more than ${MAX_WAYS} ways to match`);
		return ways;
	}
	if (node?.zones) return conditionWays(node);
	throw new Unsupported("unknown node");
};

// weaknesses (CWE) of remote code execution, injection, deserialization, authentication bypass and the like
const CRITICAL_CWE = new Set([77, 78, 94, 95, 98, 502, 917, 1336, 287, 288, 306, 290, 434]);
const HIGH_CWE = new Set([22, 23, 35, 89, 90, 91, 611, 918, 862, 863, 639, 425, 73, 284, 285, 269, 521, 798]);
const MEDIUM_CWE = new Set([79, 80, 352, 601, 200, 209, 497, 538, 548, 552, 444]);

/** the severity of a rule by its weaknesses (the hub gives none): the most severe of them, High by default */
export const severityOf = (classification) => {
	const cwes = classification
		.map((c) => /^cwe\.CWE-(\d+)$/i.exec(c)?.[1])
		.filter(Boolean)
		.map(Number);
	if (cwes.some((c) => CRITICAL_CWE.has(c))) return "Critical";
	if (cwes.some((c) => HIGH_CWE.has(c))) return "High";
	if (cwes.some((c) => MEDIUM_CWE.has(c))) return "Medium";
	return "High";
};

/** performance impact: data keywords only Low, a pattern Medium, a pattern on the body High */
const performanceOf = (keywords) => {
	const body = keywords.some((k) => k.context === CONTEXT.body && k.keyword.startsWith("pcre"));
	if (body) return "High";
	return keywords.some((k) => k.keyword.startsWith("pcre") || k.context === CONTEXT.body) ? "Medium" : "Low";
};

/**
 * The protections of a rule of the hub.
 * @param {object} doc  the rule (parsed YAML)
 * @param {{lastUpdate: string}} options  YYYYMMDD of the hub
 * @returns {object[]} protections (format of the IPS: protectionMetadata, detectionRules)
 */
export const ruleToProtections = (doc, { lastUpdate }) => {
	if (!doc?.name || !Array.isArray(doc.rules)) throw new Unsupported("not a rule");
	const ways = [];
	for (const rule of doc.rules) ways.push(...nodeWays(rule));
	if (ways.length > MAX_WAYS) throw new Unsupported(`more than ${MAX_WAYS} ways to match`);
	const labels = doc.labels ?? {};
	const classification = (labels.classification ?? []).map(String);
	const cves = [
		...new Set(
			[...classification, doc.name]
				.map((c) => /CVE-(\d{4})-(\d{4,})/i.exec(c))
				.filter(Boolean)
				.map((m) => `CVE-${m[1]}-${m[2]}`),
		),
	];
	const year = cves.map((c) => Number(c.slice(4, 8))).sort()[0];
	const confidence =
		Number(labels.confidence ?? 3) >= 3 ? "High" : Number(labels.confidence) === 2 ? "Medium" : "Low";
	const tags = [
		"NginxionS",
		"CrowdSec_Virtual_Patching",
		...(year ? [`Threat_Year_${year}`] : []),
		...classification.filter((c) => /^cwe\./i.test(c)).map((c) => `Vul_Type_${c.slice(4).toUpperCase()}`),
	];
	const name = String(doc.description || labels.label || doc.name).slice(0, 255);
	return ways.map((keywords, i) => ({
		protectionMetadata: {
			protectionName: name,
			severity: severityOf(classification),
			confidenceLevel: confidence,
			performanceImpact: performanceOf(keywords),
			lastUpdate,
			maintrainId: ways.length > 1 ? `${doc.name}#${i + 1}` : doc.name,
			tags,
			cveList: cves,
			silent: false,
		},
		detectionRules: {
			type: "simple",
			SSM: "",
			keywords: keywords.map((k) => `${k.keyword};`).join(" "),
			context: [...new Set(keywords.map((k) => k.context))],
		},
	}));
};

/**
 * The protections of rules of the hub (YAML texts) and the rules left out.
 * @param {{name: string, text: string}[]} rules
 * @param {{lastUpdate: string}} options
 */
export const convertRules = (rules, options) => {
	const protections = [];
	const skipped = [];
	for (const { name, text } of rules) {
		try {
			protections.push(...ruleToProtections(parse(text), options));
		} catch (err) {
			if (!(err instanceof Unsupported)) throw err;
			skipped.push({ name, reason: err.message });
		}
	}
	return { protections, skipped };
};
