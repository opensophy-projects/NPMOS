#!/usr/bin/env node
// NginxionS: the converter of Snort 3 signatures to IPS protections of the agent, in JavaScript (Node.js of the image
// runs nginxions-control). It replaces snort_to_ips_local.py and snort3_to_ips/ (kept in this directory as the
// reference: snort_to_ips_local.test.mjs checks that both give the same output), so the agent image has no Python
// (its CVEs, and the ones of SQLite it brings: Grype). The agent runs it from the local policy
// (policy_maker_utils.cc, createSnortProtecionsSection):
//
//   node snort_to_ips_local.mjs <snort rules file> <output file> <errors file>
//
// The logic, the messages and the order of the fields are those of the Python code, line by line. As there, an error
// of a rule raised on purpose (SnortHookException) is written to the errors file, any other one only skips the rule.

import { readFileSync, writeFileSync } from "node:fs";

class SnortHookException extends Error {}

// str[a:b] of Python (negative indexes count from the end)
const pySlice = (s, a = 0, b = s.length) => {
	const n = s.length;
	const at = (i) => (i < 0 ? Math.max(0, n + i) : Math.min(i, n));
	return s.slice(at(a), at(b));
};
// str.find(sub, start) and str.rfind(sub, start) of Python
const find = (s, sub, start) => s.indexOf(sub, start);
const rfind = (s, sub, start) => {
	const i = s.lastIndexOf(sub);
	return i >= start ? i : -1;
};
// str.strip(chars) of Python
const strip = (s, chars) => {
	if (chars === undefined) return s.trim();
	let a = 0;
	let b = s.length;
	while (a < b && chars.includes(s[a])) a++;
	while (b > a && chars.includes(s[b - 1])) b--;
	return s.slice(a, b);
};
// "a, b = s.split(sep)" of Python: a ValueError unless there are exactly two parts
const split2 = (s, sep) => {
	const parts = s.split(sep);
	if (parts.length !== 2) throw new Error(`not enough or too many values to unpack (${parts.length})`);
	return parts;
};
// s.split(sep, 1) of Python
const splitOnce = (s, sep) => {
	const i = s.indexOf(sep);
	return i < 0 ? [s] : [s.slice(0, i), s.slice(i + sep.length)];
};
// list index of Python: an IndexError out of range
const item = (list, i) => {
	if (i >= list.length) throw new Error("list index out of range");
	return list[i];
};
// dict[key] of Python: a KeyError if missing
const key = (dict, k) => {
	if (!Object.hasOwn(dict, k)) throw new Error(`KeyError: '${k}'`);
	return dict[k];
};
const isNumeric = (s) => /^\d+$/.test(s);
const title = (s) => s.replace(/[A-Za-z]+/g, (w) => w[0].toUpperCase() + w.slice(1).toLowerCase());
const isHexSegmentInStr = (value) => value.split("|").length - 1 - (value.split("\\|").length - 1) > 0;

// --- utils/utils.py ---
const parseSnortRulesLine = (line) => {
	const open = line.indexOf("(");
	const header = pySlice(line, 0, open).trim();
	const tmpBody = pySlice(line, open + 1, line.lastIndexOf(")")).replaceAll("\n", "").trim().split(";");
	const body = [];
	let segment = "";
	for (let rule of tmpBody) {
		if (rule.length === 0) continue;
		rule = rule.trim();
		if (rule[rule.length - 1] === "\\") {
			segment += `${rule.slice(0, -1)};`;
		} else {
			body.push(segment + rule);
			segment = "";
		}
	}
	return [header, body];
};
const isInvalidLine = (line) => {
	const t = line.trim();
	return t.length === 0 || t[0] === "#";
};

// --- SnortRule/SnortRuleHeader.py ---
class SnortRuleHeader {
	constructor(header) {
		this.rules = {};
		const list = header.split(" ");
		if (list.length === 2) {
			this.action(list[0]);
			this.protocol(list[1]);
			this.rules.source_ports = "";
			this.rules.destination_ports = "";
			this.rules.directional_op = "";
		} else if (list.length === 7) {
			this.action(list[0]);
			this.protocol(list[1]);
			if (!["->", "<>"].includes(list[4])) {
				throw new SnortHookException(`Error: Unknown unsupported header directional operator ${list[4]}`);
			}
			this.rules.directional_op = list[4];
			this.rules.source_ports = list[3] === "$HTTP_PORTS" ? list[3] : "";
			this.rules.destination_ports = list[6] === "$HTTP_PORTS" ? list[6] : "";
		} else {
			throw new SnortHookException("Invalid Snort rule header");
		}
	}

	action(action) {
		if (action === "drop") this.rules.action = action;
		else if (!["alert", "log", "pass", "reject", "sdrop"].includes(action)) {
			throw new SnortHookException(`Unknown header action ${action}`);
		}
	}

	protocol(protocol) {
		if (!["http", "tcp", "udp", "icmp", "ip", "file"].includes(protocol)) {
			throw new SnortHookException(`Error: Unknown header protocol ${protocol}`);
		}
		this.rules.protocol = protocol;
	}

	isHttpHeader() {
		return this.rules.protocol === "http" || this.rules.destination_ports === "$HTTP_PORTS";
	}
}

// --- SnortRule/SnortKWParser.py ---
const PRIORITY = { 1: "High", 2: "Medium", 3: "Low", 4: "Very Low" };
const CLASSIFICATIONS = {
	"attempted-admin": "High",
	"attempted-user": "High",
	"inappropriate-content": "High",
	"policy-violation": "High",
	"shellcode-detect": "High",
	"successful-admin": "High",
	"successful-user": "High",
	"trojan-activity": "High",
	"unsuccessful-user": "High",
	"web-application-attack": "High",
	"attempted-dos": "Medium",
	"attempted-recon": "Medium",
	"bad-unknown": "Medium",
	"default-login-attempt": "Medium",
	"denial-of-service": "Medium",
	"misc-attack": "Medium",
	"non-standard-protocol": "Medium",
	"rpc-portmap-decode": "Medium",
	"successful-dos": "Medium",
	"successful-recon-largescale": "Medium",
	"successful-recon-limited": "Medium",
	"suspicious-filename-detect": "Medium",
	"suspicious-login": "Medium",
	"system-call-detect": "Medium",
	"unusual-client-port-connection": "Medium",
	"web-application-activity": "Medium",
	"icmp-event": "Low",
	"misc-activity": "Low",
	"network-scan": "Low",
	"not-suspicious": "Low",
	"protocol-command-decode": "Low",
	"string-detect": "Low",
	unknown: "Low",
	"tcp-connection": "Very Low",
};

const simpleRule = (rule) => [rule.trim(), "", {}];
const simpleBinaryRule = (rule) => [...split2(rule, ":"), {}];
const parseContent = (rule) => {
	const [keyword, rest] = splitOnce(rule, ":");
	const value = pySlice(rest, 0, find(rest, '"', 2) + 1).trim();
	const optional = strip(pySlice(rest, find(rest, '"', 2) + 1), ",").trim();
	if (optional === "") return [keyword, value, {}];
	const modifiers = {};
	for (let command of optional.split(",")) {
		command = command.trim();
		const parts = splitOnce(command.trim(), " ");
		modifiers[parts[0]] = parts.length === 1 ? true : parts[1];
	}
	return [keyword, value, modifiers];
};
const parsePcre = (rule) => {
	const [keyword, rest] = splitOnce(rule, ":");
	const value = pySlice(rest, 0, rfind(rest, '"', 2) + 1).trim();
	const optional = pySlice(rest, rfind(rest, "/", 1) + 1, rfind(rest, '"', 1)).trim();
	for (const modifier of optional) {
		if ("ismxGARE".includes(modifier)) continue;
		if (modifier === "O") throw new SnortHookException(`unsupported ${keyword} modifier ${modifier}`);
		throw new SnortHookException(`Unknown ${keyword} modifier ${modifier}`);
	}
	return [keyword, value, {}];
};
const parseReference = (rule) => {
	const keyword = rule.split(":")[0];
	const value = item(rule.split(":"), 1).split(",")[0];
	return [keyword, value, { [value]: item(item(rule.split(":"), 1).split(","), 1) }];
};
const parseClasstype = (rule) => {
	const keyword = rule.split(":")[0];
	const value = item(rule.split(":"), 1).trim();
	return [keyword, value, { [value]: key(CLASSIFICATIONS, value) }];
};
const parsePriority = (rule) => {
	const keyword = rule.split(":")[0];
	const text = item(rule.split(":"), 1).trim();
	if (!/^[+-]?\d+$/.test(text)) throw new Error(`invalid literal for int(): '${text}'`);
	let value = Number.parseInt(text, 10);
	if (value > 4) value = 4;
	return [keyword, key(PRIORITY, value), {}];
};
const parseStickyBuffer = (rule) => {
	const split = splitOnce(rule, ":");
	if (split.length === 2) {
		const args = split[1].split(" ");
		return [split[0], args[0].trim(), { [args[0].trim()]: item(args, 1).trim() }];
	}
	return [rule.trim(), "", {}];
};
const parseMetadata = (rule) => {
	const [keyword, value] = split2(rule, ":");
	for (const metadata of value.split(",")) {
		if (splitOnce(metadata.trim(), " ").length !== 2) throw new Error("not enough values to unpack");
	}
	return [keyword, "", {}];
};
const parseFlow = (rule) => {
	const [keyword, value] = split2(rule, ":");
	return [keyword, value, value.split(",").map((m) => m.trim())];
};
const parseService = (rule) => [...split2(rule, ":"), {}];
const notImplementedKw = (rule) => {
	throw new SnortHookException(`unsupported keyword '${rule.split(":")[0]}'`);
};
const PARSERS = {
	content: parseContent,
	pcre: parsePcre,
	flow: parseFlow,
	bufferlen: simpleBinaryRule,
	msg: simpleBinaryRule,
	reference: parseReference,
	gid: simpleBinaryRule,
	sid: simpleBinaryRule,
	rev: simpleBinaryRule,
	classtype: parseClasstype,
	priority: parsePriority,
	metadata: parseMetadata,
	pkt_data: simpleRule,
	http_uri: parseStickyBuffer,
	http_raw_uri: parseStickyBuffer,
	http_header: parseStickyBuffer,
	http_raw_header: parseStickyBuffer,
	http_method: parseStickyBuffer,
	http_client_body: parseStickyBuffer,
	http_cookie: parseStickyBuffer,
	http_stat_code: parseStickyBuffer,
	http_stat_msg: parseStickyBuffer,
	http_raw_cookie: parseStickyBuffer,
	service: parseService,
};
for (const k of [
	"byte_test",
	"file_data",
	"byte_jump",
	"isdataat",
	"dsize",
	"icode",
	"flowbits",
	"itype",
	"dce_iface",
	"cmp_id",
	"detection_filter",
	"flags",
	"sip_stat_code",
	"ack",
	"ip_proto",
	"sip_method",
	"asn1",
	"ssl_version",
	"base64_decode",
	"ssl_state",
	"sip_header",
	"fragbits",
]) {
	PARSERS[k] = notImplementedKw;
}
const parseKwParameters = (rule) => key(PARSERS, rule.split(":")[0])(rule);

// --- Signature/IpsKW.py ---
class IpsKW {
	constructor(keyword, value, modifiers) {
		this.keyword = keyword;
		this.value = value;
		this.modifiers = modifiers;
	}

	construct() {
		return key(IPS_CONSTRUCT, this.keyword)(this);
	}
}
const constructDetection = (kw) => {
	const out = [];
	let mods = "";
	for (const [k, v] of Object.entries(kw.modifiers)) {
		if (k === "nocase" || k === "relative") mods += `, ${k}`;
		else if (k === "depth") mods += `, ${k} ${v}`;
		else if (k === "offset") {
			if (v === 0) continue;
			mods += `, ${k} ${v}`;
		} else if (k === "part") {
			mods += `, ${k} ${v}`;
			out.push(["context", v]);
		} else throw new SnortHookException(`Error: Key '${k}' is not supported in keywords`);
	}
	out.push(["keywords", `data: ${kw.value}${mods};`]);
	return out;
};
const constructPcre = (kw) => {
	const out = [];
	let mods = "";
	for (const [k, v] of Object.entries(kw.modifiers)) {
		if (k === "nocase" || k === "relative") mods += `, ${k}`;
		else if (k === "offset") {
			if (v === 0) continue;
			mods += `, ${k} ${v}`;
		} else if (k === "part") {
			mods += `, ${k} ${v}`;
			out.push(["context", v]);
		} else throw new SnortHookException(`Error: Key ${k} is not supported in pcre`);
	}
	out.push(["keywords", `pcre: ${kw.value}${mods};`]);
	return out;
};
const constructSsm = (kw) => {
	const out = [];
	for (const [k, v] of Object.entries(kw.modifiers)) if (k === "part") out.push(["context", v]);
	out.push(["SSM", strip(kw.value, '"')]);
	return out;
};
const IPS_CONSTRUCT = {
	protectionName: (kw) => [["protectionName", kw.value]],
	keywords: constructDetection,
	length: (kw) => [
		["keywords", `${kw.keyword}: ${key(kw.modifiers, "var")}, ${kw.value}, part ${key(kw.modifiers, "part")};`],
	],
	SSM: constructSsm,
	tags: (kw) => [[kw.keyword, `Vul_Type_${kw.value}`]],
	pcre: constructPcre,
	cveList: (kw) => [[kw.keyword, kw.value]],
	severity: (kw) => [[kw.keyword, kw.value]],
	sid: (kw) => [["maintrainId", `${kw.keyword}:${kw.value}`]],
	rev: (kw) => [["maintrainId", `${kw.keyword}:${kw.value}`]],
};

// --- Signature/ProtectionMetadata.py, DetectionRules.py, IpsSignature.py ---
class IpsSignature {
	constructor() {
		this.meta = {
			protectionName: "",
			severity: "",
			confidenceLevel: "",
			performanceImpact: "",
			lastUpdate: "",
			maintrainId: "",
			tags: ["Snort"],
			cveList: [],
			silent: false,
		};
		this.rules = { type: "simple", SSM: "", keywords: "", context: [] };
	}

	parseData(constructs) {
		for (const [k, v] of constructs) {
			if (Object.hasOwn(this.meta, k)) this.parseMeta(k, v);
			else if (Object.hasOwn(this.rules, k)) this.parseRule(k, v);
			else throw new SnortHookException(`'${k}' is not a valid keyword in snort signature`);
		}
	}

	parseMeta(k, v) {
		if (k === "protectionName" || k === "severity") this.meta[k] = v;
		else if (k === "maintrainId") this.meta[k] += (this.meta[k] !== "" ? " " : "") + v;
		else if (k === "tags" || k === "cveList") {
			if (!this.meta[k].includes(v)) this.meta[k].push(v);
		}
		// confidenceLevel, performanceImpact, lastUpdate, silent: not implemented (Python prints a line)
	}

	parseRule(k, v) {
		if (k === "keywords") this.rules.keywords += (this.rules.keywords.length !== 0 ? " " : "") + v;
		else if (k === "context") {
			if (!this.rules.context.includes(v)) this.rules.context.push(v);
		} else if (k === "SSM") {
			if (this.rules.SSM !== "") throw new SnortHookException("two fast_pattern content");
			this.rules.SSM += v;
		} else throw new SnortHookException("DetectionRules of type not implemented");
	}

	output() {
		if (this.meta.protectionName.length === 0) throw new Error("msg field missing in the snort rule");
		if (!(this.rules.context.length && (this.rules.keywords.length || this.rules.SSM.length))) {
			throw new SnortHookException("No detection rule in the rule");
		}
		if (this.meta.severity === "") this.meta.severity = "Critical";
		if (this.meta.confidenceLevel === "") this.meta.confidenceLevel = "High";
		if (this.meta.performanceImpact === "") this.meta.performanceImpact = "Medium";
		if (this.meta.lastUpdate === "") this.meta.lastUpdate = "20210909";
		return { protectionMetadata: this.meta, detectionRules: this.rules };
	}
}

// --- SnortRule/SnortRule.py, SnortKW.py ---
class SnortRule {
	constructor(header) {
		this.header = new SnortRuleHeader(header);
		this.keywords = [];
		this.stickyBuffer = "Default";
		this.dynamicBuffer = {};
		this.flow = "client_to_server";
	}

	isHttpRule(body) {
		return this.header.isHttpHeader() || body.includes("service:http");
	}

	parseBody(body) {
		for (const rule of body) {
			const [keyword, value, modifiers] = parseKwParameters(rule);
			this.keywords.push({ keyword, value, modifiers });
		}
	}

	convert() {
		const signature = new IpsSignature();
		for (const kw of this.keywords) {
			for (const ips of key(SNORT_CONVERT, kw.keyword)(kw, this)) signature.parseData(ips.construct());
		}
		return signature.output();
	}

	byFlow(request, response) {
		if (this.flow === "client_to_server") return request;
		if (this.flow === "server_to_client") return response;
		throw new SnortHookException(`Unknown Flow ${this.flow}`);
	}

	context() {
		switch (this.stickyBuffer) {
			case "Default":
				return { part: "HTTP_RAW" };
			case "pkt_data":
				throw new SnortHookException("Unsupported keyword 'pkt_data'");
			case "http_uri":
				return { part: "HTTP_COMPLETE_URL_DECODED" };
			case "http_raw_uri":
				return { part: "HTTP_COMPLETE_URL_ENCODED" };
			case "http_header": {
				const field = Object.hasOwn(this.dynamicBuffer, "field") ? `_${this.dynamicBuffer.field.toUpperCase()}` : "";
				return this.byFlow({ part: `HTTP_REQUEST_HEADER${field}` }, { part: `HTTP_RESPONSE_HEADER${field}` });
			}
			case "http_raw_header":
				return this.byFlow({ part: "HTTP_REQUEST_HEADER" }, { part: "HTTP_RESPONSE_HEADER" });
			case "http_method":
				return { part: "HTTP_METHOD" };
			case "http_client_body":
				return { part: "HTTP_REQUEST_BODY" };
			case "http_cookie":
			case "http_raw_cookie":
				return this.byFlow({ part: "HTTP_REQUEST_HEADER_COOKIE" }, { part: "HTTP_RESPONSE_HEADER_COOKIE" });
			case "http_stat_code":
				if (this.flow === "client_to_server") {
					throw new SnortHookException("http_stat_code isn't supported with flow: to_server, from_client");
				}
				return this.byFlow(null, { part: "HTTP_RESPONSE_CODE" });
			default:
				throw new SnortHookException(`unsupported keyword '${this.stickyBuffer}'`);
		}
	}
}

const contentModifiers = (kw, rule) => {
	const mods = {};
	for (const [k, v] of Object.entries(kw.modifiers)) {
		if (k === "nocase") mods.nocase = v;
		else if (k === "depth") mods.depth = v;
		else if (k === "distance") {
			if (pyInt(v) !== 0) mods.offset = v;
			mods.relative = true;
		} else if (k === "offset") {
			if (pyInt(v) !== 0) mods.offset = v;
		} else if (k === "within") {
			mods.depth = v;
			mods.relative = true;
		} else if (k === "fast_pattern") mods.fast_pattern = true;
		else throw new SnortHookException(`For keyword '${kw.keyword}', unsupported modifier '${k}'`);
	}
	return Object.assign(mods, rule.context());
};
// int() of Python on a modifier (a string, or True for a modifier without a value)
const pyInt = (v) => {
	if (v === true) return 1;
	const t = String(v).trim();
	if (!/^[+-]?\d+$/.test(t)) throw new Error(`invalid literal for int(): '${v}'`);
	return Number.parseInt(t, 10);
};
const bufferlen = (kw, rule) => {
	const out = [];
	const v = kw.value;
	let mods = rule.context();
	const minMax = (sep) => {
		const [left, right] = split2(v, sep);
		if (!isNumeric(left) || !isNumeric(right)) throw new SnortHookException("bufferlen - illegal numerical value");
		mods.var = left;
		out.push(new IpsKW("length", "min", mods));
		mods = rule.context();
		mods.var = right;
		out.push(new IpsKW("length", "max", mods));
	};
	if (v.includes("<=>")) minMax("<=>");
	else if (v.includes("<>")) minMax("<>");
	else if (v.includes("<")) {
		if (!isNumeric(item(v.split("<"), 1))) throw new SnortHookException("bufferlen - illegal numerical value");
		mods.var = v.split("<")[1];
		out.push(new IpsKW("length", "max", mods));
	} else if (v.includes(">")) {
		mods.var = v.split(">")[1];
		if (!isNumeric(v.split(">")[1])) throw new SnortHookException("bufferlen - illegal numerical value");
		out.push(new IpsKW("length", "min", mods));
	} else if (isNumeric(v)) {
		mods.var = v;
		out.push(new IpsKW("length", "exact", mods));
	} else throw new SnortHookException("bufferlen operator is illegal");
	return out;
};
const REFERENCES = {
	bugtraq: "BUGTRAQ-",
	cve: "CVE-",
	nessus: "NESSUS-",
	arachnids: "ARACHNIDS-",
	mcafee: "MCAFEE-",
	osvdb: "OSVDB-",
	msb: "MSB-",
	url: "http://",
};
const stickyBuffer = (kw, rule) => {
	rule.stickyBuffer = kw.keyword;
	if (kw.value !== "") {
		if (kw.keyword !== "http_header") {
			throw new SnortHookException(`arguments are not supported for '${kw.keyword}' of value '${kw.value}'`);
		}
		if (kw.value === "field") rule.dynamicBuffer = kw.modifiers;
		else throw new SnortHookException(`Unknown argument for '${kw.keyword}', '${kw.value}'`);
	}
	return [];
};
const none = () => [];
const SNORT_CONVERT = {
	content: (kw, rule) => {
		const mods = contentModifiers(kw, rule);
		const fast = mods.fast_pattern ?? false;
		delete mods.fast_pattern;
		if (fast && !isHexSegmentInStr(kw.value)) return [new IpsKW("SSM", kw.value, mods)];
		return [new IpsKW("keywords", kw.value, mods)];
	},
	pcre: (kw, rule) => [new IpsKW("pcre", kw.value, rule.context())],
	bufferlen,
	flow: (kw, rule) => {
		for (const m of kw.modifiers) {
			if (m === "to_server" || m === "from_client") rule.flow = "client_to_server";
			else if (m === "to_client" || m === "from_server") rule.flow = "server_to_client";
			else if (
				!["established", "not_established", "stateless", "no_stream", "only_stream", "no_frag", "only_frag"].includes(m)
			) {
				throw new SnortHookException(`unsupported modifier for '${kw.keyword}': '${m}'`);
			}
		}
		return [];
	},
	msg: (kw) => [new IpsKW("protectionName", strip(kw.value, '"'), "")],
	reference: (kw) => {
		if (!Object.hasOwn(REFERENCES, kw.value)) {
			throw new SnortHookException(`Unknown system in Reference of value: ${kw.value}`);
		}
		return [new IpsKW("cveList", `${REFERENCES[kw.value]}${key(kw.modifiers, kw.value)}`, "")];
	},
	gid: none,
	sid: (kw) => [new IpsKW("sid", kw.value, "")],
	rev: (kw) => [new IpsKW("rev", kw.value, "")],
	classtype: (kw) => [
		new IpsKW("severity", key(kw.modifiers, kw.value), ""),
		new IpsKW("tags", title(kw.value.replaceAll("-", " ")).replaceAll(" ", "_"), ""),
	],
	priority: (kw) => [new IpsKW("severity", kw.value, "")],
	metadata: none,
	pkt_data: stickyBuffer,
	http_uri: stickyBuffer,
	http_raw_uri: stickyBuffer,
	http_header: stickyBuffer,
	http_raw_header: stickyBuffer,
	http_method: stickyBuffer,
	http_client_body: stickyBuffer,
	http_cookie: stickyBuffer,
	http_raw_cookie: stickyBuffer,
	http_stat_code: stickyBuffer,
	http_stat_msg: stickyBuffer,
	http_encode: stickyBuffer,
	service: none,
};

// --- Signature/Signatures.py ---
export const convert = (input) => {
	const signatures = [];
	const errors = [];
	const internal = [];
	let lineNumber = 0;
	for (const line of input.split("\n")) {
		lineNumber++;
		if (isInvalidLine(line)) continue;
		const [header, body] = parseSnortRulesLine(line.trim());
		try {
			const rule = new SnortRule(header);
			if (!rule.isHttpRule(body)) continue;
			rule.parseBody(body);
			signatures.push(rule.convert());
		} catch (e) {
			(e instanceof SnortHookException ? errors : internal).push({ Error: e.message, Line: lineNumber });
		}
	}
	return { signatures, errors, internal };
};

if (import.meta.url === `file://${process.argv[1]}`) {
	if (process.argv.length < 5) {
		console.log("Usage: node snort_to_ips_local.mjs <input_file> <output_file> <error_file>");
		process.exit(1);
	}
	const [input, output, errorFile] = process.argv.slice(2);
	const { signatures, errors } = convert(readFileSync(input, "utf8"));
	writeFileSync(output, JSON.stringify({ IPSSnortSigs: { protections: signatures } }, null, 4));
	writeFileSync(errorFile, JSON.stringify({ Errors: errors }, null, 4));
}
