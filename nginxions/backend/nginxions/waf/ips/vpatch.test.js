import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { bounded, conditionWays, escapeData, ruleToProtections, Unsupported } from "./vpatch.js";

const FILE = new URL("../../../../../openappsec/agent/nginxions/ips-protections.json", import.meta.url);

/** a pcre keyword of the agent as a RegExp of JavaScript (PCRE (?i:...) is (?:...) with the flag i here: broader) */
const toRegExp = (keyword) => {
	const m = /^pcre: "\/(.*)\/([a-z]*)", part [A-Z_]+$/s.exec(keyword.trim());
	assert.ok(m, `not a pcre keyword: ${keyword}`);
	let pattern = m[1].replaceAll('\\"', '"');
	let flags = m[2];
	if (pattern.includes("(?i:") || pattern.includes("(?i)")) {
		pattern = pattern.replaceAll("(?i:", "(?:").replaceAll("(?i)", "");
		if (!flags.includes("i")) flags += "i";
	}
	return new RegExp(pattern, flags);
};
const keywordsOf = (protection) =>
	protection.detectionRules.keywords
		.split(/; (?=pcre:|data:)|;$/)
		.map((k) => k.trim())
		.filter(Boolean);
const way = (cond) => conditionWays(cond).map(([k]) => k);

test("a path ends with: a pattern on the decoded path, in any case with lowercase", () => {
	const [k] = way({
		zones: ["URI"],
		transform: ["lowercase"],
		match: { type: "endsWith", value: "/util/php/eval-stdin.php" },
	});
	assert.equal(k.context, "HTTP_PATH_DECODED");
	const re = toRegExp(k.keyword);
	assert.ok(re.test("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"));
	assert.ok(!re.test("/util/php/eval-stdin.php.bak"));
});

test("contains on a whole buffer is a data keyword", () => {
	const [k] = way({ zones: ["URI"], transform: ["lowercase"], match: { type: "contains", value: '/a"b|c' } });
	assert.equal(k.keyword, 'data: "/a\\"b\\|c", nocase, part HTTP_PATH_DECODED');
	assert.equal(escapeData("é"), "|c3a9|");
});

test("an argument by name: the query and the body (form, JSON, multipart)", () => {
	const ways = way({ zones: ["ARGS"], variables: ["cmd"], match: { type: "equals", value: "id" } });
	assert.deepEqual(
		ways.map((w) => w.context),
		["HTTP_QUERY_DECODED", "HTTP_REQUEST_BODY"],
	);
	const [query, body] = ways.map((w) => toRegExp(w.keyword));
	assert.ok(query.test("a=1&cmd=id"));
	assert.ok(query.test("cmd=id&b=2"));
	assert.ok(!query.test("cmd=idx"));
	assert.ok(!query.test("xcmd=id"));
	assert.ok(body.test("cmd=id"));
	assert.ok(body.test('{"cmd": "id"}'));
	assert.ok(body.test('--b\r\nContent-Disposition: form-data; name="cmd"\r\n\r\nid\r\n--b--'));
	assert.ok(!body.test('{"cmd": "idx"}'));
});

test("a regular expression of a value stays in the value", () => {
	const ways = way({
		zones: ["BODY_ARGS"],
		variables: ["dest_host"],
		match: { type: "regex", value: "[^0-9a-zA-Z-.]+" },
	});
	const re = toRegExp(ways[0].keyword);
	assert.ok(re.test("dest_host=a;id&x=1"));
	assert.ok(!re.test("dest_host=example.com&x=1"));
	assert.equal(bounded("a.[^0-9]x[abc]", "&"), "a[^&][^&0-9]x[abc]");
	assert.equal(bounded("[^a-z_.-]", "&"), "[^&a-z_.-]");
	assert.equal(bounded("\\.[^\\]]", '"'), '\\.[^"\\]]');
});

test("a header by name, in any case of the name", () => {
	const [k] = way({
		zones: ["HEADERS"],
		variables: ["accept"],
		transform: ["lowercase"],
		match: { type: "contains", value: "../" },
	});
	assert.equal(k.context, "HTTP_REQUEST_HEADER");
	const re = toRegExp(k.keyword);
	assert.ok(re.test("Host: a\r\nAccept: ../../etc/passwd{{\r\n"));
	assert.ok(!re.test("Accept: text/html\r\nX-Path: ../\r\n"));
});

test("a cookie by name", () => {
	const [k] = way({ zones: ["COOKIES"], variables: ["session"], match: { type: "equals", value: "x" } });
	const re = toRegExp(k.keyword);
	assert.ok(re.test("Cookie: a=1; session=x\r\n"));
	assert.ok(!re.test("Cookie: session=xy\r\n"));
});

test("and of conditions with several zones: one protection per way", () => {
	const protections = ruleToProtections(
		{
			name: "crowdsecurity/vpatch-CVE-2099-12345",
			description: "Test (CVE-2099-12345)",
			rules: [
				{
					and: [
						{ zones: ["URI"], match: { type: "equals", value: "/x" } },
						{ zones: ["ARGS"], variables: ["a"], match: { type: "contains", value: "y" } },
					],
				},
			],
			labels: { confidence: 3, classification: ["cve.CVE-2099-12345", "cwe.CWE-78"] },
		},
		{ lastUpdate: "20990101" },
	);
	assert.equal(protections.length, 2);
	const meta = protections[0].protectionMetadata;
	assert.equal(meta.severity, "Critical");
	assert.equal(meta.confidenceLevel, "High");
	assert.deepEqual(meta.cveList, ["CVE-2099-12345"]);
	assert.ok(meta.tags.includes("Threat_Year_2099"));
	assert.equal(meta.maintrainId, "crowdsecurity/vpatch-CVE-2099-12345#1");
	assert.deepEqual(protections[1].detectionRules.context, ["HTTP_PATH_DECODED", "HTTP_REQUEST_BODY"]);
});

test("what the IPS cannot do is left out", () => {
	assert.throws(() => way({ zones: ["ARGS"], match: { type: "libinjectionSQL" } }), Unsupported);
	assert.throws(
		() => way({ zones: ["ARGS"], transform: ["b64decode"], match: { type: "contains", value: "x" } }),
		Unsupported,
	);
	assert.throws(() => way({ zones: ["UNKNOWN"], match: { type: "contains", value: "x" } }), Unsupported);
});

test("the signatures of the image: every pattern is a regular expression, the metadata complete", () => {
	const file = JSON.parse(readFileSync(FILE, "utf8"));
	assert.match(file.source.ref, /^[0-9a-f]{40}$/);
	assert.ok(file.protections.length > 100);
	const ids = new Set();
	for (const p of file.protections) {
		const meta = p.protectionMetadata;
		assert.ok(["Critical", "High", "Medium", "Low"].includes(meta.severity));
		assert.ok(["High", "Medium", "Low"].includes(meta.confidenceLevel));
		assert.ok(["High", "Medium", "Low"].includes(meta.performanceImpact));
		assert.ok(!ids.has(meta.maintrainId), `twice: ${meta.maintrainId}`);
		ids.add(meta.maintrainId);
		for (const k of keywordsOf(p)) if (k.startsWith("pcre")) assert.doesNotThrow(() => toRegExp(k), k);
	}
});
