import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { classify, parseChunk } from "./normalize.js";
import { eventAggregates, trafficAggregates } from "./store.js";
import { scan } from "./tail.js";

const attack = (time, extra = {}) => ({
	eventTime: time,
	eventName: "Web Request",
	eventSeverity: "Critical",
	eventPriority: "High",
	eventSource: { serviceName: "HTTP Transaction Handler", assetName: "test.local" },
	eventData: {
		securityAction: "Prevent",
		waapIncidentType: "SQL Injection",
		sourceIP: "203.0.113.7",
		httpHostName: "Test.Local",
		httpMethod: "GET",
		httpUriPath: "/",
		httpUriQuery: "id=1' OR '1'='1",
		matchedLocation: "url",
		matchedParameter: "id",
		matchedSample: "1' OR '1'='1\u0000",
		waapFoundIndicators: ["sqli_tautology", "quote"],
		waapFinalScore: 9.2,
		httpResponseCode: "403",
		ruleName: "npm-managed-specific-rule-proxyhost-1",
		...extra,
	},
});

test("an attack becomes a security event", () => {
	const { type, row } = classify(attack("2026-10-28T03:38:24.217"));
	assert.equal(type, "event");
	assert.equal(row.kind, "security");
	assert.equal(row.time.toISOString(), "2026-10-28T03:38:24.217Z");
	assert.equal(row.host, "test.local");
	assert.equal(row.source_ip, "203.0.113.7");
	assert.equal(row.indicators, "sqli_tautology, quote");
	assert.equal(row.score, 9.2);
	assert.equal(row.response_code, 403);
	assert.equal(row.asset, "test.local");
	assert.equal(row.sample.includes("\u0000"), false);
	assert.equal(JSON.parse(row.raw).eventData.matchedSample, "1' OR '1'='1");
});

test("notices, telemetry and noise", () => {
	const notice = classify({ eventTime: "2026-10-28T03:38:23.773", eventName: "Check Point Nano-service started" });
	assert.equal(notice.row.kind, "system");
	assert.equal(classify({ eventTime: "x", eventName: "y" }), null);
	assert.equal(
		classify({ eventTime: "2026-10-28T03:00:00", eventName: "z", eventSource: { source: "fog_communication" } }),
		null,
	);
	const telemetry = classify({
		eventTime: "2026-10-28T03:12:00.000",
		eventName: "WAAP telemetry",
		eventSource: { assetName: "test.local" },
		eventData: { reservedNgenA: 10, reservedNgenB: 3, reservedNgenD: 4, reservedNgenE: 1, reservedNgenJ: 2 },
	});
	assert.equal(telemetry.type, "telemetry");
	assert.deepEqual(
		{ ...telemetry.row, hour: telemetry.row.hour.toISOString() },
		{
			node_id: "local",
			hour: "2026-10-28T03:00:00.000Z",
			asset: "test.local",
			requests: 10,
			sources: 3,
			blocked: 5,
			threat_low: 0,
			threat_medium: 0,
			threat_high: 2,
		},
	);
	assert.equal(classify({ eventTime: "2026-10-28T03:12:00", eventName: "WAAP attack type telemetry" }), null);
	const huge = classify(attack("2026-10-28T03:38:24", { httpRequestBody: "x".repeat(200000) }));
	assert.equal(JSON.parse(huge.row.raw).eventData.npmosTruncated, true);
});

test("only complete lines are parsed", () => {
	const text = Buffer.from('{"a":1}\nnot json\n{"b":"ü"}\n{"c":');
	const { lines, consumed } = parseChunk(text);
	assert.deepEqual(lines, [{ a: 1 }, { b: "ü" }]);
	assert.equal(text.subarray(consumed).toString(), '{"c":');
	assert.deepEqual(parseChunk(Buffer.from('{"c":')), { lines: [], consumed: 0 });
});

test("aggregates", () => {
	const rows = [
		classify(attack("2026-10-28T03:10:00")).row,
		classify(attack("2026-10-28T03:50:00")).row,
		classify(attack("2026-10-28T04:01:00", { securityAction: "Detect" })).row,
	];
	const hourly = eventAggregates(rows).map((r) => [r.hour.toISOString(), r.action, r.events]);
	assert.deepEqual(hourly, [
		["2026-10-28T03:00:00.000Z", "Prevent", 2],
		["2026-10-28T04:00:00.000Z", "Detect", 1],
	]);
	const hour = new Date("2026-10-28T03:00:00Z");
	const t = (requests) => ({
		node_id: "local",
		hour,
		asset: "a",
		requests,
		sources: 1,
		blocked: 0,
		threat_low: 0,
		threat_medium: 0,
		threat_high: 0,
	});
	assert.equal(trafficAggregates([t(5), t(7)])[0].requests, 12);
});

test("log files: positions, growth, truncation, rename", async () => {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "npmos-tail-"));
	const file = path.join(dir, "cp-nano-http-transaction-handler.log1");
	const cursors = new Map();
	const read = async () => {
		const { chunks } = await scan(dir, cursors, 1024 * 1024);
		const lines = [];
		for (const c of chunks) {
			const { lines: l, consumed } = parseChunk(c.buffer);
			lines.push(...l);
			if (c.rotated) continue;
			cursors.set(c.key, {
				key: c.key,
				file: c.file,
				offset: c.start + consumed,
				head: c.head,
				headLength: c.headLength,
			});
		}
		return lines.map((l) => l.n);
	};
	await fs.writeFile(file, '{"n":1}\n{"n":2}\n{"n":');
	await fs.writeFile(path.join(dir, "cp-nano-orchestration.dbg"), '{"n":99}\n');
	assert.deepEqual(await read(), [1, 2]);
	assert.deepEqual(await read(), []);
	await fs.appendFile(file, '3}\n{"n":4}\n');
	assert.deepEqual(await read(), [3, 4]);
	// renamed by a rotation: same inode, read on where it was
	await fs.rename(file, `${file}.1`);
	await fs.appendFile(`${file}.1`, '{"n":5}\n');
	await fs.writeFile(file, '{"n":6}\n');
	assert.deepEqual((await read()).sort(), [5, 6]);
	// truncated and written again (copytruncate)
	await fs.writeFile(`${file}.1`, '{"n":7}\n');
	assert.deepEqual(await read(), [7]);
	// rotation of the agent: copied to "<name>.0.gz", then truncated; the unread rest is in the archive
	await fs.appendFile(`${file}.1`, '{"n":8}\n{"n":9}\n');
	const archived = await fs.readFile(`${file}.1`);
	await fs.writeFile(`${file}.1.0.gz`, gzipSync(archived));
	await fs.truncate(`${file}.1`, 0);
	assert.deepEqual(await read(), [8, 9]);
	assert.deepEqual(await read(), []);
	await fs.appendFile(`${file}.1`, '{"n":10}\n');
	assert.deepEqual(await read(), [10]);
	await fs.rm(dir, { recursive: true });
	assert.equal((await scan(dir, cursors, 1024)).available, false);
});

test("analytics timeline: aligned buckets, actions split", async () => {
	const { emptyTimeline, fillTimeline } = await import("./analytics.js");
	const hour = 3600 * 1000;
	const from = new Date("2026-10-28T00:00:00Z");
	const buckets = emptyTimeline(from, new Date("2026-10-28T05:30:00Z"), hour);
	assert.equal(buckets.length, 6);
	fillTimeline(
		buckets,
		[
			{ time: "2026-10-28T00:00:00Z", action: "Prevent", events: "3" },
			{ time: "2026-10-28T02:59:59Z", action: "Detect", events: 2 },
			{ time: "2026-10-28T05:10:00Z", action: "Accept", events: 1 },
			{ time: "2026-10-27T23:00:00Z", action: "Prevent", events: 9 },
		],
		hour,
	);
	assert.deepEqual(
		buckets.map((b) => [b.prevent, b.detect, b.other]),
		[
			[3, 0, 0],
			[0, 0, 0],
			[0, 2, 0],
			[0, 0, 0],
			[0, 0, 0],
			[0, 0, 1],
		],
	);
});

test("requests: proxy hosts that open the interface of NPMOS", async () => {
	const { isInterfaceHost } = await import("./requests.js");
	assert.equal(isInterfaceHost({ forward_host: "127.0.0.1", forward_port: 81 }), true);
	assert.equal(isInterfaceHost({ forward_host: "localhost", forward_port: "81" }), true);
	assert.equal(isInterfaceHost({ forward_host: "127.0.0.1", forward_port: 8081 }), false);
	assert.equal(isInterfaceHost({ forward_host: "app", forward_port: 81 }), false);
});

test("requests: a line of the JSON log of nginx, admin and health checks left out", async () => {
	const { parseLine, requestAggregates, countryAggregates } = await import("./requests.js");
	const line = (host, status, extra = {}) =>
		JSON.stringify({
			t: 1793338590.123,
			h: host,
			port: "443",
			ip: "203.0.113.7",
			m: "GET",
			u: "/index.html",
			s: status,
			b: 1224,
			rl: 310,
			rt: 0.004,
			ut: "0.001, 0.003",
			uct: "0.000",
			us: "502, 200",
			ua_addr: "10.0.0.2:80, 10.0.0.3:80",
			cache: "",
			proto: "HTTP/2.0",
			tls: "TLSv1.3",
			ct: "text/html; charset=utf-8",
			ref: "https://www.example.org/x",
			ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
			...extra,
		});
	const a = parseLine(line("App.example.com", 200));
	assert.equal(a.host, "app.example.com");
	assert.equal(a.time.toISOString(), "2026-10-30T05:36:30.123Z");
	assert.equal(a.bytes, 1224);
	assert.equal(a.duration_ms, 4);
	assert.equal(a.upstream_ms, 3);
	assert.equal(a.upstream_status, 200);
	assert.equal(a.upstream_addr, "10.0.0.3:80");
	assert.equal(a.content_type, "text/html");
	assert.equal(a.referer_host, "www.example.org");
	assert.deepEqual([a.browser, a.os, a.device], ["Chrome", "Windows", "desktop"]);
	assert.equal(a.pageview, true);
	assert.equal(a.visit, true);
	assert.equal(a.mitigated, false);
	assert.equal(parseLine(line("app.example.com", 200, { ref: "https://app.example.com/" })).visit, false);
	assert.equal(parseLine(line("app.example.com", 200, { ct: "application/json" })).pageview, false);
	assert.equal(parseLine(line("127.0.0.1", 200, { port: "81" })), null);
	assert.equal(parseLine(line("app.example.com", 200, { ua: "NPMplus/healthcheck" })), null);
	assert.equal(parseLine("garbage"), null);
	assert.equal(parseLine("{broken"), null);
	const blocked = parseLine(line("app.example.com", 403, { ut: "-", us: "-", ua_addr: "-" }));
	assert.equal(blocked.mitigated, true);
	assert.equal(blocked.upstream_ms, null);
	assert.equal(blocked.upstream_status, null);
	const rows = requestAggregates([a, blocked, parseLine(line("app.example.com", 502))]);
	assert.equal(rows.length, 1);
	assert.deepEqual(
		{
			requests: rows[0].requests,
			s2xx: rows[0].s2xx,
			s4xx: rows[0].s4xx,
			s5xx: rows[0].s5xx,
			blocked: rows[0].blocked,
		},
		{ requests: 3, s2xx: 1, s4xx: 1, s5xx: 1, blocked: 1 },
	);
	assert.equal(rows[0].hour.toISOString(), "2026-10-30T05:00:00.000Z");
	a.country = "DE";
	blocked.country = "DE";
	const countries = countryAggregates([a, blocked]);
	assert.deepEqual(
		countries.map((r) => [r.country, r.requests, r.mitigated, r.bytes]),
		[["DE", 2, 1, 2448]],
	);
});

test("requests: browsers, systems and devices of user agents", async () => {
	const { parseUserAgent } = await import("./useragent.js");
	const iphone =
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
	assert.deepEqual(parseUserAgent(iphone), { browser: "Safari", os: "iOS", device: "mobile" });
	assert.deepEqual(parseUserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"), {
		browser: "Firefox",
		os: "Linux",
		device: "desktop",
	});
	assert.equal(parseUserAgent("Mozilla/5.0 (compatible; Googlebot/2.1)").device, "bot");
	assert.equal(parseUserAgent("curl/8.5.0").browser, "Bot");
	assert.equal(
		parseUserAgent("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0").browser,
		"Edge",
	);
	assert.equal(
		parseUserAgent("Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 Chrome/130.0").device,
		"tablet",
	);
	assert.deepEqual(parseUserAgent(""), { browser: "", os: "", device: "other" });
});
