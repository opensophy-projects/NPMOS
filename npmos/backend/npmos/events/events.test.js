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
