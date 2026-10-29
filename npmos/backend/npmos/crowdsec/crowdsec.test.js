import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { Liquid } from "liquidjs";
import YAML from "yaml";
import {
	ConfigError,
	defaults,
	durationMinutes,
	fatalMessages,
	normalize,
	normalizeIpOrCidr,
	renderAcquis,
	renderAllowlist,
	renderBouncer,
	renderConfigLocal,
	renderNginx,
	renderProfiles,
	renderScenario,
	requiredItems,
	unwantedItems,
} from "./config.js";
import * as hub from "./hub.js";
import { machineId, parseMetrics } from "./lapi.js";
import { allowed, exportText, parseList } from "./lists.js";

const TEMPLATES = path.join(import.meta.dirname, "../../templates");

test("settings are checked and normalized", () => {
	const s = normalize(defaults());
	assert.deepEqual(s, defaults());
	assert.equal(durationMinutes("4h"), 240);
	assert.equal(durationMinutes("2d"), 2880);
	assert.throws(() => durationMinutes("4"), ConfigError);
	assert.equal(normalizeIpOrCidr(" 10.0.0.1 "), "10.0.0.1");
	assert.equal(normalizeIpOrCidr("10.0.0.0/08"), "10.0.0.0/8");
	assert.equal(normalizeIpOrCidr("2001:db8::/129"), null);
	assert.equal(normalizeIpOrCidr("example.com"), null);

	const ok = normalize({
		...defaults(),
		allowlist: { ips: ["10.0.0.1", "10.0.0.1", "192.168.0.0/16"], expressions: [] },
	});
	assert.deepEqual(ok.allowlist, { ips: ["10.0.0.1", "192.168.0.0/16"], expressions: [], private: true });
	assert.throws(() => normalize({ ...defaults(), allowlist: { ips: ["nope"], expressions: [] } }), /invalid IP/);
	assert.throws(() => normalize({ ...defaults(), log_level: "trace" }), ConfigError);
	const profile = { ...defaults().profiles[0], filter: "a\nb" };
	assert.throws(() => normalize({ ...defaults(), profiles: [profile] }), /one line/);
	assert.throws(
		() => normalize({ ...defaults(), profiles: [defaults().profiles[0], defaults().profiles[0]] }),
		/unique/,
	);
	assert.throws(
		() => normalize({ ...defaults(), bouncer: { ...defaults().bouncer, exclude_locations: ["/a,/b"] } }),
		/location/,
	);
	assert.throws(
		() => normalize({ ...defaults(), bouncer: { ...defaults().bouncer, captcha: { provider: "turnstile" } } }),
		/site key/,
	);
	// settings of an older NPMOS get the new defaults
	const { private: _p, ...oldAllowlist } = defaults().allowlist;
	assert.equal(normalize({ ...defaults(), allowlist: oldAllowlist }).allowlist.private, true);
});

test("generated files of CrowdSec", () => {
	const s = normalize({
		...defaults(),
		appsec: { enabled: true, failure_action: "deny", configs: ["crowdsecurity/appsec-default"] },
		profiles: [
			{
				...defaults().profiles[0],
				escalate: true,
				scenarios: ["crowdsecurity/http-probing"],
				filter: "Alert.GetValue() != '1.2.3.4'",
			},
			{ ...defaults().profiles[1], enabled: false },
		],
		allowlist: {
			ips: ["10.1.1.1", "10.2.0.0/16"],
			expressions: ["evt.Meta.http_path == '/health'"],
			private: false,
		},
		openappsec_ban: { enabled: true, events: 5, minutes: 10 },
	});

	const acquis = YAML.parseAllDocuments(renderAcquis(s)).map((d) => d.toJS());
	assert.deepEqual(
		acquis.map((a) => a.source),
		["file", "file", "appsec"],
	);
	assert.equal(acquis[0].labels.type, "npmplus");
	assert.equal(acquis[1].labels.type, "openappsec");
	assert.equal(acquis[2].listen_addr, "0.0.0.0:7422");
	assert.equal(
		renderAcquis({ ...s, sources: { nginx: false, openappsec: false }, appsec: { ...s.appsec, enabled: false } }),
		null,
	);

	const profiles = YAML.parseAllDocuments(renderProfiles(s)).map((d) => d.toJS());
	assert.equal(profiles.length, 1);
	assert.equal(profiles[0].name, "npmos_ip");
	assert.equal(
		profiles[0].filters[0],
		'Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() in ["crowdsecurity/http-probing"] && (Alert.GetValue() != \'1.2.3.4\')',
	);
	assert.equal(profiles[0].duration_expr, "Sprintf('%dm', (GetDecisionsCount(Alert.GetValue()) + 1) * 240)");
	assert.equal(profiles[0].on_success, "break");
	// CrowdSec does not start without a profile
	const none = YAML.parseAllDocuments(renderProfiles({ ...s, profiles: [] })).map((d) => d.toJS());
	assert.deepEqual(none[0].filters, ["false"]);

	const allow = YAML.parse(renderAllowlist(s));
	assert.deepEqual(allow.whitelist.ip, ["10.1.1.1"]);
	assert.deepEqual(allow.whitelist.cidr, ["10.2.0.0/16"]);
	assert.equal(renderAllowlist({ ...s, allowlist: { ips: [], expressions: [], private: true } }), null);

	const scenario = YAML.parse(renderScenario(s));
	assert.equal(scenario.type, "leaky");
	assert.equal(scenario.capacity, 4);
	assert.equal(scenario.leakspeed, "120s");
	assert.equal(scenario.labels.remediation, true);
	assert.equal(
		YAML.parse(renderScenario({ ...s, openappsec_ban: { enabled: true, events: 1, minutes: 5 } })).type,
		"trigger",
	);
	assert.equal(renderScenario({ ...s, openappsec_ban: { ...s.openappsec_ban, enabled: false } }), null);

	const local = YAML.parse(renderConfigLocal(s, { registrationToken: "t".repeat(64) }));
	assert.equal(local.api.server.auto_registration.token, "t".repeat(64));
	assert.match(local.cscli.__hub_url_template__, /^http:\/\/npmos:7480\//);

	const conf = renderBouncer(s, { apiKey: "KEY", captchaSecret: "" });
	assert.match(conf, /^ENABLED=false$/m);
	assert.match(conf, /^API_KEY=KEY$/m);
	assert.match(conf, /^APPSEC_URL=http:\/\/crowdsec:7422$/m);
	assert.match(conf, /^APPSEC_FAILURE_ACTION=deny$/m);

	assert.deepEqual(requiredItems(s), [
		["collections", "ZoeyVid/npmplus"],
		["parsers", "openappsec/openappsec-logs"],
		["appsec-configs", "crowdsecurity/appsec-default"],
	]);
	assert.deepEqual(unwantedItems(s), [["parsers", "crowdsecurity/whitelists"]]);
});

test("bouncer of nginx: hosts can be left out", async () => {
	const template = 'access_by_lua_block {\n\tlocal cs = require "crowdsec"\n\t\tcs.Allow(ngx.var.remote_addr)\n}\n';
	const { text, perHost } = renderNginx(template);
	assert.equal(perHost, true);
	assert.match(text, /map \$host \$npmos_crowdsec_off/);
	assert.match(text, /if ngx\.var\.npmos_crowdsec_off ~= "1" then\n\t+cs\.Allow/);
	assert.equal(renderNginx("other code").perHost, false);

	const engine = new Liquid({ root: TEMPLATES, extname: ".conf" });
	const host = { server_names: ["a.test"], env: { DISABLE_HTTP: "true", DISABLE_IPV6: "true" } };
	const off = await engine.renderFile("_common", { ...host, npmos_crowdsec_off: true });
	assert.match(off, /set \$npmos_crowdsec_off 1;/);
	const on = await engine.renderFile("_common", { ...host, npmos_crowdsec_off: false });
	assert.doesNotMatch(on, /set \$npmos_crowdsec_off/);
});

const sha = (t) => createHash("sha256").update(t).digest("hex");

const makeHub = () => {
	const dir = mkdtempSync(path.join(os.tmpdir(), "npmos-hub-"));
	const data = path.join(dir, "data");
	mkdirSync(data);
	const parser = "filter: true\nname: a/p\n";
	const parserOld = "filter: false\nname: a/p\n";
	const scenario =
		"type: trigger\nname: a/s\ndata:\n  - source_url: https://example.invalid/list.txt\n    dest_file: list.txt\n    type: string\n";
	const collection = "parsers:\n  - a/p\nscenarios:\n  - a/s\n";
	const index = {
		collections: {
			"a/c": {
				path: "collections/a/c.yaml",
				version: "0.1",
				versions: { 0.1: { digest: sha(collection) } },
				content: collection,
				parsers: ["a/p"],
				scenarios: ["a/s"],
			},
			"a/d": {
				path: "collections/a/d.yaml",
				version: "0.1",
				versions: { 0.1: { digest: sha("parsers:\n  - a/p\n") } },
				content: "parsers:\n  - a/p\n",
				parsers: ["a/p"],
			},
		},
		parsers: {
			"a/p": {
				path: "parsers/s01-parse/a/p.yaml",
				stage: "s01-parse",
				version: "0.2",
				versions: { 0.1: { digest: sha(parserOld) }, 0.2: { digest: sha(parser) } },
				content: parser,
			},
		},
		scenarios: {
			"a/s": {
				path: "scenarios/a/s.yaml",
				version: "0.1",
				versions: { 0.1: { digest: sha(scenario) } },
				content: scenario,
			},
		},
		postoverflows: {},
		contexts: {},
		"appsec-configs": {},
		"appsec-rules": {},
	};
	mkdirSync(path.join(dir, "hub"));
	writeFileSync(path.join(dir, "hub", ".index.json"), JSON.stringify(index));
	return { dir, data, parserOld };
};

test("hub items are installed and removed like cscli does", async () => {
	const { dir, data, parserOld } = makeHub();
	try {
		await assert.rejects(hub.install("collections", "a/c", { dir, dataDir: data }), /list\.txt/);
		writeFileSync(path.join(data, "list.txt"), "x\n");
		const done = await hub.install("collections", "a/c", { dir, dataDir: data });
		assert.deepEqual(done, ["collections/a/c", "parsers/a/p", "scenarios/a/s"]);
		const link = path.join(dir, "parsers", "s01-parse", "p.yaml");
		assert.ok(lstatSync(link).isSymbolicLink());
		assert.equal(readlinkSync(link), path.join(dir, "hub", "parsers/s01-parse/a/p.yaml"));
		assert.deepEqual(await hub.install("collections", "a/c", { dir, dataDir: data }), []);

		let items = await hub.list({ installed: true }, dir);
		assert.deepEqual(
			items.map((i) => [i.name, i.status, i.needed_by]),
			[
				["a/c", "up-to-date", []],
				["a/p", "up-to-date", ["a/c"]],
				["a/s", "up-to-date", ["a/c"]],
			],
		);

		// an older version on disk
		writeFileSync(path.join(dir, "hub", "parsers/s01-parse/a/p.yaml"), parserOld);
		assert.equal((await hub.list({ type: "parsers" }, dir))[0].status, "outdated");
		assert.deepEqual(await hub.upgradeAll({ dir }), ["parsers/a/p"]);

		// a collection keeps what another installed collection needs
		await hub.install("collections", "a/d", { dir, dataDir: data });
		assert.deepEqual(await hub.remove("collections", "a/c", { dir }), ["collections/a/c", "scenarios/a/s"]);
		items = await hub.list({ installed: true }, dir);
		assert.deepEqual(
			items.map((i) => i.name),
			["a/d", "a/p"],
		);

		// local files are never touched
		writeFileSync(path.join(dir, "scenarios", "s.yaml"), "local\n");
		assert.equal((await hub.list({ type: "scenarios" }, dir))[0].installed, "local");
		await assert.rejects(hub.remove("scenarios", "a/s", { dir }), /local file/);

		assert.throws(() => hub.parseIndex("{}"), /Not a CrowdSec hub index/);
		assert.throws(() => hub.linkPath("parsers", { path: "../../etc/x.yaml" }, dir), /Unsafe/);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("blocklists, exports, metrics and logs", () => {
	const { entries, invalid } = parseList(
		"# list\n1.2.3.4\n1.2.3.4\n5.6.7.0/24 ; comment\n10.0.0.5,office\nfoo\n2001:db8::1 x\n",
		["10.0.0.0/8"],
	);
	assert.deepEqual(entries, ["1.2.3.4", "5.6.7.0/24", "2001:db8::1"]);
	assert.equal(invalid, 1);
	assert.equal(allowed("2001:db8::5", ["2001:db8::/32"]), true);
	assert.equal(allowed("2001:db9::5", ["2001:db8::/32"]), false);
	assert.equal(allowed("192.168.1.1", ["2001:db8::/32"]), false);

	const text = exportText([
		{ origin: "crowdsec", scenario: "x", type: "ban", scope: "Ip", value: "1.1.1.1" },
		{ origin: "lists", scenario: "npmos/blocklist/1", type: "ban", scope: "Ip", value: "2.2.2.2" },
		{ origin: "cscli", scenario: "npmos/manual", type: "captcha", scope: "Ip", value: "3.3.3.3" },
		{ origin: "cscli", scenario: "npmos/manual", type: "ban", scope: "Range", value: "4.4.0.0/16" },
	]);
	assert.deepEqual(text.split("\n").slice(1, -1), ["1.1.1.1", "4.4.0.0/16"]);

	const metrics = parseMetrics(
		'# HELP x\ncs_info{version="v1.8.1"} 1\ncs_filesource_hits_total{source="/var/log/a.log",type="file"} 12\n',
	);
	assert.deepEqual(metrics[1], {
		name: "cs_filesource_hits_total",
		labels: { source: "/var/log/a.log", type: "file" },
		value: 12,
	});

	assert.deepEqual(
		fatalMessages([
			{ line: 'time="t" level=info msg="starting"' },
			{ line: 'time="t" level=fatal msg="failed to compile profiles: bad \\"x\\""' },
		]),
		['failed to compile profiles: bad "x"'],
	);
	assert.match(machineId("secret"), /^npmos-[0-9a-f]{12}$/);
});
