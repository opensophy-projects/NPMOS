#!/usr/bin/env node
// The IPS signatures of the agent of NginxionS from the virtual patching rules of the CrowdSec hub (docs/WAF-POLICY.md,
// "IPS"; converter: nginxions/backend/nginxions/waf/ips/vpatch.js, it needs the packages of the backend):
//
//   git clone https://github.com/crowdsecurity/hub /tmp/hub && git -C /tmp/hub checkout <commit>
//   node scripts/update-ips-signatures.mjs /tmp/hub
//
// Writes openappsec/agent/nginxions/ips-protections.json (one protection a line, to read the changes) and prints the
// rules left out. Write the commit of the hub to CROWDSEC_HUB_REF in deploy/openappsec/sources.env.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "../nginxions/backend/node_modules/yaml/dist/index.js";
import { convertRules } from "../nginxions/backend/nginxions/waf/ips/vpatch.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const hub = process.argv[2];
if (!hub) {
	console.error("usage: node scripts/update-ips-signatures.mjs <checkout of github.com/crowdsecurity/hub>");
	process.exit(2);
}
const COLLECTIONS = ["crowdsecurity/appsec-virtual-patching", "crowdsecurity/appsec-generic-rules"];
// not protections: the settings of the rules, a test rule, an experimental one
const LEFT_OUT = new Set([
	"crowdsecurity/base-config",
	"crowdsecurity/appsec-generic-test",
	"crowdsecurity/experimental-no-user-agent",
]);

const git = (...args) => execFileSync("git", ["-C", hub, ...args], { encoding: "utf8" }).trim();
const ref = git("rev-parse", "HEAD");
const date = git("show", "-s", "--format=%cs", "HEAD");

const names = new Set();
for (const c of COLLECTIONS) {
	const [author, name] = c.split("/");
	const doc = parse(readFileSync(path.join(hub, "collections", author, `${name}.yaml`), "utf8"));
	for (const r of doc["appsec-rules"] ?? []) if (!LEFT_OUT.has(r)) names.add(r);
}
const rules = [...names].sort().map((name) => {
	const [author, rule] = name.split("/");
	return { name, text: readFileSync(path.join(hub, "appsec-rules", author, `${rule}.yaml`), "utf8") };
});
const { protections, skipped } = convertRules(rules, { lastUpdate: date.replaceAll("-", "") });

const head = {
	name: "NginxionS IPS",
	modificationTime: date,
	source: { hub: "https://github.com/crowdsecurity/hub", ref, license: "MIT", rules: rules.length, skipped },
};
const json = JSON.stringify(head);
const text = `${json.slice(0, -1)},"protections":[\n${protections.map((p) => JSON.stringify(p)).join(",\n")}\n]}\n`;
writeFileSync(path.join(root, "openappsec/agent/nginxions/ips-protections.json"), text);
console.log(`${rules.length} rules of the hub ${ref} (${date}): ${protections.length} protections`);
for (const s of skipped) console.log(`  left out ${s.name}: ${s.reason}`);
