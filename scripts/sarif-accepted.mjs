#!/usr/bin/env node
// Leaves out of a SARIF file, before it is uploaded to code scanning, the results that need no work:
//   - the ones the tool itself reports as suppressed in the source (// nosemgrep: <rule> -- why);
//   - the accepted risks of .github/security/accepted-risks.json for this tool (the same match as
//     scripts/security-report.mjs: the tool, the rule and, if given, a part of the location or of the message).
// Code scanning does not read suppressions of other tools than CodeQL, so without this every accepted finding would
// stay an open alert; a result left out is closed by code scanning at the next analysis. The reason stays in
// accepted-risks.json and in the security report (its table of accepted risks), which reads the whole SARIF.
// An accepted risk whose date is over is not left out.
//
//   node scripts/sarif-accepted.mjs <tool id of the report> <in.sarif> [out.sarif]   (out: in place)
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [tool, input, output = input] = process.argv.slice(2);
if (!tool || !input) {
	console.error("usage: sarif-accepted.mjs <tool> <in.sarif> [out.sarif]");
	process.exit(2);
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const today = new Date().toISOString().slice(0, 10);
const risks = (JSON.parse(readFileSync(join(ROOT, ".github/security/accepted-risks.json"), "utf8")).risks ?? []).filter(
	(r) => (r.tool === tool || r.tool === "*") && !(r.until && r.until < today),
);

const repoPath = (uri = "") =>
	String(uri)
		.replace(/^file:\/\//, "")
		.replace(/^(\.\.\/)+src\//, "")
		.replace(/^\/(src|repo|path|github\/workspace)\//, "")
		.replace(/^\.\//, "");

export const accepted = (result) => {
	const id = result.ruleId ?? result.rule?.id ?? "";
	const loc = result.locations?.[0]?.physicalLocation;
	const path = repoPath(loc?.artifactLocation?.uri);
	const location = path ? `${path}${loc?.region?.startLine ? `:${loc.region.startLine}` : ""}` : "";
	const message = String(result.message?.text ?? "");
	return risks.find((r) => r.id === id && (!r.where || location.includes(r.where) || message.includes(r.where)));
};

const doc = JSON.parse(readFileSync(input, "utf8"));
let kept = 0;
let suppressed = 0;
let acceptedCount = 0;
for (const run of doc.runs ?? []) {
	run.results = (run.results ?? []).filter((result) => {
		if (result.suppressions?.length) {
			suppressed++;
			return false;
		}
		if (accepted(result)) {
			acceptedCount++;
			return false;
		}
		kept++;
		return true;
	});
}
writeFileSync(output, JSON.stringify(doc));
console.log(`${input}: ${kept} kept, ${suppressed} suppressed in the source, ${acceptedCount} accepted risks left out`);
