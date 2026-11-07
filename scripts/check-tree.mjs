#!/usr/bin/env node
// CI: every file of the code of NPMOS is named in the file tree of CODE_OF_CONDUCT.md (section 4), so that the tree
// says what each file is for and does not fall behind. Tests, styles of a component, index.tsx of a page (named by its
// folder), migrations and patches are named by their folder only.
// Usage: node scripts/check-tree.mjs   (from the root of the repository)
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const ROOTS = ["npmos/backend/npmos", "npmos/frontend/src/npmos", "deploy", "scripts"];
const SKIP_DIRS = new Set(["node_modules", "migrations", "patches", "examples"]);
const skipFile = (name) =>
	name.includes(".test.") || name.endsWith(".module.css") || name === "index.tsx" || name.endsWith(".patch");

const tree = readFileSync("CODE_OF_CONDUCT.md", "utf8");
const missing = [];
const walk = (dir) => {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) walk(full);
		} else if (!skipFile(entry.name) && !tree.includes(entry.name)) {
			missing.push(full);
		}
	}
};
for (const root of ROOTS) walk(root);

if (missing.length) {
	for (const file of missing) console.log(`::error file=${file}::not in the file tree of CODE_OF_CONDUCT.md (section 4)`);
	console.log(`${missing.length} file(s): add each with a line on what it is for`);
	process.exit(1);
}
console.log("file tree of CODE_OF_CONDUCT.md: every file named");
