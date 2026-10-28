#!/usr/bin/env node
// Base languages of NPMOS are English and Russian: every key of en.json must be in ru.json, and
// the interface must not contain hardcoded English text (JSX text, placeholder/title/aria-label).
// Other languages are left to the community and are not checked here.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../npmos/frontend/src/", import.meta.url).pathname;
const en = JSON.parse(readFileSync(join(root, "locale/src/en.json"), "utf8"));
const ru = JSON.parse(readFileSync(join(root, "locale/src/ru.json"), "utf8"));
const errors = [];

for (const key of Object.keys(en)) {
	if (!(key in ru)) errors.push(`ru.json: no translation for "${key}" (${en[key].defaultMessage})`);
}

// text that is not words for people: protocols, header values, product names, file names
const allowed = /^(npmos|X-Frame-Options|local_policy\.yaml|Ctrl K|https?:\/\/|example\.com)$/;
const patterns = [
	// >Some text< between tags
	/(?<!=)>\s*([A-Za-z][A-Za-z'’ ,.!?…-]*[a-z][A-Za-z'’ ,.!?…-]*)\s*</g,
	// placeholder="Text", title="Text", aria-label="Text"
	/\b(?:placeholder|title|aria-label|alt)="([A-Za-z][^"]*[a-z][^"]*)"/g,
	// || "Text" fallbacks
	/\|\|\s*"([A-Z][a-z]+ [^"]+)"/g,
];
// upstream header, menu and footer: replaced by the NPMOS shell (src/npmos/ui), not rendered
const skip = /^components\/(SiteHeader|SiteMenu|SiteFooter|ThemeSwitcher)\.tsx$/;
const walk = (dir) =>
	readdirSync(dir).flatMap((name) => {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) return name === "locale" ? [] : walk(path);
		return path.endsWith(".tsx") ? [path] : [];
	});
for (const file of walk(root)) {
	if (skip.test(file.slice(root.length))) continue;
	const source = readFileSync(file, "utf8");
	for (const pattern of patterns) {
		for (const match of source.matchAll(pattern)) {
			const text = match[1].trim();
			if (allowed.test(text) || /^\w+:\/\/$/.test(text)) continue;
			// <option> values of technical selects (http, authelia, none…) stay as is
			const before = source.slice(Math.max(0, match.index - 80), match.index);
			if (/<option[^>]*$/.test(before)) continue;
			const line = source.slice(0, match.index).split("\n").length;
			errors.push(`${file.slice(root.length)}:${line}: hardcoded text "${text}", use a locale key`);
		}
	}
}

if (errors.length) {
	console.error(errors.join("\n"));
	console.error(`\n${errors.length} i18n problem(s): add the strings to en.json and ru.json`);
	process.exit(1);
}
console.log("i18n check passed: en and ru complete, no hardcoded text");
