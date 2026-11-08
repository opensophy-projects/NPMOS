#!/usr/bin/env node
// Security report of NginxionS: reads the results of every scanner of the pipeline (.github/workflows/security.yml,
// scripts/scan-images.sh, scripts/test-dast.sh), applies the policy below and writes
//   <out>/security-report.md     the summary (also the summary of the run on GitHub)
//   <out>/security-report.html   the same as a page, with every finding
//   <out>/sbom/<name>.html       each SBOM to read, search and copy; its CycloneDX, SPDX and CSV files next to it
// It exits 1 when the policy fails the run: a blocking finding, or an expected check that left no result (a check
// that did not run is not a pass).
//
//   node scripts/security-report.mjs --in reports --out security-report [--summary "$GITHUB_STEP_SUMMARY"]
//     [--expect source,images,dast]   groups of checks that must have run (default: source)
//     [--scope images,dast]           only these groups (the gate of the images before they are pushed)
//
// Policy (what blocks):
//   SAST (Semgrep, CodeQL)       high and critical in the code of NginxionS (OURS); upstream NPMplus is reported only
//   secrets (Gitleaks)           every finding (examples are allowlisted in .github/security/gitleaks.toml)
//   dependencies (OSV-Scanner)   high and critical with a fixed version
//   images (Trivy)               high and critical with a fixed version; secrets high and critical; Dockle FATAL
//   IaC, workflows               hadolint errors in deploy/; every actionlint error; zizmor high
//   DAST                         ZAP high (confidence medium or more); Nuclei, testssl.sh, gixy high and critical
//   reported only                Grype (second opinion), KICS, Trivy config, Scorecard, licenses, quality metrics
// A finding listed in .github/security/accepted-risks.json does not block until its end date.
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OURS = /^(nginxions\/backend\/nginxions\/|nginxions\/frontend\/src\/nginxions\/|deploy\/|scripts\/|\.github\/)/;
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_RU = { critical: "критическая", high: "высокая", medium: "средняя", low: "низкая", info: "инфо" };
const DETAILS_LIMIT = 60;

// ---------------------------------------------------------------- arguments, files

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
const list = (v, d) => (v ?? d).split(",").filter(Boolean);
const inDir = args.in ?? "reports";
const outDir = args.out;
const expect = new Set(list(args.expect, "source"));
const scope = args.scope ? new Set(list(args.scope)) : null;

const walk = (dir) =>
	existsSync(dir)
		? readdirSync(dir).flatMap((name) => {
				const p = join(dir, name);
				return statSync(p).isDirectory() ? walk(p) : [p];
			})
		: [];
const files = walk(inDir);
const readJson = (file) => {
	const text = readFileSync(file, "utf8").trim();
	return text ? JSON.parse(text) : null;
};
const readJsonLines = (file) =>
	readFileSync(file, "utf8")
		.split("\n")
		.filter((l) => l.trim().startsWith("{"))
		.map((l) => JSON.parse(l));

// a path of a container (/src, /repo, the workspace) back to a path of the repository
const WORKSPACE = process.env.GITHUB_WORKSPACE ? `${process.env.GITHUB_WORKSPACE}/` : "\u0000";
const repoPath = (uri = "") =>
	String(uri)
		.replace(/^file:\/\//, "")
		.replace(WORKSPACE, "")
		.replace(/^\/(src|repo|path|github\/workspace)\//, "")
		.replace(/^\.\//, "");
const at = (path, line) => (path ? `${path}${line ? `:${line}` : ""}` : "");
const firstLine = (s = "") => String(s).split("\n")[0].trim().slice(0, 200);
const fromScore = (n) => (n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : n > 0 ? "low" : "info");
const fromLevel = (l) => ({ error: "high", warning: "medium", note: "low", none: "info" })[l] ?? "medium";
const fromWord = (w = "") => {
	const s = String(w).toLowerCase();
	if (s === "critical" || s === "fatal") return "critical";
	if (s === "high" || s === "error") return "high";
	if (s === "medium" || s === "moderate" || s === "warn" || s === "warning") return "medium";
	if (s === "low" || s === "note") return "low";
	return "info";
};
const severe = (s) => s === "critical" || s === "high";

// ---------------------------------------------------------------- parsers

const sarif = (doc) => {
	const out = [];
	for (const run of doc?.runs ?? []) {
		const rules = new Map();
		for (const r of run.tool?.driver?.rules ?? []) rules.set(r.id, r);
		for (const ext of run.tool?.extensions ?? []) for (const r of ext.rules ?? []) rules.set(r.id, r);
		for (const res of run.results ?? []) {
			if (res.suppressions?.length || res.baselineState === "absent") continue;
			const rule = rules.get(res.ruleId) ?? rules.get(res.rule?.id);
			const score = Number(rule?.properties?.["security-severity"] ?? res.properties?.["security-severity"]);
			const level = res.level ?? rule?.defaultConfiguration?.level ?? "warning";
			const loc = res.locations?.[0]?.physicalLocation;
			const path = repoPath(loc?.artifactLocation?.uri);
			out.push({
				rule: res.ruleId ?? rule?.id ?? "",
				title: firstLine(res.message?.text) || firstLine(rule?.shortDescription?.text) || res.ruleId,
				severity: Number.isFinite(score) && score > 0 ? fromScore(score) : fromLevel(level),
				level,
				path,
				location: at(path, loc?.region?.startLine),
				url: rule?.helpUri ?? "",
			});
		}
	}
	return out;
};

const osv = (doc) => {
	const out = [];
	for (const result of doc?.results ?? []) {
		const lock = repoPath(result.source?.path);
		for (const pkg of result.packages ?? []) {
			const name = `${pkg.package.name}@${pkg.package.version}`;
			for (const group of pkg.groups ?? []) {
				const vulns = (pkg.vulnerabilities ?? []).filter((v) => group.ids.includes(v.id));
				const fixed = [
					...new Set(
						vulns.flatMap((v) =>
							(v.affected ?? [])
								.filter((a) => a.package?.name === pkg.package.name)
								.flatMap((a) => (a.ranges ?? []).flatMap((r) => r.events.map((e) => e.fixed).filter(Boolean))),
						),
					),
				];
				const score = Number.parseFloat(group.max_severity);
				out.push({
					rule: group.ids[0],
					title: `${name}: ${firstLine(vulns[0]?.summary) || group.ids.join(", ")}`,
					severity: Number.isFinite(score) ? fromScore(score) : "medium",
					location: lock,
					path: lock,
					fix: fixed.join(", "),
					url: `https://osv.dev/vulnerability/${group.ids[0]}`,
				});
			}
			for (const lic of pkg.license_violations ?? [])
				out.push({
					tool: "licenses",
					rule: lic,
					title: `${name}: лицензия ${lic} не в списке .github/security/licenses.txt`,
					severity: "low",
					location: lock,
					path: lock,
				});
		}
	}
	return out;
};

const trivy = (doc, { image }) => {
	const out = [];
	for (const result of doc?.Results ?? []) {
		for (const v of result.Vulnerabilities ?? [])
			out.push({
				rule: v.VulnerabilityID,
				title: `${v.PkgName} ${v.InstalledVersion}: ${firstLine(v.Title) || v.VulnerabilityID}`,
				severity: fromWord(v.Severity),
				location: `${image} · ${result.Target}`,
				fix: v.FixedVersion ?? "",
				url: v.PrimaryURL ?? "",
				kind: "vuln",
			});
		for (const s of result.Secrets ?? [])
			out.push({
				rule: s.RuleID,
				title: `секрет в образе: ${s.Title}`,
				severity: fromWord(s.Severity),
				location: at(`${image} · ${result.Target}`, s.StartLine),
				kind: "secret",
			});
		for (const m of result.Misconfigurations ?? [])
			if (m.Status === "FAIL")
				out.push({
					rule: m.ID,
					title: firstLine(m.Title),
					severity: fromWord(m.Severity),
					location: at(repoPath(result.Target), m.CauseMetadata?.StartLine),
					path: repoPath(result.Target),
					url: m.PrimaryURL ?? "",
				});
	}
	return out;
};

const grype = (doc, { image }) =>
	(doc?.matches ?? []).map((m) => ({
		rule: m.vulnerability.id,
		title: `${m.artifact.name} ${m.artifact.version}`,
		severity: fromWord(m.vulnerability.severity),
		location: image,
		fix: (m.vulnerability.fix?.versions ?? []).join(", "),
		url: m.vulnerability.dataSource ?? "",
	}));

const dockle = (doc, { image }) =>
	(doc?.details ?? [])
		.filter((d) => ["FATAL", "WARN", "INFO"].includes(d.level))
		.map((d) => ({
			rule: d.code,
			title: `${d.title}${d.alerts?.length ? `: ${firstLine(d.alerts[0])}` : ""}`,
			severity: { FATAL: "high", WARN: "medium", INFO: "low" }[d.level],
			level: d.level,
			location: image,
			url: `https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#${d.code.toLowerCase()}`,
		}));

const hadolint = (doc) =>
	(doc ?? []).map((h) => ({
		rule: h.code,
		title: firstLine(h.message),
		severity: fromWord(h.level === "style" ? "low" : h.level),
		level: h.level,
		path: repoPath(h.file),
		location: at(repoPath(h.file), h.line),
		url: h.code.startsWith("DL") ? `https://github.com/hadolint/hadolint/wiki/${h.code}` : "",
	}));

const actionlint = (doc) =>
	(doc ?? []).map((a) => ({
		rule: a.kind,
		title: firstLine(a.message),
		severity: "medium",
		path: repoPath(a.filepath),
		location: at(repoPath(a.filepath), a.line),
	}));

const kics = (doc) =>
	(doc?.queries ?? []).flatMap((q) =>
		(q.files ?? []).map((f) => ({
			rule: q.query_id,
			title: q.query_name,
			severity: fromWord(q.severity),
			path: repoPath(f.file_name),
			location: at(repoPath(f.file_name), f.line),
			url: q.query_url ?? "",
		})),
	);

const zap = (doc, { target }) =>
	(doc?.site ?? []).flatMap((site) =>
		(site.alerts ?? [])
			.filter((a) => a.confidence !== "0")
			.map((a) => ({
				rule: `${a.pluginid}`,
				title: `${a.alert ?? a.name} (${a.count ?? a.instances?.length ?? 1})`,
				severity: ["info", "low", "medium", "high"][Number(a.riskcode)] ?? "info",
				confidence: Number(a.confidence),
				location: `${target}: ${a.instances?.[0]?.method ?? ""} ${a.instances?.[0]?.uri ?? site["@name"]}`.trim(),
				url: `https://www.zaproxy.org/docs/alerts/${a.pluginid}/`,
			})),
	);

const nuclei = (lines) =>
	lines.map((n) => ({
		rule: n["template-id"],
		title: n.info?.name ?? n["template-id"],
		severity: fromWord(n.info?.severity),
		location: n["matched-at"] ?? n.host ?? "",
		url: [].concat(n.info?.reference ?? [])[0] ?? "",
	}));

const testssl = (doc, { target }) =>
	(Array.isArray(doc) ? doc : (doc?.scanResult ?? []))
		.filter((t) => ["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(t.severity))
		.map((t) => ({
			rule: t.id,
			title: `${t.id}: ${firstLine(t.finding)}`,
			severity: fromWord(t.severity),
			location: `${target} (${t.ip ?? ""}${t.port ? `:${t.port}` : ""})`,
			url: t.cve ? `https://nvd.nist.gov/vuln/detail/${t.cve.split(" ")[0]}` : "",
		}));

const gixy = (doc) =>
	(doc ?? []).map((g) => ({
		rule: g.plugin,
		title: `${g.summary}${g.reason ? `: ${firstLine(g.reason)}` : ""}`,
		severity: fromWord(g.severity === "UNSPECIFIED" ? "info" : g.severity),
		location: at(g.file, g.line),
		url: g.reference ?? "",
	}));

// ---------------------------------------------------------------- the checks

const IMAGES = ["nginxions", "nginxions-openappsec"];
const imageOf = (file, prefix) => basename(file).replace(prefix, "").replace(/\.json$/, "");

/** id, group, category, tool, what it checks, the files of its results, the parser, the policy of blocking */
const CHECKS = [
	{
		id: "semgrep",
		group: "source",
		category: "SAST",
		tool: "Semgrep",
		what: "уязвимости в коде JS/TS, Dockerfile и workflow (правила сообщества + правила NginxionS)",
		match: /^semgrep\.sarif$/,
		parse: sarif,
		blocks: (f) => f.ours && f.level === "error",
	},
	{
		id: "codeql-js",
		group: "source",
		category: "SAST",
		tool: "CodeQL (JS/TS)",
		what: "пути данных от запроса до опасного вызова (инъекции, SSRF, XSS, обход путей)",
		match: /^codeql-javascript-typescript\.sarif$/,
		parse: sarif,
		blocks: (f) => f.ours && severe(f.severity),
	},
	{
		id: "codeql-actions",
		group: "source",
		category: "SAST",
		tool: "CodeQL (Actions)",
		what: "уязвимости самих workflow GitHub Actions",
		match: /^codeql-actions\.sarif$/,
		parse: sarif,
		blocks: (f) => severe(f.severity),
	},
	{
		id: "gitleaks",
		group: "source",
		category: "Секреты",
		tool: "Gitleaks",
		what: "ключи, пароли и токены в файлах и во всей истории git",
		match: /^gitleaks(-files)?\.sarif$/,
		parse: sarif,
		dedupe: true,
		normalize: (f) => ({ ...f, severity: "high" }),
		blocks: () => true,
	},
	{
		id: "osv",
		group: "source",
		category: "SCA",
		tool: "OSV-Scanner",
		what: "известные уязвимости npm-зависимостей backend и frontend (pnpm-lock.yaml)",
		match: /^osv\.json$/,
		parse: (doc) => osv(doc).filter((f) => f.tool !== "licenses"),
		blocks: (f) => severe(f.severity) && !!f.fix,
	},
	{
		id: "licenses",
		group: "source",
		category: "Лицензии",
		tool: "OSV-Scanner",
		what: "лицензии зависимостей вне списка разрешённых",
		match: /^osv\.json$/,
		parse: (doc) => osv(doc).filter((f) => f.tool === "licenses"),
		blocks: () => false,
	},
	{
		id: "hadolint",
		group: "source",
		category: "IaC",
		tool: "hadolint",
		what: "ошибки и небезопасные приёмы в Dockerfile",
		match: /^hadolint\.json$/,
		parse: hadolint,
		blocks: (f) => f.level === "error" && f.path.startsWith("deploy/"),
	},
	{
		id: "trivy-config",
		group: "source",
		category: "IaC",
		tool: "Trivy config",
		what: "небезопасная конфигурация Dockerfile",
		match: /^trivy-config\.json$/,
		parse: trivy,
		blocks: () => false,
	},
	{
		id: "kics",
		group: "source",
		category: "IaC",
		tool: "KICS",
		what: "небезопасная конфигурация compose, Dockerfile и workflow",
		match: /^results\.json$/,
		parse: kics,
		blocks: () => false,
	},
	{
		id: "actionlint",
		group: "source",
		category: "CI/CD",
		tool: "actionlint",
		what: "ошибки в workflow (синтаксис, выражения, shellcheck шагов)",
		match: /^actionlint\.json$/,
		parse: actionlint,
		blocks: () => true,
	},
	{
		id: "zizmor",
		group: "source",
		category: "CI/CD",
		tool: "zizmor",
		what: "уязвимости workflow: инъекции в ${{ }}, лишние права, кеш, непривязанные actions",
		match: /^zizmor\.sarif$/,
		parse: sarif,
		blocks: (f) => f.level === "error",
	},
	{
		id: "scorecard",
		group: "source",
		category: "Цепочка поставок",
		tool: "OpenSSF Scorecard",
		what: "практики репозитория: защита веток, привязка зависимостей, права токенов",
		match: /^scorecard\.sarif$/,
		parse: sarif,
		optional: true,
		blocks: () => false,
	},
	...IMAGES.flatMap((image) => [
		{
			id: `trivy-${image}`,
			group: "images",
			category: "Образы",
			tool: `Trivy · ${image}`,
			what: `уязвимости пакетов и секреты в слоях образа ${image}`,
			match: new RegExp(`^trivy-${image}\\.json$`),
			parse: (doc) => trivy(doc, { image }),
			dedupe: true,
			blocks: (f) => severe(f.severity) && (f.kind === "secret" || !!f.fix),
		},
		{
			id: `grype-${image}`,
			group: "images",
			category: "Образы",
			tool: `Grype · ${image}`,
			what: `второе мнение по SBOM образа ${image}`,
			match: new RegExp(`^grype-${image}\\.json$`),
			parse: (doc) => grype(doc, { image }),
			dedupe: true,
			blocks: () => false,
		},
		{
			id: `dockle-${image}`,
			group: "images",
			category: "Образы",
			tool: `Dockle · ${image}`,
			what: `CIS Docker Benchmark для образа ${image}`,
			match: new RegExp(`^dockle-${image}\\.json$`),
			parse: (doc) => dockle(doc, { image }),
			blocks: (f) => f.level === "FATAL",
		},
	]),
	{
		id: "published",
		group: "published",
		category: "Опубликованные образы",
		tool: "Trivy · Docker Hub",
		what: "новые CVE в уже выпущенных образах (develop, latest)",
		match: /^trivy-published-.+\.json$/,
		parse: (doc, file) => trivy(doc, { image: imageOf(file, "trivy-published-") }),
		dedupe: true,
		optional: true,
		blocks: (f) => severe(f.severity) && !!f.fix,
	},
	...[
		["zap-api", "интерфейс: API (:81, OpenAPI, с сессией)", "активная атака на API по схеме OpenAPI"],
		["zap-ui", "интерфейс: страницы (:81)", "заголовки, cookies, утечки на страницах интерфейса"],
		["zap-host", "прокси-хост dast.local", "заголовки, cookies, утечки сайта за NginxionS"],
	].map(([name, target, what]) => ({
		id: name,
		group: "dast",
		category: "DAST",
		tool: `OWASP ZAP · ${name.slice(4)}`,
		what,
		match: new RegExp(`^${name}\\.json$`),
		parse: (doc) => zap(doc, { target }),
		blocks: (f) => f.severity === "high" && f.confidence >= 2,
	})),
	{
		id: "nuclei",
		group: "dast",
		category: "DAST",
		tool: "Nuclei",
		what: "известные CVE, открытые панели и файлы, ошибки конфигурации",
		match: /^nuclei\.jsonl$/,
		lines: true,
		parse: nuclei,
		blocks: (f) => severe(f.severity),
	},
	...[
		["testssl-ui", "интерфейс :81"],
		["testssl-host", "dast.local:443"],
	].map(([name, target]) => ({
		id: name,
		group: "dast",
		category: "TLS",
		tool: `testssl.sh · ${target}`,
		what: "протоколы, шифры, HSTS, известные атаки на TLS",
		match: new RegExp(`^${name}\\.json$`),
		parse: (doc) => testssl(doc, { target }),
		blocks: (f) => severe(f.severity),
	})),
	{
		id: "gixy",
		group: "dast",
		category: "Конфигурация nginx",
		tool: "gixy",
		what: "работающая конфигурация nginx (nginx -T): SSRF, инъекции заголовков, обход alias",
		match: /^gixy\.json$/,
		parse: gixy,
		blocks: (f) => severe(f.severity),
	},
];

// ---------------------------------------------------------------- accepted risks

const today = new Date().toISOString().slice(0, 10);
const accepted = (() => {
	const file = join(ROOT, ".github/security/accepted-risks.json");
	return existsSync(file) ? (readJson(file)?.risks ?? []) : [];
})();
const acceptance = (check, f) =>
	accepted.find(
		(r) =>
			(r.tool === check.id || r.tool === "*") &&
			r.id === f.rule &&
			(!r.where || f.location.includes(r.where) || f.title.includes(r.where)),
	);

// ---------------------------------------------------------------- run the checks

const checks = [];
for (const check of CHECKS) {
	if (scope && !scope.has(check.group)) continue;
	const own = files.filter((f) => check.match.test(basename(f)));
	const result = { ...check, files: own, findings: [], error: "" };
	try {
		const seen = new Set();
		for (const file of own) {
			const doc = check.lines ? readJsonLines(file) : readJson(file);
			for (let f of check.parse(doc, file)) {
				if (check.normalize) f = check.normalize(f);
				if (check.dedupe) {
					const key = `${f.rule}\u0000${f.location}\u0000${f.title}`;
					if (seen.has(key)) continue;
					seen.add(key);
				}
				f.ours = OURS.test(f.path ?? "");
				f.blocking = check.blocks(f);
				// non-blocking findings too: the reason shows in the report and they are left out of code scanning
				const risk = acceptance(check, f);
				if (risk) {
					if (risk.until && risk.until < today) f.expired = risk;
					else {
						f.blocking = false;
						f.accepted = risk;
					}
				}
				result.findings.push(f);
			}
		}
	} catch (err) {
		result.error = `не удалось прочитать результат: ${err.message}`;
	}
	result.expected = expect.has(check.group) && !check.optional;
	result.missing = own.length === 0;
	result.findings.sort((a, b) => b.blocking - a.blocking || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
	result.blockingCount = result.findings.filter((f) => f.blocking).length;
	result.status = result.error
		? "error"
		: result.missing
			? result.expected
				? "missing"
				: "skipped"
			: result.blockingCount
				? "fail"
				: result.findings.length
					? "warn"
					: "pass";
	checks.push(result);
}

const blocking = checks.flatMap((c) => c.findings.filter((f) => f.blocking).map((f) => ({ ...f, check: c })));
const broken = checks.filter((c) => c.status === "missing" || c.status === "error");
const acceptedFindings = checks.flatMap((c) => c.findings.filter((f) => f.accepted).map((f) => ({ ...f, check: c })));
const passed = blocking.length === 0 && broken.length === 0;

// ---------------------------------------------------------------- SBOM

const sboms = files
	.filter((f) => /^sbom-.+\.cdx\.json$/.test(basename(f)))
	.map((file) => {
		const name = basename(file).replace(/^sbom-/, "").replace(/\.cdx\.json$/, "");
		const doc = readJson(file) ?? {};
		const components = [];
		const add = (c) => {
			const licenses = (c.licenses ?? [])
				.map((l) => l.license?.id ?? l.license?.name ?? l.expression)
				.filter(Boolean)
				.join(" OR ");
			components.push({
				name: c.group ? `${c.group}/${c.name}` : c.name,
				version: c.version ?? "",
				type: c.type ?? "",
				ecosystem: (c.purl ?? "").match(/^pkg:([^/]+)/)?.[1] ?? "",
				license: licenses,
				purl: c.purl ?? "",
			});
			for (const sub of c.components ?? []) add(sub);
		};
		for (const c of doc.components ?? []) add(c);
		components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
		const count = (key) =>
			Object.entries(
				components.reduce((m, c) => {
					const k = c[key] || "—";
					m[k] = (m[k] ?? 0) + 1;
					return m;
				}, {}),
			).sort((a, b) => b[1] - a[1]);
		return { name, file, components, ecosystems: count("ecosystem"), licenses: count("license") };
	});

// ---------------------------------------------------------------- metrics of quality

const metrics = [];
for (const file of files.filter((f) => basename(f) === "jscpd-report.json")) {
	const total = readJson(file)?.statistics?.total;
	if (total)
		metrics.push(["Дублирование кода (jscpd)", `${total.percentage}% строк, ${total.clones} повторов в ${total.sources} файлах`]);
}
for (const file of files.filter((f) => /^lcov-.+\.info$/.test(basename(f)))) {
	let found = 0;
	let hit = 0;
	for (const line of readFileSync(file, "utf8").split("\n")) {
		if (line.startsWith("LF:")) found += Number(line.slice(3));
		if (line.startsWith("LH:")) hit += Number(line.slice(3));
	}
	const part = basename(file).replace(/^lcov-/, "").replace(/\.info$/, "");
	if (found) metrics.push([`Покрытие тестами: ${part}`, `${((hit / found) * 100).toFixed(1)}% строк (${hit} из ${found})`]);
}
for (const file of files.filter((f) => basename(f) === "coverage-summary.json")) {
	const lines = readJson(file)?.total?.lines;
	if (lines) metrics.push(["Покрытие тестами: frontend", `${lines.pct}% строк (${lines.covered} из ${lines.total})`]);
}

// ---------------------------------------------------------------- output: Markdown

const env = process.env;
const commit = (env.GITHUB_SHA ?? "").slice(0, 9);
const runUrl = env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : "";
const ICON = { pass: "✅", warn: "⚠️", fail: "❌", missing: "❗", error: "❗", skipped: "➖" };
const STATUS_RU = {
	pass: "чисто",
	warn: "есть замечания",
	fail: "блокирует",
	missing: "нет результата",
	error: "ошибка чтения",
	skipped: "не запускался",
};
const md = (s) =>
	String(s ?? "")
		.replace(/\\/g, "\\\\")
		.replace(/\|/g, "\\|")
		.replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;"))
		.replace(/\n/g, " ");
const countBy = (findings) => Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const where = (f) => (f.location ? `\`${md(f.location)}\`` : "");
const link = (f) => (f.url ? `[${md(f.rule)}](${f.url})` : md(f.rule));

const markdown = () => {
	const out = [];
	out.push("# Отчёт безопасности NginxionS", "");
	out.push(
		passed
			? "**Итог: ✅ проверки пройдены** — блокирующих находок нет."
			: `**Итог: ❌ не пройдено** — блокирующих находок: ${blocking.length}${broken.length ? `, проверок без результата: ${broken.length}` : ""}.`,
		"",
	);
	out.push(
		[commit && `коммит \`${commit}\``, env.GITHUB_REF_NAME && `ветка \`${env.GITHUB_REF_NAME}\``, `${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`, runUrl && `[прогон](${runUrl})`]
			.filter(Boolean)
			.join(" · "),
		"",
	);
	out.push("## Сводка", "");
	out.push("| | Категория | Инструмент | Что проверяет | Крит. | Высок. | Сред. | Низк. | Блокирует |");
	out.push("|---|---|---|---|--:|--:|--:|--:|--:|");
	for (const c of checks) {
		const n = countBy(c.findings);
		out.push(
			`| ${ICON[c.status]} | ${c.category} | ${md(c.tool)} | ${md(c.what)}${c.status === "pass" || c.status === "warn" || c.status === "fail" ? "" : ` — *${STATUS_RU[c.status]}*`} | ${n.critical} | ${n.high} | ${n.medium} | ${n.low} | ${c.blockingCount || ""} |`,
		);
	}
	out.push("", "✅ чисто · ⚠️ есть замечания, не блокируют · ❌ блокирует · ❗ проверка не дала результата · ➖ не запускалась в этом прогоне", "");
	if (broken.length) {
		out.push("## Проверки без результата", "");
		for (const c of broken) out.push(`- **${md(c.tool)}**: ${c.error || "файл результата не найден — шаг упал или не запускался"}`);
		out.push("");
	}
	if (blocking.length) {
		out.push("## Блокирующие находки", "");
		out.push("| Серьёзность | Инструмент | Правило | Что | Где | Исправление |", "|---|---|---|---|---|---|");
		for (const f of blocking.slice(0, 200))
			out.push(
				`| ${SEVERITY_RU[f.severity]} | ${md(f.check.tool)} | ${link(f)} | ${md(f.title)}${f.expired ? ` *(срок принятия риска истёк ${f.expired.until})*` : ""} | ${where(f)} | ${md(f.fix ?? "")} |`,
			);
		if (blocking.length > 200) out.push("", `…и ещё ${blocking.length - 200} — в security-report.html.`);
		out.push("");
	}
	if (acceptedFindings.length) {
		out.push("## Принятые риски", "", "| Инструмент | Правило | Где | Причина | До |", "|---|---|---|---|---|");
		for (const f of acceptedFindings)
			out.push(`| ${md(f.check.tool)} | ${link(f)} | ${where(f)} | ${md(f.accepted.reason)} | ${f.accepted.until ?? "—"} |`);
		out.push("");
	}
	if (sboms.length) {
		out.push("## SBOM (состав компонентов)", "");
		out.push("| Состав | Компонентов | Экосистемы | Частые лицензии | Файлы |", "|---|--:|---|---|---|");
		for (const s of sboms)
			out.push(
				`| ${md(s.name)} | ${s.components.length} | ${s.ecosystems.slice(0, 5).map(([k, v]) => `${md(k)} ${v}`).join(", ")} | ${s.licenses.slice(0, 4).map(([k, v]) => `${md(k)} ${v}`).join(", ")} | \`sbom/${md(s.name)}.html\` · \`.cdx.json\` · \`.spdx.json\` · \`.csv\` |`,
			);
		out.push("", "Все файлы — в артефакте **security-report** этого прогона: `sbom/<состав>.html` открывается в браузере (поиск, фильтр, копирование списка).", "");
	}
	if (metrics.length) {
		out.push("## Качество кода", "");
		for (const [k, v] of metrics) out.push(`- **${k}**: ${v}`);
		out.push("");
	}
	const detailed = checks.filter((c) => c.findings.length);
	if (detailed.length) {
		out.push("## Подробности", "");
		for (const c of detailed) {
			out.push(`<details><summary>${ICON[c.status]} ${md(c.tool)} — ${c.findings.length}</summary>`, "");
			out.push("| Серьёзность | Правило | Что | Где | Исправление |", "|---|---|---|---|---|");
			for (const f of c.findings.slice(0, DETAILS_LIMIT))
				out.push(`| ${f.blocking ? "❌ " : ""}${SEVERITY_RU[f.severity]} | ${link(f)} | ${md(f.title)} | ${where(f)} | ${md(f.fix ?? "")} |`);
			if (c.findings.length > DETAILS_LIMIT) out.push("", `…и ещё ${c.findings.length - DETAILS_LIMIT} — в security-report.html.`);
			out.push("", "</details>", "");
		}
	}
	out.push("---", "Политика блокировки — в начале `scripts/security-report.mjs`; принятые риски — `.github/security/accepted-risks.json`; описание — `docs/DEVSECOPS.md`.");
	return out.join("\n");
};

// ---------------------------------------------------------------- output: HTML

const esc = (s) =>
	String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const STYLE = `
:root{--bg:#fff;--fg:#1b1f24;--muted:#59636e;--line:#d1d9e0;--soft:#f6f8fa;--bad:#cf222e;--warn:#9a6700;--ok:#1a7f37;--acc:#0969da}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;--soft:#151b23;--bad:#f85149;--warn:#d29922;--ok:#3fb950;--acc:#4493f8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 8px}h2{font-size:18px;margin:32px 0 12px}
.meta{color:var(--muted)}.verdict{padding:12px 16px;border:1px solid var(--line);border-radius:8px;margin:16px 0;font-weight:600}
.verdict.ok{border-color:var(--ok);color:var(--ok)}.verdict.bad{border-color:var(--bad);color:var(--bad)}
.table{overflow-x:auto;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--soft);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}td.n{text-align:right;font-variant-numeric:tabular-nums}code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.sev{font-weight:600;white-space:nowrap}.critical,.high{color:var(--bad)}.medium{color:var(--warn)}.low,.info{color:var(--muted)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0}summary{cursor:pointer;padding:8px 12px;font-weight:600}details .table{border:0;border-top:1px solid var(--line);border-radius:0}
a{color:var(--acc)}input,select,button{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
button{cursor:pointer;background:var(--soft)}.bar{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.bar input{flex:1;min-width:200px}`;
const page = (title, body, script = "") =>
	`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${STYLE}</style></head><body><main>${body}</main>${script ? `<script>${script}</script>` : ""}</body></html>`;
const findingRows = (findings, withTool) =>
	findings
		.map(
			(f) =>
				`<tr><td class="sev ${f.severity}">${f.blocking ? "❌ " : ""}${SEVERITY_RU[f.severity]}</td>${withTool ? `<td>${esc(f.check.tool)}</td>` : ""}<td>${f.url ? `<a href="${esc(f.url)}">${esc(f.rule)}</a>` : esc(f.rule)}</td><td>${esc(f.title)}${f.accepted ? `<br><small>принято: ${esc(f.accepted.reason)}</small>` : ""}${f.expired ? `<br><small>срок принятия риска истёк ${esc(f.expired.until)}</small>` : ""}</td><td><code>${esc(f.location)}</code></td><td>${esc(f.fix ?? "")}</td></tr>`,
		)
		.join("");

const html = () => {
	const b = [];
	b.push("<h1>Отчёт безопасности NginxionS</h1>");
	b.push(
		`<div class="meta">${[commit && `коммит <code>${esc(commit)}</code>`, env.GITHUB_REF_NAME && `ветка <code>${esc(env.GITHUB_REF_NAME)}</code>`, `${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`, runUrl && `<a href="${esc(runUrl)}">прогон</a>`]
			.filter(Boolean)
			.join(" · ")}</div>`,
	);
	b.push(
		passed
			? `<div class="verdict ok">✅ Проверки пройдены: блокирующих находок нет</div>`
			: `<div class="verdict bad">❌ Не пройдено: блокирующих находок ${blocking.length}${broken.length ? `, проверок без результата ${broken.length}` : ""}</div>`,
	);
	b.push("<h2>Сводка</h2><div class='table'><table><tr><th></th><th>Категория</th><th>Инструмент</th><th>Что проверяет</th><th>Крит.</th><th>Высок.</th><th>Сред.</th><th>Низк.</th><th>Блокирует</th></tr>");
	for (const c of checks) {
		const n = countBy(c.findings);
		b.push(
			`<tr><td title="${STATUS_RU[c.status]}">${ICON[c.status]}</td><td>${esc(c.category)}</td><td>${esc(c.tool)}</td><td>${esc(c.what)}${["missing", "error", "skipped"].includes(c.status) ? ` — <em>${STATUS_RU[c.status]}</em>` : ""}</td><td class="n">${n.critical}</td><td class="n">${n.high}</td><td class="n">${n.medium}</td><td class="n">${n.low}</td><td class="n">${c.blockingCount || ""}</td></tr>`,
		);
	}
	b.push("</table></div>");
	if (blocking.length)
		b.push(
			`<h2>Блокирующие находки</h2><div class="table"><table><tr><th>Серьёзность</th><th>Инструмент</th><th>Правило</th><th>Что</th><th>Где</th><th>Исправление</th></tr>${findingRows(blocking, true)}</table></div>`,
		);
	if (acceptedFindings.length)
		b.push(
			`<h2>Принятые риски</h2><div class="table"><table><tr><th>Серьёзность</th><th>Инструмент</th><th>Правило</th><th>Что</th><th>Где</th><th>Исправление</th></tr>${findingRows(acceptedFindings, true)}</table></div>`,
		);
	if (sboms.length) {
		b.push("<h2>SBOM</h2><div class='table'><table><tr><th>Состав</th><th>Компонентов</th><th>Экосистемы</th><th>Частые лицензии</th><th>Файлы</th></tr>");
		for (const s of sboms)
			b.push(
				`<tr><td><a href="sbom/${esc(s.name)}.html">${esc(s.name)}</a></td><td class="n">${s.components.length}</td><td>${s.ecosystems.slice(0, 6).map(([k, v]) => `${esc(k)} ${v}`).join(", ")}</td><td>${s.licenses.slice(0, 5).map(([k, v]) => `${esc(k)} ${v}`).join(", ")}</td><td><a href="sbom/${esc(s.name)}.cdx.json">CycloneDX</a> · <a href="sbom/${esc(s.name)}.spdx.json">SPDX</a> · <a href="sbom/${esc(s.name)}.csv">CSV</a></td></tr>`,
			);
		b.push("</table></div>");
	}
	if (metrics.length) {
		b.push("<h2>Качество кода</h2><div class='table'><table>");
		for (const [k, v] of metrics) b.push(`<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`);
		b.push("</table></div>");
	}
	const detailed = checks.filter((c) => c.findings.length);
	if (detailed.length) {
		b.push("<h2>Все находки</h2>");
		for (const c of detailed)
			b.push(
				`<details${c.blockingCount ? " open" : ""}><summary>${ICON[c.status]} ${esc(c.tool)} — ${c.findings.length}</summary><div class="table"><table><tr><th>Серьёзность</th><th>Правило</th><th>Что</th><th>Где</th><th>Исправление</th></tr>${findingRows(c.findings, false)}</table></div></details>`,
			);
	}
	return page("Отчёт безопасности NginxionS", b.join(""));
};

const sbomPage = (s) => {
	const data = JSON.stringify(s.components.map((c) => [c.name, c.version, c.ecosystem || c.type, c.license, c.purl])).replace(
		/</g,
		"\\u003c",
	);
	const body = `<h1>SBOM: ${esc(s.name)}</h1><div class="meta">${s.components.length} компонентов${commit ? ` · коммит <code>${esc(commit)}</code>` : ""} · <a href="../security-report.html">к отчёту</a> · <a href="${esc(s.name)}.cdx.json">CycloneDX JSON</a> · <a href="${esc(s.name)}.spdx.json">SPDX JSON</a> · <a href="${esc(s.name)}.csv">CSV</a></div>
<div class="bar"><input id="q" type="search" placeholder="Поиск: имя, версия, лицензия, purl" aria-label="Поиск"><select id="eco" aria-label="Экосистема"><option value="">Все экосистемы</option>${s.ecosystems.map(([k, v]) => `<option value="${esc(k === "—" ? "" : k)}">${esc(k)} (${v})</option>`).join("")}</select><button id="copy" type="button">Скопировать список</button><button id="csv" type="button">Скачать CSV</button></div>
<div class="meta" id="shown"></div><div class="table"><table><thead><tr><th>Компонент</th><th>Версия</th><th>Экосистема</th><th>Лицензия</th><th>purl</th></tr></thead><tbody id="rows"></tbody></table></div>`;
	const script = `const D=${data};const q=document.getElementById("q"),eco=document.getElementById("eco"),rows=document.getElementById("rows"),shown=document.getElementById("shown");
const e=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"})[c]);
let cur=D;function draw(){const t=q.value.trim().toLowerCase(),x=eco.value;cur=D.filter(r=>(!x||r[2]===x)&&(!t||r.join(" ").toLowerCase().includes(t)));
rows.innerHTML=cur.map(r=>"<tr><td>"+e(r[0])+"</td><td><code>"+e(r[1])+"</code></td><td>"+e(r[2])+"</td><td>"+e(r[3])+"</td><td><code>"+e(r[4])+"</code></td></tr>").join("");shown.textContent="Показано: "+cur.length+" из "+D.length;}
q.oninput=draw;eco.onchange=draw;draw();
const csv=()=>["name,version,ecosystem,license,purl"].concat(cur.map(r=>r.map(v=>'"'+String(v).replace(/"/g,'""')+'"').join(","))).join("\\n");
document.getElementById("copy").onclick=async()=>{const text=cur.map(r=>r[0]+"@"+r[1]+(r[3]?"  ("+r[3]+")":"")).join("\\n");try{await navigator.clipboard.writeText(text);}catch{const a=document.createElement("textarea");a.value=text;document.body.append(a);a.select();document.execCommand("copy");a.remove();}document.getElementById("copy").textContent="Скопировано: "+cur.length;};
document.getElementById("csv").onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv()],{type:"text/csv"}));a.download=${JSON.stringify(`sbom-${s.name}.csv`)};a.click();};`;
	return page(`SBOM ${s.name}`, body, script);
};

const csvOf = (s) =>
	["name,version,ecosystem,license,purl"]
		.concat(
			s.components.map((c) =>
				[c.name, c.version, c.ecosystem || c.type, c.license, c.purl].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","),
			),
		)
		.join("\n");

// ---------------------------------------------------------------- write

const report = markdown();
if (outDir) {
	mkdirSync(join(outDir, "sbom"), { recursive: true });
	writeFileSync(join(outDir, "security-report.md"), `${report}\n`);
	writeFileSync(join(outDir, "security-report.html"), html());
	for (const s of sboms) {
		writeFileSync(join(outDir, "sbom", `${s.name}.html`), sbomPage(s));
		writeFileSync(join(outDir, "sbom", `${s.name}.csv`), `${csvOf(s)}\n`);
		copyFileSync(s.file, join(outDir, "sbom", `${s.name}.cdx.json`));
		const spdx = s.file.replace(/\.cdx\.json$/, ".spdx.json");
		if (existsSync(spdx)) copyFileSync(spdx, join(outDir, "sbom", `${s.name}.spdx.json`));
	}
	// the raw results of the scanners, for whoever wants to dig further
	for (const file of files) {
		const dest = join(outDir, "raw", relative(inDir, file));
		mkdirSync(dirname(dest), { recursive: true });
		copyFileSync(file, dest);
	}
}
if (args.summary) writeFileSync(args.summary, `${report.slice(0, 900_000)}\n`, { flag: "a" });

for (const c of checks)
	console.log(`${ICON[c.status]} ${c.tool.padEnd(34)} ${String(c.findings.length).padStart(5)} found, ${c.blockingCount} blocking${c.error ? ` (${c.error})` : ""}`);
for (const c of broken) console.log(`::error title=${c.tool}::${c.error || "no result: the step failed or did not run"}`);
for (const f of blocking.slice(0, 50))
	console.log(`::error title=${f.check.tool}: ${f.rule}::${f.title}${f.location ? ` (${f.location})` : ""}`);
console.log(passed ? "OK: the security policy passed" : `FAIL: ${blocking.length} blocking findings, ${broken.length} checks without result`);
process.exit(passed ? 0 : 1);
