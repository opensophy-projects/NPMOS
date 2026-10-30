// What a backup of NPM / NPMplus / open-appsec-npm contains and where. The archive may start
// anywhere ("./", "data/", "npm/data/", the content of /data, /data and /etc/letsencrypt side by
// side), so places are found by their names, not by fixed paths.
import { readdir, stat } from "node:fs/promises";
import path from "node:path";

/** the parts of a backup that are migrated; everything else (logs, generated configs) is skipped */
const WANTED = [
	// NPMplus runs SQLite in WAL mode: the last changes may still be in database.sqlite-wal
	/(^|\/)database\.sqlite(-wal)?$/,
	/(^|\/)local_policy\.yaml$/,
	// certbot: /etc/letsencrypt of NPM, /data/tls/certbot of NPMplus
	/(^|\/)(live|archive|renewal|accounts)\//,
	/(^|\/)custom_ssl\//,
	/(^|\/)tls\/(custom|mtls)\//,
	/(^|\/)access\//,
	/(^|\/)nginx\/custom\//,
	/(^|\/)custom_nginx\//,
	/(^|\/)nginx\/default_www\//,
	/(^|\/)html\//,
];

/** directories that are never needed (they can be large) */
const SKIPPED = /(^|\/)(logs?|nginx\/(proxy_host|redirection_host|dead_host|stream|temp)|crowdsec|anubis|gravatar)\//;

export const accept = (rel) => !SKIPPED.test(`${rel}/`) && WANTED.some((re) => re.test(rel));

const exists = async (p) => !!(await stat(p).catch(() => null));

const isDir = async (p) => !!(await stat(p).catch(() => null))?.isDirectory();

/** all paths under dir (relative), depth-limited */
const walk = async (dir, depth = 8, rel = "") => {
	if (depth < 0) return [];
	const out = [];
	for (const d of await readdir(path.join(dir, rel), { withFileTypes: true }).catch(() => [])) {
		const r = rel ? `${rel}/${d.name}` : d.name;
		if (d.isDirectory()) {
			out.push(`${r}/`);
			out.push(...(await walk(dir, depth - 1, r)));
		} else if (d.isFile()) {
			out.push(r);
		}
	}
	return out;
};

const depthOf = (rel) => rel.split("/").length;
const shallowest = (list) => list.sort((a, b) => depthOf(a) - depthOf(b) || a.localeCompare(b))[0] ?? null;

/**
 * @param {string} root  the extracted archive
 * @returns {Promise<{database: string|null, dataRoot: string|null, certbot: string|null,
 *   customSsl: string|null, mtls: string|null, access: string|null, customNginx: string|null,
 *   html: string|null, wafPolicy: string|null}>} absolute paths
 */
export const locate = async (root) => {
	const all = await walk(root);
	const abs = (rel) => (rel === null ? null : path.join(root, rel));

	// NPMplus moved the database to /data/npmplus; a copy left at the old place is older
	const databases = all.filter((p) => p.endsWith("database.sqlite"));
	const database =
		shallowest(databases.filter((p) => p.endsWith("npmplus/database.sqlite"))) ?? shallowest(databases);
	let dataRoot = null;
	if (database) {
		dataRoot = path.posix.dirname(database);
		if (dataRoot.endsWith("npmplus")) dataRoot = path.posix.dirname(dataRoot);
		if (dataRoot === ".") dataRoot = "";
	} else {
		// files without a database (the database is read over the network)
		const marker = shallowest(
			all
				.filter((p) => /(^|\/)(custom_ssl|access|tls|custom_nginx|nginx)\/$/.test(p))
				.map((p) => path.posix.dirname(p.slice(0, -1))),
		);
		if (marker !== null) dataRoot = marker === "." ? "" : marker;
	}
	const inData = (rel) => (dataRoot === null ? null : dataRoot ? `${dataRoot}/${rel}` : rel);
	const dirIf = async (rel) => (rel !== null && (await isDir(path.join(root, rel))) ? rel : null);

	// certbot: tls/certbot of NPMplus, else a directory with renewal/ or live/ (/etc/letsencrypt of NPM)
	let certbot = await dirIf(inData("tls/certbot"));
	if (!certbot) {
		certbot = shallowest(
			all
				.filter((p) => /(^|\/)(renewal|live)\/$/.test(p))
				.map((p) => path.posix.dirname(p.slice(0, -1)))
				.filter((p) => !p.includes("/tls/certbot") && !p.startsWith("tls/certbot")),
		);
		if (certbot === ".") certbot = "";
	}

	const wafPolicy = shallowest(all.filter((p) => p.endsWith("local_policy.yaml")));

	return {
		database: abs(database),
		dataRoot: abs(dataRoot),
		certbot: certbot === null ? null : abs(certbot),
		customSsl: abs((await dirIf(inData("tls/custom"))) ?? (await dirIf(inData("custom_ssl")))),
		mtls: abs(await dirIf(inData("tls/mtls"))),
		access: abs(await dirIf(inData("access"))),
		customNginx: abs((await dirIf(inData("custom_nginx"))) ?? (await dirIf(inData("nginx/custom")))),
		html: abs((await dirIf(inData("html"))) ?? (await dirIf(inData("nginx/default_www")))),
		wafPolicy: abs(wafPolicy),
	};
};

/** certificates of certbot in a located tree: names of live/ or renewal/ (npm-<id>) */
export const certbotNames = async (certbot) => {
	if (!certbot) return [];
	const names = new Set();
	for (const sub of ["archive", "renewal"]) {
		for (const d of await readdir(path.join(certbot, sub)).catch(() => [])) {
			const m = /^(npm-\d+)(\.conf)?$/.exec(d);
			if (m) names.add(m[1]);
		}
	}
	return [...names].sort();
};

export { exists };
