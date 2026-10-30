// Files of the old installation → /data of NPMOS, in the layout of NPMplus (what start.sh of
// NPMplus does for NPM: /etc/letsencrypt → /data/tls/certbot, custom_ssl → tls/custom,
// nginx/custom → custom_nginx). Nginx configs and htpasswd files are not copied: NPMOS generates them.
import { cp, lstat, mkdir, readdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import path from "node:path";

const DATA = process.env.NPMOS_MIGRATION_DATA || "/data";
const LIVE_FILES = ["cert", "chain", "fullchain", "privkey"];

const isDir = async (p) => !!(await stat(p).catch(() => null))?.isDirectory();

/** copies regular files and directories only (no links) */
const copyTree = async (from, to) => {
	await cp(from, to, {
		recursive: true,
		force: true,
		filter: async (src) => {
			const st = await lstat(src).catch(() => null);
			return !!st && (st.isDirectory() || st.isFile());
		},
	});
};

/** a renewal config of certbot with the paths of NPMplus */
export const rewriteRenewal = (text) =>
	text
		.replaceAll("/etc/letsencrypt", "/data/tls/certbot")
		.replaceAll("/data/tls/certbot/credentials", "/tmp/certbot-credentials")
		.replaceAll("/data/letsencrypt-acme-challenge", "/data/tls/certbot/acme-challenge");

/** the newest archive/<name>/<file>N.pem */
const newest = (files, base) =>
	files
		.map((f) => ({ f, m: new RegExp(`^${base}(\\d+)\\.pem$`).exec(f) }))
		.filter((x) => x.m)
		.sort((a, b) => Number(b.m[1]) - Number(a.m[1]))[0]?.f ?? null;

/**
 * Certbot: accounts, archive, renewal of the certificates `ids`; live/ is made again as links to
 * the newest files of archive/ (like start.sh of NPMplus).
 * @returns {Promise<number>} certificates copied
 */
export const copyCertbot = async (from, ids, data = DATA) => {
	const to = path.join(data, "tls/certbot");
	if (await isDir(path.join(from, "accounts")))
		await copyTree(path.join(from, "accounts"), path.join(to, "accounts"));
	let copied = 0;
	for (const id of ids) {
		const name = `npm-${id}`;
		const archive = path.join(from, "archive", name);
		if (!(await isDir(archive))) continue;
		await rm(path.join(to, "archive", name), { recursive: true, force: true });
		await copyTree(archive, path.join(to, "archive", name));
		const renewal = path.join(from, "renewal", `${name}.conf`);
		const conf = await readFile(renewal, "utf8").catch(() => null);
		if (conf !== null) {
			await mkdir(path.join(to, "renewal"), { recursive: true });
			await writeFile(path.join(to, "renewal", `${name}.conf`), rewriteRenewal(conf));
		}
		const files = await readdir(path.join(to, "archive", name));
		const live = path.join(to, "live", name);
		await rm(live, { recursive: true, force: true });
		await mkdir(live, { recursive: true });
		for (const base of LIVE_FILES) {
			const file = newest(files, base);
			if (file) await symlink(`../../archive/${name}/${file}`, path.join(live, `${base}.pem`));
		}
		copied += 1;
	}
	return copied;
};

/** files of custom certificates (npm-<id>) the database does not hold */
export const copyCustomCerts = async (from, ids, data = DATA) => {
	let copied = 0;
	for (const id of ids) {
		const dir = path.join(from, `npm-${id}`);
		if (!(await isDir(dir))) continue;
		await copyTree(dir, path.join(data, "tls/custom", `npm-${id}`));
		copied += 1;
	}
	return copied;
};

/**
 * Custom nginx snippets (http.conf, server_proxy.conf, ...). The current files are kept in
 * `backup`, to be put back when nginx does not accept the imported ones.
 * @returns {Promise<string[]>} names of the copied files
 */
export const copyCustomNginx = async (from, backup, data = DATA) => {
	const to = path.join(data, "custom_nginx");
	await rm(backup, { recursive: true, force: true });
	if (await isDir(to)) await copyTree(to, backup);
	const names = [];
	for (const d of await readdir(from, { withFileTypes: true })) {
		if (!d.isFile() || !d.name.endsWith(".conf")) continue;
		const content = await readFile(path.join(from, d.name));
		if (!content.length) continue;
		await mkdir(to, { recursive: true });
		await writeFile(path.join(to, d.name), content);
		names.push(d.name);
	}
	return names;
};

export const restoreCustomNginx = async (backup, data = DATA) => {
	if (!(await isDir(backup))) return;
	const to = path.join(data, "custom_nginx");
	await rm(to, { recursive: true, force: true });
	await copyTree(backup, to);
};

/** the default page (setting "default-site" = html) */
export const copyHtml = async (from, data = DATA) => {
	const files = await readdir(from).catch(() => []);
	if (!files.length) return 0;
	await copyTree(from, path.join(data, "html"));
	return files.length;
};
