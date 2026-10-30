// System → Migration: moves an installation of NPM, NPMplus or open-appsec-npm into NPMOS.
// 1. the source: an archive of its /data (and /etc/letsencrypt of NPM), a database.sqlite, or its
//    MySQL/MariaDB/Postgres database over the network (plus an archive for the files);
// 2. its database is upgraded in a SQLite copy (schema.js) and analyzed: what comes over, what
//    stops it; 3. the import (copy.js, files.js), then nginx configs and the WAF policy are generated.
// Work files: /data/npmos/migration, removed by "discard".
import { createWriteStream } from "node:fs";
import { copyFile, mkdir, open, readdir, readFile, rm, stat } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import db from "../../db.js";
import internalAccessList from "../../internal/access-list.js";
import internalAuditLog from "../../internal/audit-log.js";
import internalCertificate from "../../internal/certificate.js";
import internalNginx from "../../internal/nginx.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import { regenerateAllHosts } from "../../setup.js";
import { importLegacy, regenerateNow } from "../waf/policy.js";
import { analyze, importInto } from "./copy.js";
import { copyCertbot, copyCustomCerts, copyCustomNginx, copyHtml, restoreCustomNginx } from "./files.js";
import { appliedMigrations, available, cloneRemote, NPM_MIGRATIONS, openSqlite, upgrade } from "./schema.js";
import { accept, locate } from "./source.js";
import { extract, sniff, TarError } from "./tar.js";

const WORK = process.env.NPMOS_MIGRATION_DIR || "/data/npmos/migration";
const UPLOAD = path.join(WORK, "upload");
const SOURCE = path.join(WORK, "source");
const DATABASE = path.join(WORK, "database.sqlite");
const NGINX_BACKUP = path.join(WORK, "custom_nginx.before");
export const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024;
const MAX_ENTRIES = 200000;
const ENGINES = { mysql: "mysql2", mariadb: "mysql2", postgres: "pg" };

/** idle → ready (analysis) → importing → done | failed */
const state = { stage: "idle", origin: null, analysis: null, result: null, error: null, busy: false };

const view = () => ({
	stage: state.stage,
	origin: state.origin && { ...state.origin, migrations: undefined },
	analysis: state.analysis,
	result: state.result,
	error: state.error,
});

const guard = async (access) => {
	// users and roles are imported: only who manages users, roles and settings
	await access.can("settings:manage");
	await access.can("users:manage");
	await access.can("roles:manage");
};

const exclusive = async (fn) => {
	if (state.busy || state.stage === "importing")
		throw new errs.ValidationError("A migration step is already running");
	state.busy = true;
	try {
		return await fn();
	} finally {
		state.busy = false;
	}
};

const isFile = async (p) => !!(await stat(p).catch(() => null))?.isFile();

/** NPM, NPMplus; open-appsec-npm is NPM with WAF rules in local_policy.yaml */
const kindOf = (applied, wafRules) => {
	const npmplus = applied.some((n) => !NPM_MIGRATIONS.includes(n));
	if (npmplus) return "npmplus";
	return wafRules ? "open-appsec-npm" : "npm";
};

const countWafRules = (text) => (text.match(/name:\s*npm-managed-specific-rule-proxyhost-\d+/g) || []).length;

/** upgrades the SQLite copy and analyzes it (+ the files of the archive) */
const prepare = async ({ applied, unknown }) => {
	const places = await locate(SOURCE).catch(() => ({}));
	const src = openSqlite(DATABASE);
	try {
		const ran = await upgrade(src);
		const report = await analyze(src, db());
		const wafText = places.wafPolicy ? await readFile(places.wafPolicy, "utf8").catch(() => "") : "";
		const wafRules = countWafRules(wafText);
		const warnings = [];
		const missing = [];
		for (const cert of report.certificates) {
			if (cert.provider !== "letsencrypt") continue;
			const has = places.certbot && (await isFile(path.join(places.certbot, "renewal", `npm-${cert.id}.conf`)));
			cert.files = !!has;
			if (!has) missing.push(cert.id);
		}
		if (missing.length) warnings.push({ code: "certbot_missing", ids: missing });
		if (unknown.length) warnings.push({ code: "newer_source", names: unknown });
		if (report.plainPasswords) warnings.push({ code: "plain_passwords", count: report.plainPasswords });
		const customNginx = [];
		for (const n of places.customNginx ? await readdir(places.customNginx) : []) {
			const st = await stat(path.join(places.customNginx, n)).catch(() => null);
			if (st?.isFile() && st.size && n.endsWith(".conf")) customNginx.push(n);
		}
		state.analysis = {
			kind: kindOf(applied, wafRules),
			schema: { applied: applied.length, last: applied.at(-1) ?? null, upgraded: ran.length, unknown },
			...report,
			files: {
				certbot: !!places.certbot,
				custom_certs: !!places.customSsl,
				custom_nginx: customNginx,
				html: !!places.html,
				waf_rules: wafRules,
			},
			warnings,
		};
		state.stage = "ready";
		state.error = null;
		state.result = null;
	} finally {
		await src.destroy();
	}
};

const reset = async () => {
	await rm(WORK, { recursive: true, force: true });
	Object.assign(state, { stage: "idle", origin: null, analysis: null, result: null, error: null });
};

const failPrepare = async (err) => {
	await rm(DATABASE, { force: true });
	await rm(`${DATABASE}-wal`, { force: true });
	state.stage = "idle";
	state.analysis = null;
	if (err instanceof TarError) throw new errs.ValidationError(err.message);
	if (err instanceof errs.ValidationError) throw err;
	throw new errs.ValidationError(`The source could not be read: ${err.message}`);
};

const runImport = async (access, { history, customNginx }) => {
	const src = openSqlite(DATABASE);
	const places = await locate(SOURCE).catch(() => ({}));
	const result = { warnings: [] };
	try {
		const report = await importInto(src, db(), { history });
		Object.assign(result, report);
		// the rows are in NPMOS from here on: a later failure does not undo them
		result.committed = true;

		const certs = await db()("certificate").where("is_deleted", 0).select("id", "provider", "meta");
		const letsencrypt = certs.filter((c) => c.provider === "letsencrypt").map((c) => c.id);
		const custom = certs.filter((c) => c.provider !== "letsencrypt");
		result.certbot = places.certbot ? await copyCertbot(places.certbot, letsencrypt) : 0;
		result.custom_certs = places.customSsl
			? await copyCustomCerts(
					places.customSsl,
					custom.map((c) => c.id),
				)
			: 0;
		// the database holds the custom certificates and keys: written like NPMplus does
		for (const cert of custom) {
			const meta = typeof cert.meta === "string" ? JSON.parse(cert.meta) : cert.meta || {};
			if (!meta.certificate) continue;
			try {
				await internalCertificate.writeCustomCert({ ...cert, meta });
			} catch (err) {
				result.warnings.push({ code: "custom_cert", id: cert.id, message: err.message });
			}
		}
		result.dns_certificates = certs.filter((c) => {
			const meta = typeof c.meta === "string" ? JSON.parse(c.meta) : c.meta || {};
			return c.provider === "letsencrypt" && meta.dns_challenge;
		}).length;
		// htpasswd files of the access lists (passwords are hashes now)
		for (const list of await db()("access_list").where("is_deleted", 0).select("id", "name")) {
			const items = await db()("access_list_auth")
				.where("access_list_id", list.id)
				.select("username", "password");
			await internalAccessList.build({ ...list, items });
		}
		result.html = places.html ? await copyHtml(places.html) : 0;
		result.custom_nginx =
			customNginx && places.customNginx ? await copyCustomNginx(places.customNginx, NGINX_BACKUP) : [];

		if (places.wafPolicy) {
			result.waf_rules = await importLegacy(await readFile(places.wafPolicy, "utf8"));
		}

		// nginx: the default site and every host; snippets nginx refuses are taken back
		const generate = async () => {
			const site = await db()("setting").where("id", "default-site").first();
			if (site) await internalNginx.generateConfig("default", site);
			await regenerateAllHosts(true);
			await internalNginx.test();
		};
		try {
			await generate();
		} catch (err) {
			if (!result.custom_nginx.length) throw err;
			result.warnings.push({ code: "custom_nginx_refused", names: result.custom_nginx, message: err.message });
			await restoreCustomNginx(NGINX_BACKUP);
			result.custom_nginx = [];
			await generate();
		}
		const offline = [];
		for (const table of ["proxy_host", "redirection_host", "dead_host", "stream"]) {
			for (const row of await db()(table).where({ is_deleted: 0, enabled: 1 }).select("id", "meta")) {
				const meta = typeof row.meta === "string" ? JSON.parse(row.meta) : row.meta || {};
				if (meta.nginx_online === false) offline.push({ table, id: row.id, error: meta.nginx_err ?? "" });
			}
		}
		if (offline.length) result.warnings.push({ code: "hosts_offline", hosts: offline });
		await regenerateNow({ force: true }).catch((err) => {
			result.warnings.push({ code: "waf_policy", message: err.message });
		});

		await internalAuditLog.add(access, {
			action: "imported",
			object_type: "setting",
			meta: {
				name: "migration",
				kind: state.analysis?.kind,
				hosts: report.rows,
				users: report.users.added.length,
			},
		});
		state.result = result;
		state.stage = "done";
		logger.info(`NPMOS migration: imported from ${state.analysis?.kind}`);
	} catch (err) {
		logger.error(`NPMOS migration failed: ${err.message}`);
		state.error = err.message;
		state.result = result;
		state.stage = "failed";
	} finally {
		await src.destroy();
		await rm(UPLOAD, { force: true });
	}
};

const internalMigration = {
	status: async (access) => {
		await guard(access);
		return view();
	},

	/**
	 * An archive (.tar, .tar.gz) or a database.sqlite, streamed to disk.
	 * @param {import("express").Request} req
	 */
	upload: async (access, req) =>
		exclusive(async () => {
			await guard(access);
			if (state.stage === "done") throw new errs.ValidationError("Discard the finished migration first");
			const remote = state.origin?.type === "database" && (await isFile(DATABASE));
			await rm(SOURCE, { recursive: true, force: true });
			await rm(UPLOAD, { force: true });
			await mkdir(SOURCE, { recursive: true, mode: 0o700 });
			let size = 0;
			const out = createWriteStream(UPLOAD, { mode: 0o600 });
			req.on("data", (chunk) => {
				size += chunk.length;
				if (size > MAX_UPLOAD_BYTES) req.destroy(new Error("The file is larger than 2 GB"));
			});
			try {
				await pipeline(req, out);
			} catch (err) {
				await rm(UPLOAD, { force: true });
				throw new errs.ValidationError(err.message);
			}
			const head = Buffer.alloc(512);
			const handle = await open(UPLOAD, "r");
			await handle.read(head, 0, 512, 0);
			await handle.close();
			const type = sniff(head);
			try {
				if (type === "sqlite") {
					await copyFile(UPLOAD, path.join(SOURCE, "database.sqlite"));
				} else if (type === "gzip" || type === "tar") {
					await extract(UPLOAD, SOURCE, {
						gzip: type === "gzip",
						accept,
						maxBytes: MAX_EXTRACTED_BYTES,
						maxEntries: MAX_ENTRIES,
					});
				} else {
					throw new errs.ValidationError("Expected a .tar.gz / .tar archive or a database.sqlite file");
				}
				await rm(UPLOAD, { force: true });
				const places = await locate(SOURCE);
				if (places.database) {
					await rm(`${DATABASE}-wal`, { force: true });
					await copyFile(places.database, DATABASE);
					if (await isFile(`${places.database}-wal`))
						await copyFile(`${places.database}-wal`, `${DATABASE}-wal`);
					const src = openSqlite(DATABASE);
					let applied;
					try {
						applied = await appliedMigrations(src);
					} finally {
						await src.destroy();
					}
					if (!applied.length)
						throw new errs.ValidationError("database.sqlite is not a database of NPM or NPMplus");
					const known = await available();
					state.origin = { type: "archive", size };
					await prepare({ applied, unknown: applied.filter((n) => !known.includes(n)) });
				} else if (remote) {
					// files for a database read over the network
					state.origin = { ...state.origin, files: true };
					await prepare(state.origin.migrations);
				} else {
					throw new errs.ValidationError(
						"No database.sqlite in the archive (or connect to the database first)",
					);
				}
				return view();
			} catch (err) {
				await rm(UPLOAD, { force: true });
				return failPrepare(err);
			}
		}),

	/**
	 * The MySQL/MariaDB/Postgres database of NPM, read once into a SQLite copy.
	 * @param {{engine: string, host: string, port?: number, user: string, password?: string, database: string}} data
	 */
	connect: async (access, data) =>
		exclusive(async () => {
			await guard(access);
			if (state.stage === "done") throw new errs.ValidationError("Discard the finished migration first");
			const client = ENGINES[data.engine];
			if (!client) throw new errs.ValidationError("Unknown database engine");
			await mkdir(WORK, { recursive: true, mode: 0o700 });
			await rm(DATABASE, { force: true });
			try {
				const migrations = await cloneRemote(
					{
						client,
						connection: {
							host: data.host,
							port: data.port || (client === "pg" ? 5432 : 3306),
							user: data.user,
							password: data.password ?? "",
							database: data.database,
							...(client === "mysql2" ? { connectTimeout: 10000 } : { connectionTimeoutMillis: 10000 }),
						},
					},
					DATABASE,
				);
				state.origin = {
					type: "database",
					engine: data.engine,
					host: data.host,
					database: data.database,
					files: !!(await locate(SOURCE).catch(() => ({}))).dataRoot,
					migrations,
				};
				await prepare(migrations);
				return view();
			} catch (err) {
				return failPrepare(err);
			}
		}),

	/**
	 * Starts the import; the page follows it through status().
	 * @param {{history?: boolean, custom_nginx?: boolean}} options
	 */
	apply: async (access, options = {}) =>
		exclusive(async () => {
			await guard(access);
			if (state.stage !== "ready") throw new errs.ValidationError("Nothing to import: upload the source first");
			if (state.analysis?.blocking?.length) {
				throw new errs.ValidationError("NPMOS already has hosts, certificates or access lists");
			}
			state.stage = "importing";
			state.error = null;
			runImport(access, { history: options.history !== false, customNginx: options.custom_nginx !== false });
			return view();
		}),

	discard: async (access) =>
		exclusive(async () => {
			await guard(access);
			await reset();
			return view();
		}),
};

export default internalMigration;
