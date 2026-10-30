// The database of the old installation is brought to the schema of NPMOS (the upstream NPMplus
// migrations; NPM's are the same files) in a SQLite copy, never in place: an uploaded
// database.sqlite is copied, a MySQL/MariaDB/Postgres database is read into a new SQLite file.
import { readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import knex from "knex";

const MIGRATIONS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../migrations");
const TABLE = "migrations";

/** the migrations of NPM (github.com/NginxProxyManager/nginx-proxy-manager); NPMplus has them all */
export const NPM_MIGRATIONS = [
	"20180618015850_initial.js",
	"20180929054513_websockets.js",
	"20181019052346_forward_host.js",
	"20181113041458_http2_support.js",
	"20181213013211_forward_scheme.js",
	"20190104035154_disabled.js",
	"20190215115310_customlocations.js",
	"20190218060101_hsts.js",
	"20190227065017_settings.js",
	"20200410143839_access_list_client.js",
	"20200410143840_access_list_client_fix.js",
	"20201014143841_pass_auth.js",
	"20210210154702_redirection_scheme.js",
	"20210210154703_redirection_status_code.js",
	"20210423103500_stream_domain.js",
	"20211108145214_regenerate_default_host.js",
	"20240427161436_stream_ssl.js",
	"20251111090000_redirect_auto_scheme.js",
	"20260131163528_trust_forwarded_proto.js",
];

/** the tables of upstream, in an order that keeps references valid */
export const TABLES = [
	"user",
	"auth",
	"user_permission",
	"certificate",
	"access_list",
	"access_list_auth",
	"access_list_client",
	"proxy_host",
	"redirection_host",
	"dead_host",
	"stream",
	"npmplus_proxy_host_access_list",
	"setting",
	"audit_log",
];

export const available = async () => (await readdir(MIGRATIONS)).filter((f) => f.endsWith(".js")).sort();

/**
 * Upstream migrations as a knex migration source. The ones that regenerate the default host
 * write nginx files of the running NPMOS: here they do nothing.
 */
class Source {
	constructor(names) {
		this.names = names;
	}
	getMigrations() {
		return Promise.resolve(this.names);
	}
	getMigrationName(name) {
		return name;
	}
	async getMigration(name) {
		if (name.includes("regenerate_default_host")) return { up: async () => {}, down: async () => {} };
		return import(pathToFileURL(path.join(MIGRATIONS, name)).href);
	}
}

export const openSqlite = (file) =>
	knex({ client: "better-sqlite3", connection: { filename: file }, useNullAsDefault: true });

/** names of the migrations a database has run (table "migrations", like upstream) */
export const appliedMigrations = async (db) => {
	if (!(await db.schema.hasTable(TABLE))) return [];
	return (await db(TABLE).select("name")).map((r) => r.name);
};

/**
 * Runs the upstream migrations the database has not run yet.
 * @returns {Promise<string[]>} names of the migrations that ran
 */
export const upgrade = async (db, names = null) => {
	const list = names ?? (await available());
	const [, ran] = await db.migrate.latest({
		tableName: TABLE,
		migrationSource: new Source(list),
		// a newer NPM/NPMplus may have run migrations NPMOS does not know: they are reported, not fatal
		disableMigrationsListValidation: true,
	});
	return ran;
};

const portable = (value) => {
	if (value instanceof Date)
		return value
			.toISOString()
			.replace("T", " ")
			.replace(/\.\d+Z$/, "");
	if (Buffer.isBuffer(value)) return value.toString("utf8");
	if (value !== null && typeof value === "object") return JSON.stringify(value);
	if (typeof value === "boolean") return value ? 1 : 0;
	return value;
};

/**
 * Copies a MySQL/MariaDB/Postgres database of NPM into a new SQLite file: the schema is made by
 * the same migrations the source has run, then the rows are copied (the columns both have).
 * @param {object} connection  knex config of the source
 * @param {string} file        the SQLite file to create
 */
export const cloneRemote = async (connection, file) => {
	const source = knex({ ...connection, pool: { min: 0, max: 1 }, acquireConnectionTimeout: 10000 });
	const target = openSqlite(file);
	try {
		const applied = await appliedMigrations(source);
		if (!applied.length) throw new Error("No NPM tables in this database (no migrations table)");
		const known = await available();
		await upgrade(
			target,
			known.filter((n) => applied.includes(n)),
		);
		for (const table of TABLES) {
			if (!(await source.schema.hasTable(table)) || !(await target.schema.hasTable(table))) continue;
			const columns = Object.keys(await target(table).columnInfo());
			const sourceColumns = Object.keys(await source(table).columnInfo());
			const shared = columns.filter((c) => sourceColumns.includes(c));
			const rows = await source(table).select(shared);
			for (let i = 0; i < rows.length; i += 100) {
				const batch = rows
					.slice(i, i + 100)
					.map((row) => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, portable(v)])));
				await target(table).insert(batch);
			}
		}
		return { applied, unknown: applied.filter((n) => !known.includes(n)) };
	} finally {
		await source.destroy();
		await target.destroy();
	}
};
