// Rows of the upgraded source database (SQLite, schema of NPMOS) → the database of NPMOS.
// Hosts, certificates and access lists keep their ids: files on disk (certbot npm-<id>, access
// lists, WAF rules of open-appsec-npm) are named after them, so NPMOS must not have any yet.
// Users are matched by email: an existing user stays as it is, the others are added with their
// password hashes, 2FA and permissions (as roles, like the RBAC migration).
import bcrypt from "bcryptjs";
import { fromProjection } from "../rbac/model.js";
import { TABLES } from "./schema.js";

/** tables whose ids are kept: NPMOS must have no rows in them */
export const KEEP_IDS = [
	"certificate",
	"access_list",
	"access_list_auth",
	"access_list_client",
	"proxy_host",
	"redirection_host",
	"dead_host",
	"stream",
];

const OWNED = ["certificate", "access_list", "proxy_host", "redirection_host", "dead_host", "stream"];
const HOSTS = ["proxy_host", "redirection_host", "dead_host", "stream"];
const SKIP_SETTINGS = ["oidc-config"];

const parse = (v, fallback) => {
	if (v === null || v === undefined || v === "") return fallback;
	if (typeof v !== "string") return v;
	try {
		return JSON.parse(v);
	} catch {
		return fallback;
	}
};

/** NPM keeps access list passwords in plain text, NPMplus as a hash (written to htpasswd as is) */
const HASHED = /^(\$(2[abxy]?|apr1|1|5|6)\$|\{SHA\})/;
export const hashAccessPassword = (password) =>
	!password || HASHED.test(password) ? password : bcrypt.hashSync(password, 6);

const count = async (db, table) =>
	(await db.schema.hasTable(table)) ? Number((await db(table).count("* as n").first()).n) : 0;

/** a value of the source for a column of the target (Postgres types) */
const convert = (value, column, info) => {
	const type = info?.type ?? "";
	if (type === "json" || type === "jsonb") {
		const fallback = column === "domain_names" || column === "roles" ? [] : info.nullable ? null : {};
		const v = parse(value, fallback);
		return v === null ? null : JSON.stringify(v);
	}
	if (type.startsWith("timestamp") || type === "date") {
		if (value === null || value === undefined || value === "") return info.nullable ? null : new Date(0);
		if (typeof value === "number") return new Date(value);
		// SQLite: "YYYY-MM-DD HH:MM:SS" in UTC
		return /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?$/.test(value) ? `${value}Z` : value;
	}
	if (type === "boolean") return value === null ? null : !!Number(value);
	return value;
};

/**
 * What would be imported, and what stops it.
 * @param {import("knex").Knex} src  the upgraded SQLite
 * @param {import("knex").Knex} dst  NPMOS
 */
export const analyze = async (src, dst) => {
	const counts = {};
	for (const table of TABLES) counts[table] = await count(src, table);
	const live = {};
	for (const table of [...HOSTS, "certificate", "access_list"]) {
		live[table] = (await src.schema.hasTable(table))
			? Number((await src(table).where("is_deleted", 0).count("* as n").first()).n)
			: 0;
	}
	const blocking = [];
	for (const table of KEEP_IDS) {
		const n = await count(dst, table);
		if (n) blocking.push({ table, count: n });
	}
	const existing = new Set(
		(await dst("user").where("is_deleted", 0).select("email")).map((u) => String(u.email).toLowerCase()),
	);
	const users = (await src("user").where("is_deleted", 0).select("id", "email", "name", "roles", "is_disabled")).map(
		(u) => ({
			email: u.email,
			name: u.name,
			admin: (parse(u.roles, []) || []).includes("admin"),
			disabled: !!u.is_disabled,
			exists: existing.has(String(u.email).toLowerCase()),
		}),
	);
	const certificates = (await src.schema.hasTable("certificate"))
		? (
				await src("certificate")
					.where("is_deleted", 0)
					.select("id", "provider", "nice_name", "domain_names", "expires_on")
			).map((c) => ({
				id: c.id,
				provider: c.provider,
				name: c.nice_name || (parse(c.domain_names, []) || []).join(", "),
				expires_on: c.expires_on,
			}))
		: [];
	const plainPasswords = (await src.schema.hasTable("access_list_auth"))
		? (await src("access_list_auth").select("password")).filter((r) => r.password && !HASHED.test(r.password))
				.length
		: 0;
	return { counts, live, blocking, users, certificates, plainPasswords };
};

/** a role with exactly these permissions, or a new one (named like the RBAC migration does) */
const roleFor = async (trx, { scope, permissions }, now) => {
	const wanted = [...permissions].sort().join(",");
	const roles = await trx("npmos_role").whereNull("builtin").andWhere("scope", scope).select("id");
	for (const role of roles) {
		const perms = (await trx("npmos_role_permission").where("role_id", role.id).select("resource", "action"))
			.map((p) => `${p.resource}:${p.action}`)
			.sort()
			.join(",");
		if (perms === wanted) return role.id;
	}
	let name = "Imported permissions";
	for (let n = 2; await trx("npmos_role").where("name", name).first(); n++) name = `Imported permissions ${n}`;
	const [inserted] = await trx("npmos_role")
		.insert({
			name,
			description: "Moved from the per-user permissions of the imported installation",
			builtin: null,
			scope,
			oidc_groups: "[]",
			created_on: now,
			modified_on: now,
		})
		.returning("id");
	const id = typeof inserted === "object" ? inserted.id : inserted;
	if (permissions.length) {
		await trx("npmos_role_permission").insert(
			permissions.map((p) => {
				const [resource, action] = p.split(":");
				return { role_id: id, resource, action };
			}),
		);
	}
	return id;
};

const insertRows = async (trx, table, rows) => {
	for (let i = 0; i < rows.length; i += 100) await trx(table).insert(rows.slice(i, i + 100));
};

/**
 * Imports everything in one transaction of NPMOS.
 * @param {{history?: boolean}} options  history: the audit log of the source
 * @returns {Promise<object>} what was imported
 */
export const importInto = async (src, dst, { history = true } = {}) => {
	const now = new Date();
	const columnsOf = {};
	for (const table of TABLES) {
		if ((await src.schema.hasTable(table)) && (await dst.schema.hasTable(table))) {
			const target = await dst(table).columnInfo();
			const source = Object.keys(await src(table).columnInfo());
			columnsOf[table] = Object.fromEntries(Object.entries(target).filter(([c]) => source.includes(c)));
		}
	}
	const rowsOf = async (table) => {
		if (!columnsOf[table]) return [];
		const query = src(table).select(Object.keys(columnsOf[table]));
		return "id" in columnsOf[table] ? query.orderBy("id") : query;
	};
	const shape = (table, row) =>
		Object.fromEntries(Object.entries(row).map(([c, v]) => [c, convert(v, c, columnsOf[table][c])]));

	return dst.transaction(async (trx) => {
		for (const table of KEEP_IDS) {
			if (await count(trx, table)) throw new Error(`NPMOS already has rows in ${table}`);
		}
		const report = { users: { added: [], matched: [] }, rows: {}, roles: 0, hashed: 0 };

		// users: matched by email, else added
		const userMap = new Map();
		const added = new Set();
		const existing = await trx("user").where("is_deleted", 0).select("id", "email");
		const byEmail = new Map(existing.map((u) => [String(u.email).toLowerCase(), u.id]));
		for (const user of await rowsOf("user")) {
			const email = String(user.email).toLowerCase();
			if (!user.is_deleted && byEmail.has(email)) {
				userMap.set(user.id, byEmail.get(email));
				report.users.matched.push(user.email);
				continue;
			}
			const { id, ...rest } = shape("user", user);
			// gravatar addresses are blocked by the CSP of NPMOS; the avatar is made again on save
			if ("avatar" in rest) rest.avatar = "";
			const [inserted] = await trx("user").insert(rest).returning("id");
			const newId = typeof inserted === "object" ? inserted.id : inserted;
			userMap.set(id, newId);
			added.add(newId);
			if (!user.is_deleted) report.users.added.push(user.email);
		}
		const mapUser = (id) => userMap.get(id) ?? [...userMap.values()][0] ?? id;

		for (const table of ["auth", "user_permission"]) {
			const rows = (await rowsOf(table))
				.filter((r) => added.has(userMap.get(r.user_id)))
				.map((r) => {
					const { id, ...rest } = shape(table, r);
					return { ...rest, user_id: userMap.get(r.user_id) };
				});
			await insertRows(trx, table, rows);
		}

		// roles of the added users (administrators keep the admin flag)
		const roleIds = new Map();
		for (const perm of await rowsOf("user_permission")) {
			const userId = userMap.get(perm.user_id);
			if (!added.has(userId)) continue;
			const user = await trx("user").where("id", userId).first();
			if ((parse(user.roles, []) || []).includes("admin") || !perm.visibility) continue;
			const signature = fromProjection(perm);
			const key = JSON.stringify(signature);
			if (!roleIds.has(key)) roleIds.set(key, await roleFor(trx, signature, now));
			await trx("npmos_user_role").insert({ user_id: userId, role_id: roleIds.get(key) });
		}
		report.roles = roleIds.size;

		// the rest keeps its ids
		for (const table of TABLES.filter(
			(t) => !["user", "auth", "user_permission", "setting", "audit_log"].includes(t),
		)) {
			const rows = (await rowsOf(table)).map((r) => {
				const row = shape(table, r);
				if (OWNED.includes(table) && "owner_user_id" in row) row.owner_user_id = mapUser(row.owner_user_id);
				if (table === "access_list_auth" && row.password) {
					const hashed = hashAccessPassword(row.password);
					if (hashed !== row.password) report.hashed += 1;
					row.password = hashed;
				}
				return row;
			});
			await insertRows(trx, table, rows);
			report.rows[table] = rows.length;
			if (rows.length && "id" in rows[0]) {
				await trx.raw(
					`SELECT setval(pg_get_serial_sequence('"${table}"', 'id'), (SELECT MAX(id) FROM "${table}"))`,
				);
			}
		}

		// settings of the source win (default site and the like)
		let settings = 0;
		for (const row of await (columnsOf.setting ? src("setting").select(Object.keys(columnsOf.setting)) : [])) {
			if (SKIP_SETTINGS.includes(row.id)) continue;
			await trx("setting").insert(shape("setting", row)).onConflict("id").merge();
			settings += 1;
		}
		report.rows.setting = settings;

		if (history) {
			const rows = (await rowsOf("audit_log")).map((r) => {
				const { id, ...rest } = shape("audit_log", r);
				rest.user_id = mapUser(rest.user_id);
				if (rest.object_type === "user") rest.object_id = userMap.get(rest.object_id) ?? rest.object_id;
				return rest;
			});
			await insertRows(trx, "audit_log", rows);
			report.rows.audit_log = rows.length;
		}
		return report;
	});
};
