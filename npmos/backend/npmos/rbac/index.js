// RBAC of NPMOS: roles in the database (npmos_role, npmos_role_permission, npmos_user_role), the
// adapter for upstream access.can() and the API of Administration → Roles. Rules: ./model.js.
import internalAuditLog from "../../internal/audit-log.js";
import db from "../../db.js";
import errs from "../../lib/error.js";
import { debug, access as logger } from "../../logger.js";
import userModel from "../../models/user.js";
import userPermissionModel from "../../models/user_permission.js";
import { getSetting, setSetting } from "../settings.js";
import * as model from "./model.js";
import { HOST_TABLES } from "./scope.js";

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);
const roleTable = () => db()("npmos_role");

const isAdminRoles = (roles) => (parse(roles) ?? []).includes("admin");

/** hosts of roles (scope "hosts"); none before the migration */
const hostsOf = (roleIds) =>
	db()("npmos_role_host")
		.whereIn("role_id", roleIds)
		.select("role_id", "host_type", "host_id")
		.catch(() => []);

/** roles of a user with their permissions (without the admin flag) */
async function rolesOf(userId) {
	const rows = await db()("npmos_user_role")
		.join("npmos_role", "npmos_role.id", "npmos_user_role.role_id")
		.where("npmos_user_role.user_id", userId)
		.select("npmos_role.id", "npmos_role.builtin", "npmos_role.scope");
	const custom = rows.filter((r) => !r.builtin).map((r) => r.id);
	const permissionRows = custom.length
		? await db()("npmos_role_permission").whereIn("role_id", custom).select("role_id", "resource", "action")
		: [];
	const hostRows = custom.length ? await hostsOf(custom) : [];
	return rows.map((row) => ({
		id: row.id,
		scope: row.builtin ? model.BUILTIN[row.builtin]?.scope : row.scope,
		hosts: hostRows.filter((h) => h.role_id === row.id),
		permissions: row.builtin
			? (model.BUILTIN[row.builtin]?.permissions ?? [])
			: permissionRows.filter((p) => p.role_id === row.id).map((p) => `${p.resource}:${p.action}`),
	}));
}

/** effective permissions of a user loaded with its upstream "roles" column */
const effectiveOf = async (user) => {
	const admin = isAdminRoles(user.roles);
	return model.effective(admin, admin ? [] : await rolesOf(user.id));
};

/**
 * Adapter for access.js (init): the permissions of the token's user come from the roles.
 * Writes user_permission when it differs from the roles, so upstream code and UI that read
 * it directly see the same.
 * @param {object} user  with roles and permissions (upstream graph)
 * @returns {Promise<object>} upstream permissions object, plus `npmos` (effective permissions)
 */
export async function resolve(user) {
	const eff = await effectiveOf(user);
	const row = model.projection(eff);
	const current = user.permissions ?? {};
	const stale = Object.keys(row).some((key) => current[key] !== row[key]);
	if (stale) {
		const updated = await userPermissionModel.query().where("user_id", user.id).patch(row);
		if (!updated) await userPermissionModel.query().insert({ user_id: user.id, ...row });
		debug(logger, `user ${user.id}: user_permission follows the roles`);
	}
	return { ...current, ...row, npmos: eff };
}

const userIsAdmin = async (id) => {
	if (!Number.isInteger(id)) return false;
	const user = await userModel.query().select("roles").where("id", id).first();
	return !!user && isAdminRoles(user.roles);
};

/**
 * Adapter for access.js (can): decides NPMOS labels and opens admin-only upstream sections to
 * roles. undefined: the upstream permission schema decides.
 * @returns {Promise<object|false|undefined>}
 */
export async function check(permissions, label, data) {
	const eff = permissions?.npmos ?? { admin: false, scope: "own", permissions: new Set() };
	const grant = model.UPSTREAM_GRANTS[label];
	let targetIsAdmin = false;
	if (grant?.target && !eff.admin && eff.permissions.has(grant.permission)) {
		targetIsAdmin =
			label === "users:create"
				? (data?.roles ?? []).includes("admin")
				: await userIsAdmin(Number(typeof data === "object" ? data?.id : data));
	}
	const decision = model.decide(label, eff, { targetIsAdmin });
	if (decision === "grant") {
		return { permission_visibility: eff.scope === "all" ? "all" : "user", npmos_hosts: eff.hosts ?? {} };
	}
	if (decision === "deny") return false;
	return undefined;
}

// ---- API ----

/** permissions of the actor (the checks below need them, access.js does not expose them) */
const actorOf = async (access) => {
	const user = await userModel.query().select("id", "roles").where("id", access.token.getUserId(1)).first();
	if (!user) throw new errs.AuthError("User not found");
	return effectiveOf(user);
};

const forbid = (lacking) => {
	if (lacking.length) {
		throw new errs.PermissionError(`Permission Denied: you do not have ${lacking.join(", ")}`);
	}
};

const roleRows = async (where) => {
	const roles = await roleTable()
		.where(where ?? {})
		.select();
	const ids = roles.map((r) => r.id);
	const permissions = ids.length ? await db()("npmos_role_permission").whereIn("role_id", ids) : [];
	const hosts = ids.length ? await hostsOf(ids) : [];
	const members = ids.length
		? await db()("npmos_user_role")
				.join("user", "user.id", "npmos_user_role.user_id")
				.where("user.is_deleted", 0)
				.whereIn("role_id", ids)
				.select("role_id", "user.id", "user.name", "user.email")
		: [];
	const admins = await userModel.query().select("id", "name", "email", "roles").where("is_deleted", 0);
	const order = Object.keys(model.BUILTIN);
	return roles
		.map((role) => {
			const builtin = role.builtin ? model.BUILTIN[role.builtin] : null;
			return {
				id: role.id,
				name: role.name,
				description: role.description ?? "",
				builtin: role.builtin || null,
				scope: builtin ? builtin.scope : role.scope,
				oidc_groups: parse(role.oidc_groups) ?? [],
				hosts: hosts
					.filter((h) => h.role_id === role.id)
					.map(({ host_type, host_id }) => ({ host_type, host_id })),
				permissions: builtin
					? model.normalize(builtin.permissions)
					: model.normalize(
							permissions.filter((p) => p.role_id === role.id).map((p) => `${p.resource}:${p.action}`),
						),
				users:
					role.builtin === "administrator"
						? admins
								.filter((u) => isAdminRoles(u.roles))
								.map(({ id, name, email }) => ({ id, name, email }))
						: members
								.filter((m) => m.role_id === role.id)
								.map(({ id, name, email }) => ({ id, name, email })),
				created_on: role.created_on,
				modified_on: role.modified_on,
			};
		})
		.sort((a, b) => {
			const x = a.builtin ? order.indexOf(a.builtin) : order.length;
			const y = b.builtin ? order.indexOf(b.builtin) : order.length;
			return x - y || a.name.localeCompare(b.name);
		});
};

const getRole = async (id) => {
	const [role] = await roleRows({ id });
	if (!role) throw new errs.ItemNotFoundError(id);
	return role;
};

const cleanGroups = (groups) => [...new Set((groups ?? []).map((g) => String(g).trim()).filter(Boolean))];

const validateRole = async (data, id) => {
	const name = String(data.name ?? "").trim();
	if (!name || name.length > 100) throw new errs.ValidationError("A role needs a name (up to 100 characters)");
	if (!model.SCOPES.includes(data.scope)) throw new errs.ValidationError("scope must be all, own or hosts");
	const hosts = data.scope === "hosts" ? await validHosts(data.hosts ?? []) : [];
	if (data.scope === "hosts" && !hosts.length) throw new errs.ValidationError("Choose the hosts of the role");
	const same = await roleTable()
		.whereRaw("lower(name) = ?", [name.toLowerCase()])
		.whereNot("id", id ?? 0)
		.first();
	if (same) throw new errs.ValidationError(`A role named ${name} already exists`);
	return {
		name,
		description: String(data.description ?? "").slice(0, 500),
		scope: data.scope,
		oidc_groups: cleanGroups(data.oidc_groups),
		permissions: model.normalize(data.permissions ?? []),
		hosts,
	};
};

/** existing hosts only, each once */
const validHosts = async (list) => {
	const result = [];
	for (const table of HOST_TABLES) {
		const wanted = [...new Set(list.filter((h) => h.host_type === table).map((h) => Number(h.host_id)))];
		if (!wanted.length) continue;
		const found = await db()(table).whereIn("id", wanted).where("is_deleted", 0).select("id");
		if (found.length !== wanted.length) throw new errs.ValidationError(`Unknown ${table} in the role`);
		for (const { id } of found) result.push({ host_type: table, host_id: id });
	}
	if (list.some((h) => !HOST_TABLES.includes(h.host_type))) throw new errs.ValidationError("Unknown host type");
	return result;
};

const writeHosts = async (trx, roleId, hosts) => {
	await trx("npmos_role_host").where("role_id", roleId).delete();
	if (hosts.length) await trx("npmos_role_host").insert(hosts.map((h) => ({ role_id: roleId, ...h })));
};

const writePermissions = async (trx, roleId, permissions) => {
	await trx("npmos_role_permission").where("role_id", roleId).delete();
	if (permissions.length) {
		await trx("npmos_role_permission").insert(
			permissions.map((p) => {
				const [resource, action] = p.split(":");
				return { role_id: roleId, resource, action };
			}),
		);
	}
};

/** user_permission of the members follows a changed role at once (the UI lists it) */
const resyncMembers = async (roleId) => {
	const ids = (await db()("npmos_user_role").where("role_id", roleId).select("user_id")).map((r) => r.user_id);
	await resyncUsers(ids);
};

const resyncUsers = async (ids) => {
	if (!ids.length) return;
	const users = await userModel
		.query()
		.whereIn("id", ids)
		.allowGraph("[permissions]")
		.withGraphFetched("[permissions]");
	for (const user of users) await resolve(user);
};

const audit = (access, action, objectType, objectId, meta) =>
	internalAuditLog.add(access, { action, object_type: objectType, object_id: objectId, meta });

const internalRbac = {
	/**
	 * Resources, actions and built-in roles (the role editor is built from it). Lists, not maps:
	 * the API client camelizes keys, and resource names are matched as values.
	 */
	model: () => ({
		resources: Object.entries(model.RESOURCES).map(([id, actions]) => ({ id, actions })),
		scopes: model.SCOPES,
		builtin: Object.entries(model.BUILTIN).map(([key, role]) => ({
			key,
			name: role.name,
			scope: role.scope,
			permissions: model.normalize(role.permissions),
		})),
	}),

	/** permissions of the current user, for the UI */
	me: async (access) => {
		const userId = access.token.getUserId(1);
		const user = await userModel.query().select("id", "roles").where("id", userId).first();
		if (!user) throw new errs.AuthError("User not found");
		const eff = await effectiveOf(user);
		const roles = await db()("npmos_user_role")
			.join("npmos_role", "npmos_role.id", "npmos_user_role.role_id")
			.where("npmos_user_role.user_id", userId)
			.select("npmos_role.id", "npmos_role.name", "npmos_role.builtin");
		if (eff.admin) {
			const admin = await roleTable().where("builtin", "administrator").select("id", "name", "builtin").first();
			if (admin) roles.unshift(admin);
		}
		return { admin: eff.admin, scope: eff.scope, hosts: eff.hosts, permissions: [...eff.permissions], roles };
	},

	list: async (access) => {
		await access.can("roles:view");
		return roleRows();
	},

	get: async (access, id) => {
		await access.can("roles:view");
		return getRole(id);
	},

	create: async (access, data) => {
		await access.can("roles:manage");
		const role = await validateRole(data);
		forbid(model.missing(await actorOf(access), role.permissions, role.scope));
		const id = await db().transaction(async (trx) => {
			const [inserted] = await trx("npmos_role")
				.insert({
					name: role.name,
					description: role.description,
					scope: role.scope,
					oidc_groups: JSON.stringify(role.oidc_groups),
					builtin: null,
					created_on: new Date(),
					modified_on: new Date(),
				})
				.returning("id");
			const roleId = typeof inserted === "object" ? inserted.id : inserted;
			await writePermissions(trx, roleId, role.permissions);
			await writeHosts(trx, roleId, role.hosts);
			return roleId;
		});
		await audit(access, "created", "role", id, { name: role.name, permissions: role.permissions });
		return getRole(id);
	},

	update: async (access, id, data) => {
		await access.can("roles:manage");
		const current = await getRole(id);
		const actor = await actorOf(access);
		if (current.builtin) {
			// built-in roles: only who gets them through OIDC
			if (current.builtin === "administrator" && !actor.admin) forbid(["roles:administrator"]);
			await roleTable()
				.where({ id })
				.update({ oidc_groups: JSON.stringify(cleanGroups(data.oidc_groups)), modified_on: new Date() });
			await audit(access, "updated", "role", id, {
				name: current.name,
				oidc_groups: cleanGroups(data.oidc_groups),
			});
			return getRole(id);
		}
		const role = await validateRole(data, id);
		// nobody edits a role stronger than themselves
		forbid([
			...model.missing(actor, current.permissions, current.scope),
			...model.missing(actor, role.permissions, role.scope),
		]);
		await db().transaction(async (trx) => {
			await trx("npmos_role")
				.where({ id })
				.update({
					name: role.name,
					description: role.description,
					scope: role.scope,
					oidc_groups: JSON.stringify(role.oidc_groups),
					modified_on: new Date(),
				});
			await writePermissions(trx, id, role.permissions);
			await writeHosts(trx, id, role.hosts);
		});
		await resyncMembers(id);
		await audit(access, "updated", "role", id, { name: role.name, permissions: role.permissions });
		return getRole(id);
	},

	delete: async (access, id) => {
		await access.can("roles:manage");
		const current = await getRole(id);
		if (current.builtin) throw new errs.ValidationError("Built-in roles cannot be deleted");
		forbid(model.missing(await actorOf(access), current.permissions, current.scope));
		const members = current.users.map((u) => u.id);
		await db().transaction(async (trx) => {
			await trx("npmos_user_role").where("role_id", id).delete();
			await trx("npmos_role_permission").where("role_id", id).delete();
			await trx("npmos_role_host").where("role_id", id).delete();
			await trx("npmos_role").where({ id }).delete();
		});
		await resyncUsers(members);
		await audit(access, "deleted", "role", id, { name: current.name });
		return true;
	},

	/** {user id: [{id, name, builtin}]} of all users, the Administrator role for admins */
	assignments: async (access) => {
		try {
			await access.can("users:list");
		} catch {
			await access.can("roles:view");
		}
		const roles = await roleTable().select("id", "name", "builtin");
		const admin = roles.find((r) => r.builtin === "administrator");
		const result = {};
		for (const user of await userModel.query().select("id", "roles").where("is_deleted", 0)) {
			result[user.id] = isAdminRoles(user.roles) && admin ? [admin] : [];
		}
		for (const row of await db()("npmos_user_role").select("user_id", "role_id")) {
			const role = roles.find((r) => r.id === row.role_id);
			if (result[row.user_id] && role) result[row.user_id].push(role);
		}
		return result;
	},

	/**
	 * Roles of a user. The Administrator role is the upstream admin flag.
	 * @param {number[]} roleIds
	 */
	setUserRoles: async (access, userId, roleIds) => {
		await access.can("roles:manage");
		const user = await userModel
			.query()
			.where({ id: userId, is_deleted: 0 })
			.allowGraph("[permissions]")
			.withGraphFetched("[permissions]")
			.first();
		if (!user) throw new errs.ItemNotFoundError(userId);
		const roles = await roleRows();
		const chosen = roles.filter((r) => roleIds.includes(r.id));
		if (chosen.length !== new Set(roleIds).size) throw new errs.ValidationError("Unknown role");
		const actor = await actorOf(access);
		const makeAdmin = chosen.some((r) => r.builtin === "administrator");
		const wasAdmin = isAdminRoles(user.roles);
		if (!actor.admin && (wasAdmin || makeAdmin)) forbid(["roles:administrator"]);
		for (const role of chosen) forbid(model.missing(actor, role.permissions, role.scope));
		// the roles taken away must be within the actor's too
		const before = roles.filter((r) => r.users.some((u) => u.id === userId));
		for (const role of before) forbid(model.missing(actor, role.permissions, role.scope));
		if (wasAdmin && !makeAdmin) {
			const admins = (await userModel.query().select("roles").where({ is_deleted: 0, is_disabled: 0 })).filter(
				(u) => isAdminRoles(u.roles),
			);
			if (admins.length <= 1) throw new errs.ValidationError("The last administrator cannot lose the role");
		}
		await db().transaction(async (trx) => {
			await trx("npmos_user_role").where("user_id", userId).delete();
			const rows = chosen.filter((r) => !r.builtin || r.builtin !== "administrator");
			if (rows.length) await trx("npmos_user_role").insert(rows.map((r) => ({ user_id: userId, role_id: r.id })));
		});
		if (wasAdmin !== makeAdmin) {
			const flags = (parse(user.roles) ?? []).filter((r) => r !== "admin");
			await userModel
				.query()
				.patch({ roles: makeAdmin ? [...flags, "admin"] : flags })
				.where("id", userId);
		}
		const updated = await userModel
			.query()
			.where({ id: userId })
			.allowGraph("[permissions]")
			.withGraphFetched("[permissions]")
			.first();
		await resolve(updated);
		await audit(access, "updated", "user", userId, { name: user.name, roles: chosen.map((r) => r.name) });
		return chosen.map((r) => r.id);
	},

	getOidc: async (access) => {
		await access.can("roles:view");
		return getSetting("rbac.oidc");
	},

	setOidc: async (access, value) => {
		await access.can("roles:manage");
		const saved = await setSetting("rbac.oidc", value);
		await audit(access, "updated", "role", 0, { name: "OIDC", ...saved });
		return saved;
	},
};

/**
 * OIDC login (routes/oidc.js): the roles of the user follow the IdP groups when at least one
 * role names OIDC groups. A user in none of them keeps no role; the last administrator stays one.
 * @param {string} email
 * @param {object} claims  id token claims (and userinfo)
 */
export async function syncOidcGroups(email, claims) {
	const { claim } = await getSetting("rbac.oidc");
	const roles = await roleRows();
	const mapped = roles.filter((r) => r.oidc_groups.length);
	const raw = claims?.[claim];
	if (!mapped.length || raw === undefined) return;
	const groups = new Set((Array.isArray(raw) ? raw : String(raw).split(/[,\s]+/)).map(String));
	const user = await userModel.query().where({ email, is_deleted: 0 }).first();
	if (!user) return;
	const chosen = mapped.filter((r) => r.oidc_groups.some((g) => groups.has(g)));
	const makeAdmin = chosen.some((r) => r.builtin === "administrator");
	const wasAdmin = isAdminRoles(user.roles);
	let keepAdmin = makeAdmin;
	if (wasAdmin && !makeAdmin) {
		const admins = (await userModel.query().select("roles").where({ is_deleted: 0, is_disabled: 0 })).filter((u) =>
			isAdminRoles(u.roles),
		);
		keepAdmin = admins.length <= 1;
	}
	await db().transaction(async (trx) => {
		await trx("npmos_user_role").where("user_id", user.id).delete();
		const rows = chosen.filter((r) => r.builtin !== "administrator");
		if (rows.length) await trx("npmos_user_role").insert(rows.map((r) => ({ user_id: user.id, role_id: r.id })));
	});
	if (wasAdmin !== keepAdmin) {
		const flags = (parse(user.roles) ?? []).filter((r) => r !== "admin");
		await userModel
			.query()
			.patch({ roles: keepAdmin ? [...flags, "admin"] : flags })
			.where("id", user.id);
	}
	await internalAuditLog.add(null, {
		user_id: user.id,
		action: "updated",
		object_type: "user",
		object_id: user.id,
		meta: { name: user.name, roles: chosen.map((r) => r.name), source: "oidc" },
	});
}

export default internalRbac;
