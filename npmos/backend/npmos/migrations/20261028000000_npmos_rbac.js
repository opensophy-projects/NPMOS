import { migrate as logger } from "../../logger.js";
import { BUILTIN, fromProjection } from "../rbac/model.js";

const migrateName = "npmos_rbac";

const DEFAULT_SIGNATURE = JSON.stringify(
	fromProjection({
		visibility: "user",
		proxy_hosts: "manage",
		redirection_hosts: "manage",
		dead_hosts: "manage",
		streams: "manage",
		access_lists: "manage",
		certificates: "manage",
	}),
);

/**
 * Roles (docs/ROADMAP.md, phase 3). Built-in roles get a row each (their permissions are in
 * rbac/model.js). The per-user permissions of upstream become roles: users with the same
 * permissions share one, so nothing changes for them; administrators keep the admin flag
 * (= the Administrator role).
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_role", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("name", 100).notNull().unique();
		table.string("description", 500).notNull().defaultTo("");
		// key of a built-in role, null for roles made in the GUI
		table.string("builtin", 32).nullable().unique();
		// all: every host; own: the hosts the user owns
		table.string("scope", 8).notNull().defaultTo("all");
		// OIDC groups that give this role (Administration → Roles)
		table.json("oidc_groups").notNull();
	});
	await knex.schema.createTable("npmos_role_permission", (table) => {
		table.integer("role_id").notNull().unsigned();
		table.string("resource", 50).notNull();
		table.string("action", 50).notNull();
		table.primary(["role_id", "resource", "action"]);
	});
	await knex.schema.createTable("npmos_user_role", (table) => {
		table.integer("user_id").notNull().unsigned();
		table.integer("role_id").notNull().unsigned();
		table.primary(["user_id", "role_id"]);
		table.index("role_id");
	});
	logger.info(`[${migrateName}] npmos_role, npmos_role_permission, npmos_user_role tables created`);

	const now = new Date();
	for (const [key, role] of Object.entries(BUILTIN)) {
		await knex("npmos_role").insert({
			name: role.name,
			description: "",
			builtin: key,
			scope: role.scope,
			oidc_groups: "[]",
			created_on: now,
			modified_on: now,
		});
	}

	// per-user permissions → roles
	const users = await knex("user")
		.leftJoin("user_permission", "user_permission.user_id", "user.id")
		.where("user.is_deleted", 0)
		.select("user.id", "user.roles", "user_permission.*", "user.id as uid");
	const bySignature = new Map();
	for (const user of users) {
		const roles = typeof user.roles === "string" ? JSON.parse(user.roles) : user.roles || [];
		if (roles.includes("admin") || !user.visibility) continue;
		const signature = JSON.stringify(fromProjection(user));
		if (!bySignature.has(signature)) bySignature.set(signature, []);
		bySignature.get(signature).push(user.uid);
	}
	let n = 0;
	for (const [signature, userIds] of bySignature) {
		const { scope, permissions } = JSON.parse(signature);
		n += 1;
		const name = signature === DEFAULT_SIGNATURE ? "NPMplus user" : `NPMplus permissions ${n}`;
		const [inserted] = await knex("npmos_role")
			.insert({
				name,
				description: "Moved from the per-user permissions of NPMplus",
				builtin: null,
				scope,
				oidc_groups: "[]",
				created_on: now,
				modified_on: now,
			})
			.returning("id");
		const roleId = typeof inserted === "object" ? inserted.id : inserted;
		if (permissions.length) {
			await knex("npmos_role_permission").insert(
				permissions.map((p) => {
					const [resource, action] = p.split(":");
					return { role_id: roleId, resource, action };
				}),
			);
		}
		await knex("npmos_user_role").insert(userIds.map((userId) => ({ user_id: userId, role_id: roleId })));
		logger.info(`[${migrateName}] role "${name}" for ${userIds.length} user(s)`);
	}
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_user_role");
	await knex.schema.dropTable("npmos_role_permission");
	await knex.schema.dropTable("npmos_role");
};

export { down, up };
