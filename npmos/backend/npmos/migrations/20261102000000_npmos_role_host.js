import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_role_host";

/**
 * RBAC: hosts given to a role of scope "hosts" (its members see their own hosts and these).
 * host_type: proxy_host | redirection_host | dead_host | stream.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_role_host", (table) => {
		table.integer("role_id").unsigned().notNull();
		table.string("host_type", 32).notNull();
		table.integer("host_id").unsigned().notNull();
		table.primary(["role_id", "host_type", "host_id"]);
		table.index("role_id");
	});
	logger.info(`[${migrateName}] npmos_role_host created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_role_host");
};

export { down, up };
