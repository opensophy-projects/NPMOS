import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_waf_custom_policy";

/**
 * WAF -> Policy (expert): versions of the administrator's YAML fragments merged over the generated
 * local_policy.yaml. The newest row is in force; a rollback adds a copy of an older one.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_waf_custom_policy", (table) => {
		table.increments().primary();
		table.text("content").notNull();
		table.string("comment", 255).notNull().defaultTo("");
		table.integer("user_id").unsigned();
		table.dateTime("created_on").notNull();
	});
	logger.info(`[${migrateName}] npmos_waf_custom_policy Table created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_waf_custom_policy");
};

export { down, up };
