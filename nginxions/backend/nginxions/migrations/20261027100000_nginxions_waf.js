import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_waf";

/**
 * open-appsec settings of proxy hosts and their locations. The source of truth for the WAF:
 * local_policy.yaml is generated from these tables (nginxions/waf/policy.js).
 * A location without a row inherits the settings of its host.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("nginxions_waf_host", (table) => {
		table.integer("proxy_host_id").unsigned().primary();
		table.boolean("enabled").notNull().defaultTo(false);
		table.string("mode", 20).notNull().defaultTo("detect-learn");
		table.string("minimum_confidence", 20).notNull().defaultTo("high");
		table.dateTime("modified_on").notNull();
	});
	await knex.schema.createTable("nginxions_waf_location", (table) => {
		table.increments().primary();
		table.integer("proxy_host_id").unsigned().notNull();
		table.string("path", 255).notNull();
		table.boolean("enabled").notNull().defaultTo(false);
		table.string("mode", 20).notNull().defaultTo("detect-learn");
		table.string("minimum_confidence", 20).notNull().defaultTo("high");
		table.dateTime("modified_on").notNull();
		table.unique(["proxy_host_id", "path"]);
	});
	logger.info(`[${migrateName}] nginxions_waf_host, nginxions_waf_location Tables created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("nginxions_waf_location");
	await knex.schema.dropTable("nginxions_waf_host");
};

export { down, up };
