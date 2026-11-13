import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_waf_trial";

/**
 * Trial mode of a host (docs/ROADMAP.md, phase 12): blocking is tried for some hours on the log only (the host keeps
 * its mode), then a report of what blocking would have done with the events of those hours and the offer to switch.
 * One open trial per host: closed when it is enabled, dismissed or cancelled.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("nginxions_waf_trial", (table) => {
		table.increments("id").primary();
		table.string("node_id", 64).notNull().defaultTo("local");
		table.integer("proxy_host_id").notNull();
		table.dateTime("started_on").notNull();
		table.dateTime("ends_on").notNull();
		// the mode that is tried
		table.string("mode", 32).notNull();
		table.integer("user_id").notNull().defaultTo(0);
		// the end was reached: the report of its hours is kept
		table.dateTime("finished_on");
		table.text("report").notNull();
		// enabled, dismissed, cancelled; empty while it is open
		table.string("outcome", 16).notNull().defaultTo("");
		table.dateTime("closed_on");
		table.integer("closed_by");
		table.index(["proxy_host_id"]);
	});
	logger.info(`[${migrateName}] nginxions_waf_trial created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("nginxions_waf_trial");
};

export { down, up };
