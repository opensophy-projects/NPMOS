import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_request_hourly";

/**
 * Requests of the hosts per hour from the access log of nginx (Analytics: all requests, not only attacks):
 * by status class, blocked ones (403, 429, 444, 495, 496) and bytes sent.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_request_hourly", (table) => {
		table.string("node_id", 64).notNull().defaultTo("local");
		table.dateTime("hour").notNull();
		table.string("host", 255).notNull();
		table.bigInteger("requests").notNull().defaultTo(0);
		table.bigInteger("s2xx").notNull().defaultTo(0);
		table.bigInteger("s3xx").notNull().defaultTo(0);
		table.bigInteger("s4xx").notNull().defaultTo(0);
		table.bigInteger("s5xx").notNull().defaultTo(0);
		table.bigInteger("blocked").notNull().defaultTo(0);
		table.bigInteger("bytes").notNull().defaultTo(0);
		table.primary(["hour", "node_id", "host"]);
	});
	logger.info(`[${migrateName}] npmos_request_hourly created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_request_hourly");
};

export { down, up };
