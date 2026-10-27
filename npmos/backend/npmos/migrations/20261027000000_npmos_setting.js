import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_setting";

/**
 * NPMOS settings changed in the GUI: key → JSON value. A missing key means "use the default"
 * (usually the env value of the first start), see npmos/settings.js.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_setting", (table) => {
		table.string("key", 100).primary();
		table.json("value").notNull();
		table.dateTime("modified_on").notNull();
	});
	logger.info(`[${migrateName}] npmos_setting Table created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_setting");
};

export { down, up };
