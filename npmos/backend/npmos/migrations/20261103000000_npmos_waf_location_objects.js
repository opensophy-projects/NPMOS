import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_waf_location_objects";

/**
 * WAF: own policy objects of a location (references as npmos_waf_host.objects); null: the
 * location takes the objects of its host.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("npmos_waf_location", (table) => {
		table.text("objects").nullable();
	});
	logger.info(`[${migrateName}] npmos_waf_location.objects added`);
};

const down = async (knex) => {
	await knex.schema.alterTable("npmos_waf_location", (table) => {
		table.dropColumn("objects");
	});
};

export { down, up };
