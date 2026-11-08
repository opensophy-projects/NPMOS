import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_waf_location_objects";

/**
 * WAF: own policy objects of a location (references as nginxions_waf_host.objects); null: the
 * location takes the objects of its host.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("nginxions_waf_location", (table) => {
		table.text("objects").nullable();
	});
	logger.info(`[${migrateName}] nginxions_waf_location.objects added`);
};

const down = async (knex) => {
	await knex.schema.alterTable("nginxions_waf_location", (table) => {
		table.dropColumn("objects");
	});
};

export { down, up };
