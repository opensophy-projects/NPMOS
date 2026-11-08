import { migrate as logger } from "../logger.js";

const migrateName = "drop_access_list_relation_foreign_keys";

const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	await knex.schema.alterTable("npmplus_proxy_host_access_list", (table) => {
		table.dropForeign("proxy_host_id");
		table.dropForeign("access_list_id");
	});

	logger.info(`[${migrateName}] npmplus_proxy_host_access_list Table altered`);
};

const down = (_knex) => {
	logger.warn(`[${migrateName}] You can't migrate down this one.`);
	return Promise.resolve(true);
};

export { down, up };
