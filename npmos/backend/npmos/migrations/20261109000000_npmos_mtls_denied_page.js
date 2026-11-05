import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_mtls_denied_page";

/**
 * What a host with mTLS answers to a refused client: certificate (the page "a client certificate is required", 403),
 * blocked (the block page of NPMOS, 403), not_found (the 404 page, the site looks absent) or close (no answer, 444).
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("npmos_mtls_host", (table) => {
		table.string("denied_page", 16).notNullable().defaultTo("certificate");
	});
};

const down = async (knex) => {
	await knex.schema.alterTable("npmos_mtls_host", (table) => {
		table.dropColumn("denied_page");
	});
};

export { down, up };
