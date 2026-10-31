import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_mtls_revocation";

/**
 * How a host with mTLS checks revocation: crl (nginx reads the CRL files, reloaded when one changes) or ocsp
 * (nginx asks the OCSP responder of NPMOS, no reload).
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("npmos_mtls_host", (table) => {
		table.string("revocation", 8).notNullable().defaultTo("crl");
	});
};

const down = async (knex) => {
	await knex.schema.alterTable("npmos_mtls_host", (table) => {
		table.dropColumn("revocation");
	});
};

export { down, up };
