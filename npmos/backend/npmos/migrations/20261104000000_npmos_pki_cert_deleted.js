import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_pki_cert_deleted";

/**
 * mTLS access certificates can be deleted in the GUI. A deleted certificate keeps its row (revoked
 * before it is hidden): the CRL of its CA is generated from the database and must keep listing it.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("npmos_pki_cert", (table) => {
		table.dateTime("deleted_on").nullable();
	});
	logger.info(`[${migrateName}] npmos_pki_cert.deleted_on added`);
};

const down = async (knex) => {
	await knex.schema.alterTable("npmos_pki_cert", (table) => {
		table.dropColumn("deleted_on");
	});
};

export { down, up };
