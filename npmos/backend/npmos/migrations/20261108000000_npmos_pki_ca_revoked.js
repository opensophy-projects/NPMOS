import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_pki_ca_revoked";

/**
 * Revocation of an intermediate CA (trust domain): the CRL and OCSP of its root list it, every certificate it issued
 * is revoked with it, and it issues nothing more.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("npmos_pki_ca", (table) => {
		table.dateTime("revoked_on").nullable();
		table.string("revoke_reason", 32).nullable();
	});
};

const down = async (knex) => {
	await knex.schema.alterTable("npmos_pki_ca", (table) => {
		table.dropColumn("revoked_on");
		table.dropColumn("revoke_reason");
	});
};

export { down, up };
