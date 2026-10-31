import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_pki_auto_renew";

/**
 * Short-lived certificates renewed by NPMOS: auto_renew "link" (people: NPMOS issues the next certificate before
 * the end and sends a one-time link, the .p12 keeps the password chosen at issue) or "token" (services: the client
 * renews itself with a token, POST /api/npmos/pki/public/renew). renew_hours: validity of each renewal.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("npmos_pki_cert", (table) => {
		table.string("auto_renew", 8).notNullable().defaultTo("");
		table.integer("renew_hours").unsigned().nullable();
		table.string("renew_token_hash", 64).nullable().index();
		table.text("renew_password_enc").nullable();
		// the one-time link of an automatic renewal, for the notification (pki_reissued) until it is used
		table.text("renew_link_enc").nullable();
	});
};

const down = async (knex) => {
	await knex.schema.alterTable("npmos_pki_cert", (table) => {
		table.dropColumn("auto_renew");
		table.dropColumn("renew_hours");
		table.dropColumn("renew_token_hash");
		table.dropColumn("renew_password_enc");
		table.dropColumn("renew_link_enc");
	});
};

export { down, up };
