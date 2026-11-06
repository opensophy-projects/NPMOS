import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_acme_server";

/**
 * ACME servers a certificate is issued by (Certificates → ACME, Settings → ACME): a preset (Let's Encrypt, ZeroSSL,
 * Google, SSL.com, the TLS CA of the Russian Federation…) or one of your own (step-ca, an internal CA…). client: the
 * ACME client NPMOS runs for it, certbot or lego (lego registers with an ES256 key and puts the name in the CN of the
 * CSR, which some CAs require). The certificates keep the id of their server in meta.acme_server_id.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_acme_server", (table) => {
		table.increments().primary();
		table.string("name", 100).notNullable();
		table.string("preset", 40).notNullable().defaultTo("custom");
		table.string("directory", 500).notNullable();
		table.string("client", 16).notNullable().defaultTo("certbot");
		table.string("email", 255).notNullable().defaultTo("");
		table.string("eab_kid", 512).notNullable().defaultTo("");
		table.text("eab_hmac_key_enc").nullable();
		table.string("profile", 40).notNullable().defaultTo("");
		table.boolean("tls_verify").notNullable().defaultTo(true);
		table.boolean("is_default").notNullable().defaultTo(false);
		table.dateTime("created_on").notNullable().defaultTo(knex.fn.now());
		table.dateTime("modified_on").notNullable().defaultTo(knex.fn.now());
	});
};

const down = async (knex) => {
	await knex.schema.dropTableIfExists("npmos_acme_server");
};

export { down, up };
