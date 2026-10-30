import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_pki";

/**
 * PKI and mTLS (docs/ROADMAP.md, phase 6; docs/adr/0009-pki-mtls.md): certificate authorities
 * (own root and intermediate, external ones for verification only), issued certificates, one-time
 * download links and the mTLS settings of hosts and streams. Private keys are stored encrypted
 * (npmos/secrets.js); the key of an issued certificate only when asked to.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_pki_ca", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("node_id", 64).notNull().defaultTo("local");
		table.string("name", 100).notNull().unique();
		// root | intermediate | external
		table.string("kind", 16).notNull();
		table.integer("parent_id").unsigned().nullable();
		// external CAs uploaded in NPMplus (certificate with provider mtls)
		table.integer("upstream_certificate_id").unsigned().nullable();
		table.json("subject").notNull();
		// RFC 2253, as nginx prints $ssl_client_i_dn
		table.string("subject_dn", 1000).notNull();
		table.string("serial", 64).notNull();
		table.dateTime("not_before").notNull();
		table.dateTime("not_after").notNull();
		table.string("fingerprint", 128).notNull();
		table.string("key_type", 32).notNull();
		// own CAs: their certificate; external: every certificate of the bundle
		table.text("cert_pem").notNull();
		table.text("key_enc").nullable();
		// own CAs: the last generated CRL; external: an uploaded one (optional)
		table.text("crl_pem").nullable();
		table.integer("crl_number").notNull().defaultTo(0);
		table.dateTime("crl_updated_on").nullable();
		table.dateTime("crl_next_update").nullable();
		table.json("meta").notNull();
	});
	await knex.schema.createTable("npmos_pki_cert", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("node_id", 64).notNull().defaultTo("local");
		table.integer("ca_id").unsigned().notNull();
		// client | server
		table.string("profile", 16).notNull();
		table.string("serial", 64).notNull().unique();
		table.string("common_name", 255).notNull();
		table.json("subject").notNull();
		table.json("sans").notNull();
		table.dateTime("not_before").notNull();
		table.dateTime("not_after").notNull();
		table.string("fingerprint", 128).notNull();
		table.string("key_type", 32).notNull();
		table.text("cert_pem").notNull();
		table.text("key_enc").nullable();
		table.dateTime("revoked_on").nullable();
		table.string("revoke_reason", 32).nullable();
		// the certificate that replaced this one (renewal)
		table.integer("replaced_by").unsigned().nullable();
		table.string("template", 100).notNull().defaultTo("");
		table.string("notes", 500).notNull().defaultTo("");
		table.integer("owner_user_id").unsigned().notNull().defaultTo(0);
		// server certificates installed as a custom certificate of NPMplus
		table.integer("certificate_id").unsigned().nullable();
		table.index(["ca_id"]);
		table.index(["not_after"]);
	});
	await knex.schema.createTable("npmos_pki_link", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("expires_on").notNull();
		table.dateTime("used_on").nullable();
		table.integer("cert_id").unsigned().notNull();
		table.integer("created_by").unsigned().notNull().defaultTo(0);
		// sha256 of the token in the link
		table.string("token_hash", 64).notNull().unique();
		table.string("filename", 255).notNull();
		table.text("payload_enc").nullable();
	});
	await knex.schema.createTable("npmos_mtls_host", (table) => {
		// proxy_host | stream
		table.string("host_type", 16).notNull();
		table.integer("host_id").unsigned().notNull();
		table.primary(["host_type", "host_id"]);
		table.dateTime("modified_on").notNull();
		table.boolean("enabled").notNull().defaultTo(false);
		table.json("ca_ids").notNull();
		// on | optional
		table.string("mode", 16).notNull().defaultTo("on");
		table.integer("depth").notNull().defaultTo(2);
		// send the names of the CAs to clients (ssl_client_certificate) or not (ssl_trusted_certificate)
		table.boolean("send_ca_names").notNull().defaultTo(true);
		// [{field, op, value}]: all must match
		table.json("rules").notNull();
		// optional mode: paths of locations that require a certificate ("/" is the host itself)
		table.json("required_paths").notNull();
		// X-Client-* headers to the upstream
		table.boolean("headers").notNull().defaultTo(true);
	});
	logger.info(`[${migrateName}] npmos_pki_ca, npmos_pki_cert, npmos_pki_link, npmos_mtls_host created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_mtls_host");
	await knex.schema.dropTable("npmos_pki_link");
	await knex.schema.dropTable("npmos_pki_cert");
	await knex.schema.dropTable("npmos_pki_ca");
};

export { down, up };
