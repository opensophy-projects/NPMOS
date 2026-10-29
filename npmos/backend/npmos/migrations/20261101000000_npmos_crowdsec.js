import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_crowdsec";

/**
 * CrowdSec from the GUI (docs/ROADMAP.md, phase 7; docs/adr/0010-crowdsec.md): local blocklists
 * (a file or a URL, also the export of another NPMOS node) and the hosts the bouncer of NPMOS
 * leaves alone. Everything else of CrowdSec is in the npmos_setting "crowdsec" and in CrowdSec.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_crowdsec_blocklist", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("node_id", 64).notNull().defaultTo("local");
		table.string("name", 64).notNull().unique();
		table.boolean("enabled").notNull().defaultTo(true);
		// file | url
		table.string("source", 16).notNull();
		table.string("url", 1000).notNull().defaultTo("");
		// bearer token for the URL (another NPMOS node), encrypted
		table.text("token_enc").nullable();
		// do not verify the TLS certificate of the URL (another node with a self-signed certificate)
		table.boolean("insecure").notNull().defaultTo(false);
		// file: the uploaded list (one IP or CIDR per line)
		table.text("content").nullable();
		// ban | captcha
		table.string("decision", 16).notNull().defaultTo("ban");
		table.string("duration", 16).notNull().defaultTo("24h");
		// url: minutes between downloads, 0 = only by hand
		table.integer("refresh_minutes").notNull().defaultTo(0);
		table.dateTime("synced_on").nullable();
		table.integer("count").notNull().defaultTo(0);
		table.string("error", 1000).notNull().defaultTo("");
	});
	await knex.schema.createTable("npmos_crowdsec_host", (table) => {
		// proxy_host | redirection_host | dead_host
		table.string("host_type", 32).notNull();
		table.integer("host_id").unsigned().notNull();
		table.primary(["host_type", "host_id"]);
		table.dateTime("modified_on").notNull();
		// false: the bouncer of NPMOS does not check requests to this host
		table.boolean("bouncer").notNull().defaultTo(true);
	});
	logger.info(`[${migrateName}] npmos_crowdsec_blocklist, npmos_crowdsec_host created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_crowdsec_host");
	await knex.schema.dropTable("npmos_crowdsec_blocklist");
};

export { down, up };
