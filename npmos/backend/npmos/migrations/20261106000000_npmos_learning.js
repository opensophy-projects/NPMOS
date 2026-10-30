import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_learning";

/**
 * Labels of learning (docs/ROADMAP.md, phase 8): what an administrator decided about a group of events or a
 * tuning suggestion, what it applies to, its instant effects and who decided. The labels are the local
 * dataset: the group (features) is kept with the label, undone labels stay with the time they were undone.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_learning_label", (table) => {
		table.increments("id").primary();
		table.string("node_id", 64).notNull().defaultTo("local");
		table.dateTime("created_on").notNull();
		table.integer("user_id").notNull().defaultTo(0);
		// group: a group of the queue (events of NPMOS); tuning: a suggestion of the tuning service
		table.string("origin", 16).notNull();
		table.string("group_key", 64).notNull().defaultTo("");
		table.string("tuning_id", 128).notNull().defaultTo("");
		table.integer("proxy_host_id");
		table.string("host", 255).notNull().defaultTo("");
		table.string("decision", 16).notNull();
		table.text("scopes").notNull();
		// the group as it was labelled: uri, parameter, indicators, counts, score, sample, event id
		table.text("features").notNull();
		table.text("note").notNull();
		table.boolean("exception").notNull().defaultTo(false);
		table.dateTime("expires_on");
		// sources banned in CrowdSec, and for how long
		table.text("banned").notNull();
		table.string("ban_duration", 16).notNull().defaultTo("");
		// written to decisions.data (or to the tuning service), the last error otherwise
		table.dateTime("synced_on");
		table.text("sync_error").notNull();
		table.dateTime("undone_on");
		table.integer("undone_by");
		table.index(["group_key"]);
		table.index(["proxy_host_id"]);
		table.index(["created_on"]);
	});
	logger.info(`[${migrateName}] npmos_learning_label created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_learning_label");
};

export { down, up };
