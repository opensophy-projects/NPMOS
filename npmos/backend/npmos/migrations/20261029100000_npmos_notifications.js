import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_notifications";

/**
 * Notifications (docs/ROADMAP.md, phase 4; ADR-11): channels (email, webhook, Telegram), rules
 * that send to them, and the log of what was sent. Secrets of channels are stored encrypted
 * (npmos/secrets.js).
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("npmos_notification_channel", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("name", 100).notNull();
		// email | webhook | telegram
		table.string("type", 16).notNull();
		table.boolean("enabled").notNull().defaultTo(true);
		table.json("config").notNull();
	});
	await knex.schema.createTable("npmos_notification_rule", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		table.string("name", 100).notNull();
		// attack_spike | agent_down | policy_error | service_down | cert_expiry | host_problem
		table.string("type", 32).notNull();
		table.boolean("enabled").notNull().defaultTo(true);
		table.json("params").notNull();
		table.json("channel_ids").notNull();
		// remind while still active, minutes (0: once)
		table.integer("repeat_minutes").notNull().defaultTo(0);
		table.boolean("notify_resolved").notNull().defaultTo(true);
		// alerts active now: {key: ISO time of the last message}
		table.json("state").notNull();
	});
	await knex.schema.createTable("npmos_notification_log", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.integer("rule_id").unsigned().nullable();
		table.integer("channel_id").unsigned().nullable();
		// firing | resolved | test
		table.string("status", 16).notNull();
		table.string("title", 255).notNull();
		table.boolean("ok").notNull();
		table.string("error", 500).notNull().defaultTo("");
		table.index(["created_on"]);
	});
	logger.info(`[${migrateName}] npmos_notification_channel, npmos_notification_rule, npmos_notification_log created`);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_notification_log");
	await knex.schema.dropTable("npmos_notification_rule");
	await knex.schema.dropTable("npmos_notification_channel");
};

export { down, up };
