import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_events";

const isPostgres = (knex) => ["pg", "postgres", "postgresql"].includes(knex.client.config.client);

/**
 * Security events of the open-appsec agent and their aggregates (docs/ROADMAP.md, phase 4).
 * On Postgres (the NPMOS stack) npmos_security_event is partitioned by day: old days are dropped
 * as whole partitions (npmos/events/store.js creates and drops them). Other databases of NPMplus
 * get a plain table, old rows are deleted.
 * node_id: the NPMOS node or agent the row comes from (ADR-10), "local" for now.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (isPostgres(knex)) {
		await knex.raw(`
			CREATE TABLE npmos_security_event (
				id bigserial NOT NULL,
				node_id varchar(64) NOT NULL DEFAULT 'local',
				time timestamptz NOT NULL,
				kind varchar(16) NOT NULL,
				name varchar(200) NOT NULL DEFAULT '',
				severity varchar(32) NOT NULL DEFAULT '',
				priority varchar(32) NOT NULL DEFAULT '',
				confidence varchar(32) NOT NULL DEFAULT '',
				action varchar(32) NOT NULL DEFAULT '',
				incident_type varchar(100) NOT NULL DEFAULT '',
				source_ip varchar(64) NOT NULL DEFAULT '',
				source_port integer,
				proxy_ip varchar(255) NOT NULL DEFAULT '',
				source_country varchar(64) NOT NULL DEFAULT '',
				host varchar(255) NOT NULL DEFAULT '',
				asset varchar(255) NOT NULL DEFAULT '',
				method varchar(16) NOT NULL DEFAULT '',
				uri text NOT NULL DEFAULT '',
				query text NOT NULL DEFAULT '',
				response_code integer,
				location varchar(64) NOT NULL DEFAULT '',
				parameter text NOT NULL DEFAULT '',
				sample text NOT NULL DEFAULT '',
				indicators text NOT NULL DEFAULT '',
				score real,
				rule varchar(255) NOT NULL DEFAULT '',
				practice varchar(255) NOT NULL DEFAULT '',
				override varchar(32) NOT NULL DEFAULT '',
				service varchar(100) NOT NULL DEFAULT '',
				raw jsonb NOT NULL,
				PRIMARY KEY (time, id)
			) PARTITION BY RANGE (time)
		`);
	} else {
		await knex.schema.createTable("npmos_security_event", (table) => {
			table.bigIncrements("id").primary();
			table.string("node_id", 64).notNull().defaultTo("local");
			table.dateTime("time").notNull();
			table.string("kind", 16).notNull();
			for (const [name, length] of [
				["name", 200],
				["severity", 32],
				["priority", 32],
				["confidence", 32],
				["action", 32],
				["incident_type", 100],
				["source_ip", 64],
				["proxy_ip", 255],
				["source_country", 64],
				["host", 255],
				["asset", 255],
				["method", 16],
				["location", 64],
				["rule", 255],
				["practice", 255],
				["override", 32],
				["service", 100],
			]) {
				table.string(name, length).notNull().defaultTo("");
			}
			for (const name of ["uri", "query", "parameter", "sample", "indicators"]) {
				table.text(name).notNull();
			}
			table.integer("source_port").nullable();
			table.integer("response_code").nullable();
			table.float("score").nullable();
			table.json("raw").notNull();
		});
	}
	await knex.schema.alterTable("npmos_security_event", (table) => {
		table.index(["time"]);
		table.index(["host", "time"]);
		table.index(["source_ip", "time"]);
		table.index(["kind", "severity", "time"]);
	});

	// events per hour: kept longer than the events (analytics over months)
	await knex.schema.createTable("npmos_event_hourly", (table) => {
		table.string("node_id", 64).notNull().defaultTo("local");
		table.dateTime("hour").notNull();
		table.string("host", 255).notNull();
		table.string("kind", 16).notNull();
		table.string("action", 32).notNull();
		table.string("severity", 32).notNull();
		table.string("incident_type", 100).notNull();
		table.integer("events").notNull().defaultTo(0);
		table.primary(["hour", "node_id", "host", "kind", "action", "severity", "incident_type"]);
	});
	// telemetry of the agent ("WAAP telemetry"): requests per asset and hour
	await knex.schema.createTable("npmos_traffic_hourly", (table) => {
		table.string("node_id", 64).notNull().defaultTo("local");
		table.dateTime("hour").notNull();
		table.string("asset", 255).notNull();
		table.bigInteger("requests").notNull().defaultTo(0);
		table.bigInteger("sources").notNull().defaultTo(0);
		table.bigInteger("blocked").notNull().defaultTo(0);
		table.bigInteger("threat_low").notNull().defaultTo(0);
		table.bigInteger("threat_medium").notNull().defaultTo(0);
		table.bigInteger("threat_high").notNull().defaultTo(0);
		table.primary(["hour", "node_id", "asset"]);
	});
	// how far each log file of the agent has been read
	await knex.schema.createTable("npmos_log_cursor", (table) => {
		table.string("key", 64).primary();
		table.string("file", 255).notNull();
		table.bigInteger("offset").notNull();
		table.string("head", 64).notNull();
		table.integer("head_length").notNull();
		table.dateTime("modified_on").notNull();
	});
	logger.info(
		`[${migrateName}] npmos_security_event, npmos_event_hourly, npmos_traffic_hourly, npmos_log_cursor created`,
	);
};

const down = async (knex) => {
	await knex.schema.dropTable("npmos_log_cursor");
	await knex.schema.dropTable("npmos_traffic_hourly");
	await knex.schema.dropTable("npmos_event_hourly");
	await knex.schema.dropTable("npmos_security_event");
};

export { down, up };
