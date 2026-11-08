import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_request_log";

const isPostgres = (knex) => ["pg", "postgres", "postgresql"].includes(knex.client.config.client);

/**
 * Every request of the hosts (Analytics → Requests and the top lists, the map, percentiles), from the JSON log of
 * nginx (nginxions-requests.log). Kept for a few days (events.retention.requestDays): on Postgres the table is
 * partitioned by day like nginxions_security_event and old days are dropped. The path is stored without its query.
 * nginxions_request_country_hourly: requests per country and hour for periods longer than the log is kept.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	const columns = `
		node_id varchar(64) NOT NULL DEFAULT 'local',
		time timestamptz NOT NULL,
		host varchar(255) NOT NULL DEFAULT '',
		port integer,
		ip varchar(64) NOT NULL DEFAULT '',
		country varchar(2) NOT NULL DEFAULT '',
		method varchar(16) NOT NULL DEFAULT '',
		path text NOT NULL DEFAULT '',
		status integer NOT NULL DEFAULT 0,
		bytes bigint NOT NULL DEFAULT 0,
		request_bytes bigint NOT NULL DEFAULT 0,
		duration_ms integer NOT NULL DEFAULT 0,
		upstream_ms integer,
		connect_ms integer,
		upstream_status integer,
		upstream_addr varchar(255) NOT NULL DEFAULT '',
		cache varchar(16) NOT NULL DEFAULT '',
		protocol varchar(16) NOT NULL DEFAULT '',
		tls varchar(16) NOT NULL DEFAULT '',
		content_type varchar(100) NOT NULL DEFAULT '',
		referer_host varchar(255) NOT NULL DEFAULT '',
		user_agent varchar(512) NOT NULL DEFAULT '',
		browser varchar(32) NOT NULL DEFAULT '',
		os varchar(32) NOT NULL DEFAULT '',
		device varchar(16) NOT NULL DEFAULT '',
		pageview boolean NOT NULL DEFAULT false,
		visit boolean NOT NULL DEFAULT false,
		mitigated boolean NOT NULL DEFAULT false`;
	if (isPostgres(knex)) {
		// nosemgrep: nginxions-knex-raw-interpolation -- the columns are a constant of this migration
		await knex.raw(
			`CREATE TABLE nginxions_request_log (id bigserial NOT NULL, ${columns}, PRIMARY KEY (time, id)) PARTITION BY RANGE (time)`,
		);
	} else {
		await knex.schema.createTable("nginxions_request_log", (table) => {
			table.bigIncrements("id").primary();
			table.string("node_id", 64).notNull().defaultTo("local");
			table.dateTime("time").notNull();
			for (const [name, length] of [
				["host", 255],
				["ip", 64],
				["country", 2],
				["method", 16],
				["upstream_addr", 255],
				["cache", 16],
				["protocol", 16],
				["tls", 16],
				["content_type", 100],
				["referer_host", 255],
				["user_agent", 512],
				["browser", 32],
				["os", 32],
				["device", 16],
			]) {
				table.string(name, length).notNull().defaultTo("");
			}
			table.text("path").notNull();
			table.integer("port").nullable();
			table.integer("status").notNull().defaultTo(0);
			table.bigInteger("bytes").notNull().defaultTo(0);
			table.bigInteger("request_bytes").notNull().defaultTo(0);
			table.integer("duration_ms").notNull().defaultTo(0);
			table.integer("upstream_ms").nullable();
			table.integer("connect_ms").nullable();
			table.integer("upstream_status").nullable();
			for (const name of ["pageview", "visit", "mitigated"]) table.boolean(name).notNull().defaultTo(false);
		});
	}
	await knex.schema.alterTable("nginxions_request_log", (table) => {
		table.index(["time"]);
		table.index(["host", "time"]);
		table.index(["ip", "time"]);
	});
	await knex.schema.createTable("nginxions_request_country_hourly", (table) => {
		table.string("node_id", 64).notNull().defaultTo("local");
		table.dateTime("hour").notNull();
		table.string("host", 255).notNull();
		table.string("country", 2).notNull();
		table.bigInteger("requests").notNull().defaultTo(0);
		table.bigInteger("mitigated").notNull().defaultTo(0);
		table.bigInteger("bytes").notNull().defaultTo(0);
		table.primary(["hour", "node_id", "host", "country"]);
	});
	logger.info(`[${migrateName}] nginxions_request_log, nginxions_request_country_hourly created`);
};

const down = async (knex) => {
	await knex.schema.dropTableIfExists("nginxions_request_country_hourly");
	await knex.schema.dropTableIfExists("nginxions_request_log");
};

export { down, up };
