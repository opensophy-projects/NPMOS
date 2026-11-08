import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_request_client";

/**
 * Who made a request of the log (events/client.js): a person ("human"), a bot that says so ("bot") or a scanner
 * ("scanner"). Rows of before: bots by their device, scanners by a refusal (403, 444) or the bare IP as the Host.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.alterTable("nginxions_request_log", (table) => {
		table.string("client", 8).notNull().defaultTo("human");
	});
	await knex("nginxions_request_log").where("device", "bot").update({ client: "bot" });
	await knex("nginxions_request_log")
		.where((q) =>
			q
				.whereIn("status", [403, 444])
				.orWhere("user_agent", "")
				.orWhere("host", "")
				.orWhere("host", "_")
				.orWhereRaw("host ~ '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'"),
		)
		.update({ client: "scanner" })
		.catch(() => {});
	logger.info(`[${migrateName}] nginxions_request_log.client added`);
};

const down = async (knex) => {
	await knex.schema.alterTable("nginxions_request_log", (table) => {
		table.dropColumn("client");
	});
};

export { down, up };
