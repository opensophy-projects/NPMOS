import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_request_refused";

const isPostgres = (knex) => ["pg", "postgres", "postgresql"].includes(knex.client.config.client);

/**
 * "Refused" (mitigated) is every request that never reached the server behind the host: a refusal of the
 * protection, or a 4xx nginx answered itself (events/requests.js refused). Rows of the log kept so far and the
 * blocked counters of their hours follow the new meaning.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex("nginxions_request_log")
		.where("mitigated", false)
		.whereBetween("status", [400, 499])
		.whereNull("upstream_status")
		.update({ mitigated: true });
	if (isPostgres(knex)) {
		await knex.raw(`
			UPDATE nginxions_request_hourly h SET blocked = s.blocked
			FROM (
				SELECT node_id, host, date_trunc('hour', time) AS hour, COUNT(*) FILTER (WHERE mitigated) AS blocked
				FROM nginxions_request_log GROUP BY 1, 2, 3
			) s
			WHERE h.node_id = s.node_id AND h.host = s.host AND h.hour = s.hour`);
	}
	logger.info(`[${migrateName}] refused requests of the log updated`);
};

const down = async () => {};

export { down, up };
