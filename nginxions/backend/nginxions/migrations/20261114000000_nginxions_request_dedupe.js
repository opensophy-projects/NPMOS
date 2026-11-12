import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_request_dedupe";

const isPostgres = (knex) => ["pg", "postgres", "postgresql"].includes(knex.client.config.client);

/**
 * The ingest of the agent's log dropped the cursor of the request log (nginx:requests) every few seconds, so the
 * request log was read again from its start over and over: each request became hundreds of rows. Copies (same
 * time to the millisecond, address, request, answer and sizes) are removed, and the hourly counters of the hours
 * the log covers are counted again from it.
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!isPostgres(knex)) return;
	const removed = await knex.raw(`
		DELETE FROM nginxions_request_log l USING (
			SELECT time, id FROM (
				SELECT time, id, row_number() OVER (
					PARTITION BY time, node_id, host, port, ip, method, path, status, bytes, request_bytes, duration_ms,
						upstream_addr, user_agent
					ORDER BY id
				) AS n
				FROM nginxions_request_log
			) d WHERE d.n > 1
		) c
		WHERE l.time = c.time AND l.id = c.id`);
	// the first hour of the log may hold only a part of its requests: counted again from the next one
	const { rows } = await knex.raw(
		"SELECT date_trunc('hour', min(time)) + interval '1 hour' AS start FROM nginxions_request_log",
	);
	const start = rows[0]?.start;
	if (start) {
		await knex("nginxions_request_hourly").where("hour", ">=", start).delete();
		await knex.raw(
			`INSERT INTO nginxions_request_hourly (node_id, hour, host, requests, s2xx, s3xx, s4xx, s5xx, blocked, bytes)
			SELECT node_id, date_trunc('hour', time), host, COUNT(*),
				COUNT(*) FILTER (WHERE status BETWEEN 200 AND 299), COUNT(*) FILTER (WHERE status BETWEEN 300 AND 399),
				COUNT(*) FILTER (WHERE status BETWEEN 400 AND 499), COUNT(*) FILTER (WHERE status BETWEEN 500 AND 599),
				COUNT(*) FILTER (WHERE mitigated), COALESCE(SUM(bytes), 0)
			FROM nginxions_request_log WHERE time >= ? GROUP BY 1, 2, 3`,
			[start],
		);
		await knex("nginxions_request_country_hourly").where("hour", ">=", start).delete();
		await knex.raw(
			`INSERT INTO nginxions_request_country_hourly (node_id, hour, host, country, requests, mitigated, bytes)
			SELECT node_id, date_trunc('hour', time), host, country, COUNT(*), COUNT(*) FILTER (WHERE mitigated),
				COALESCE(SUM(bytes), 0)
			FROM nginxions_request_log WHERE time >= ? GROUP BY 1, 2, 3, 4`,
			[start],
		);
	}
	logger.info(`[${migrateName}] ${removed.rowCount ?? 0} copied request(s) removed, hourly counters counted again`);
};

const down = async () => {};

export { down, up };
