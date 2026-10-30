import { migrate as logger } from "../../logger.js";

const migrateName = "npmos_event_score";

/**
 * waapFinalScore of events logged by agents that write it multiplied by 100 (1000 for 10): back to the scale
 * 0..10 of the agent, as the ingest stores it now (events/normalize.js, scoreOf).
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	const n = await knex("npmos_security_event")
		.where("score", ">", 10)
		.update({ score: knex.raw("round(score) / 100") });
	logger.info(`[${migrateName}] ${n} score(s) rescaled`);
};

const down = async () => {};

export { down, up };
