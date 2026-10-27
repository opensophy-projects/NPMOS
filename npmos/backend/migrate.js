import db from "./db.js";
import { migrate as logger } from "./logger.js";

const migrateUp = async () => {
	const version = await db().migrate.currentVersion();
	logger.info("Current database version:", version);
	return await db().migrate.latest({
		tableName: "migrations",
		// NPMOS: our tables (npmos_*) are created by npmos/migrations
		directory: ["migrations", "npmos/migrations"],
	});
};

export { migrateUp };
