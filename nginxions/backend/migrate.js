import db from "./db.js";
import { migrate as logger } from "./logger.js";
// NginxionS: a database of the time the project was called NPMOS gets the new names first
import { renameFromNpmos } from "./nginxions/rename.js";

const migrateUp = async () => {
	await renameFromNpmos(db());
	const version = await db().migrate.currentVersion();
	logger.info("Current database version:", version);
	return await db().migrate.latest({
		tableName: "migrations",
		// NginxionS: our tables (nginxions_*) are created by nginxions/migrations
		directory: ["migrations", "nginxions/migrations"],
	});
};

export { migrateUp };
