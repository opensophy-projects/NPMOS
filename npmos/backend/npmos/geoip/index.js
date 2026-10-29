// Countries of source addresses, offline: a MaxMind DB file. The CrowdSec image brings
// GeoLite2-City (volume crowdsec-data, mounted into npmos); an administrator can upload a newer or
// another database (System → Settings → GeoIP), it is used instead.
import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import { MmdbError, Reader } from "./mmdb.js";

const UPLOADED = process.env.NPMOS_GEOIP_FILE || "/data/npmos/geoip/geoip.mmdb";
const BUNDLED = process.env.NPMOS_GEOIP_BUNDLED || "/var/lib/crowdsec/data/GeoLite2-City.mmdb";
export const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;
/** a changed file on disk is noticed within this time */
const RECHECK_MS = 5 * 60 * 1000;

let current = null; // {reader, file, source, mtime}
let checked = 0;
let loading = null;

const describe = (c) =>
	c
		? {
				source: c.source,
				type: String(c.reader.metadata.database_type || ""),
				built: c.reader.metadata.build_epoch
					? new Date(c.reader.metadata.build_epoch * 1000).toISOString()
					: null,
				size: c.size,
			}
		: null;

const open = async () => {
	for (const [file, source] of [
		[UPLOADED, "uploaded"],
		[BUNDLED, "crowdsec"],
	]) {
		const st = await stat(file).catch(() => null);
		if (!st?.size) continue;
		if (current?.file === file && current.mtime === st.mtimeMs) return current;
		try {
			const reader = new Reader(await readFile(file));
			logger.info(`NPMOS GeoIP: ${file} (${reader.metadata.database_type})`);
			return { reader, file, source, mtime: st.mtimeMs, size: st.size };
		} catch (err) {
			logger.warn(`NPMOS GeoIP: ${file} is not usable: ${err.message}`);
		}
	}
	return null;
};

/** the database, reloaded when the file changed */
const database = async () => {
	if (Date.now() - checked < RECHECK_MS) return current;
	if (!loading) {
		loading = open()
			.then((c) => {
				current = c;
				checked = Date.now();
			})
			.finally(() => {
				loading = null;
			});
	}
	await loading;
	return current;
};

/** name of the country of a record (English, as the agent writes it), "" when unknown */
const countryOf = (record) => {
	const c = record?.country || record?.registered_country;
	return String(c?.names?.en || c?.iso_code || "").slice(0, 64);
};

/**
 * Fills source_country of events that have none (in place).
 * @param {object[]} events  rows of npmos_security_event
 */
export const enrich = async (events) => {
	if (!events.some((e) => e.source_ip && !e.source_country)) return events;
	let db;
	try {
		db = await database();
	} catch {
		return events;
	}
	if (!db) return events;
	for (const e of events) {
		if (!e.source_ip || e.source_country) continue;
		try {
			e.source_country = countryOf(db.reader.get(e.source_ip));
		} catch {
			// a broken record: no country
		}
	}
	return events;
};

// loaded on use: events/store.js imports this module, the audit log needs the whole backend
const audit = async (access, action, name) => {
	const { default: internalAuditLog } = await import("../../internal/audit-log.js");
	await internalAuditLog.add(access, { action, object_type: "setting", meta: { name } });
};

const internalGeoip = {
	/** @param {Access} access */
	status: async (access) => {
		await access.can("settings:view");
		checked = 0;
		const c = await database();
		return { database: describe(c), uploaded: c?.source === "uploaded" };
	},

	/**
	 * @param {Access} access
	 * @param {Buffer|null} body  the .mmdb file
	 */
	upload: async (access, body) => {
		await access.can("settings:manage");
		if (!body?.length) throw new errs.ValidationError("Empty file");
		if (body.length > MAX_UPLOAD_BYTES) throw new errs.ValidationError("The database is larger than 200 MB");
		let reader;
		try {
			reader = new Reader(body);
			reader.get("8.8.8.8");
		} catch (err) {
			throw new errs.ValidationError(
				err instanceof MmdbError ? err.message : `Not a MaxMind DB file: ${err.message}`,
			);
		}
		await mkdir(path.dirname(UPLOADED), { recursive: true });
		await writeFile(`${UPLOADED}.tmp`, body, { mode: 0o644 });
		await rename(`${UPLOADED}.tmp`, UPLOADED);
		checked = 0;
		const c = await database();
		await audit(access, "updated", `GeoIP database ${reader.metadata.database_type}`);
		return { database: describe(c), uploaded: true };
	},

	/** @param {Access} access */
	remove: async (access) => {
		await access.can("settings:manage");
		await rm(UPLOADED, { force: true });
		checked = 0;
		const c = await database();
		await audit(access, "deleted", "GeoIP database");
		return { database: describe(c), uploaded: false };
	},
};

export default internalGeoip;
