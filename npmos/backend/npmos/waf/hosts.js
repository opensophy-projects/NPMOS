// WAF settings of proxy hosts and their locations (npmos_waf_host / npmos_waf_location).
// Who may see or edit a proxy host may see or edit its WAF settings (upstream proxy_hosts:*
// permissions, including ownership).
import internalAuditLog from "../../internal/audit-log.js";
import db from "../../db.js";
import errs from "../../lib/error.js";
import { CONFIDENCES, MODES, scheduleRegenerate } from "./policy.js";

const DEFAULTS = { enabled: false, mode: "detect-learn", minimum_confidence: "high" };

const toSettings = (row) => ({
	enabled: !!row.enabled,
	mode: row.mode,
	minimum_confidence: row.minimum_confidence,
});

const parseJson = (value) => (typeof value === "string" ? JSON.parse(value) : value) || [];

const getProxyHost = async (id) => {
	const host = await db()("proxy_host")
		.select("id", "domain_names", "locations")
		.where({ id, is_deleted: 0 })
		.first();
	if (!host) {
		throw new errs.ItemNotFoundError(id);
	}
	return host;
};

const validate = (settings, what) => {
	if (typeof settings?.enabled !== "boolean") {
		throw new errs.ValidationError(`${what}: enabled must be a boolean`);
	}
	if (!MODES.includes(settings.mode)) {
		throw new errs.ValidationError(`${what}: mode must be one of ${MODES.join(", ")}`);
	}
	if (!CONFIDENCES.includes(settings.minimum_confidence)) {
		throw new errs.ValidationError(`${what}: minimum_confidence must be one of ${CONFIDENCES.join(", ")}`);
	}
};

const internalWafHosts = {
	/**
	 * WAF settings of all proxy hosts the user can see: {<proxy host id>: settings}
	 * (for badges in the host list). Hosts without settings are not listed (= defaults).
	 * @param {Access} access
	 */
	list: async (access) => {
		const accessData = await access.can("proxy_hosts:list");
		const query = db()("npmos_waf_host")
			.join("proxy_host", "proxy_host.id", "npmos_waf_host.proxy_host_id")
			.where("proxy_host.is_deleted", 0)
			.select("npmos_waf_host.*");
		if (accessData.permission_visibility !== "all") {
			query.where("proxy_host.owner_user_id", access.token.getUserId(1));
		}
		const result = {};
		for (const row of await query) {
			result[row.proxy_host_id] = toSettings(row);
		}
		return result;
	},

	/**
	 * @param {Access} access
	 * @param {number} id  proxy host id
	 * @returns {Promise<{enabled, mode, minimum_confidence, locations: Array<{path, inherit, enabled, mode, minimum_confidence}>}>}
	 */
	get: async (access, id) => {
		await access.can("proxy_hosts:get", id);
		const host = await getProxyHost(id);
		const row = await db()("npmos_waf_host").where({ proxy_host_id: id }).first();
		const settings = row ? toSettings(row) : { ...DEFAULTS };
		const locationRows = await db()("npmos_waf_location").where({ proxy_host_id: id });
		// every location of the host, in its order; a location without a row inherits the host
		const locations = parseJson(host.locations).map((location) => {
			const own = locationRows.find((l) => l.path === location.path);
			return own
				? { path: location.path, inherit: false, ...toSettings(own) }
				: { path: location.path, inherit: true, ...settings };
		});
		return { ...settings, locations };
	},

	/**
	 * @param {Access} access
	 * @param {number} id  proxy host id
	 * @param {{enabled, mode, minimum_confidence, locations?: Array<{path, inherit?, enabled, mode, minimum_confidence}>}} data
	 */
	set: async (access, id, data) => {
		await access.can("proxy_hosts:update", id);
		const host = await getProxyHost(id);
		validate(data, "WAF");
		const paths = parseJson(host.locations).map((l) => l.path);
		for (const location of data.locations || []) {
			if (!paths.includes(location.path)) {
				throw new errs.ValidationError(`WAF: the host has no location ${location.path}`);
			}
			if (!location.inherit) {
				validate(location, `WAF of location ${location.path}`);
			}
		}

		const now = new Date();
		await db().transaction(async (trx) => {
			await trx("npmos_waf_host")
				.insert({ proxy_host_id: id, ...toSettings(data), modified_on: now })
				.onConflict("proxy_host_id")
				.merge();
			if (data.locations) {
				await trx("npmos_waf_location").where({ proxy_host_id: id }).delete();
				const rows = data.locations
					.filter((l) => !l.inherit)
					.map((l) => ({ proxy_host_id: id, path: l.path, ...toSettings(l), modified_on: now }));
				if (rows.length) {
					await trx("npmos_waf_location").insert(rows);
				}
			}
		});

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "waf",
			object_id: id,
			meta: { name: parseJson(host.domain_names).join(", "), ...toSettings(data) },
		});
		scheduleRegenerate();
		return internalWafHosts.get(access, id);
	},
};

export default internalWafHosts;
