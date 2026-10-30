// WAF settings of proxy hosts and their locations (npmos_waf_host / npmos_waf_location).
// Who may see or edit a proxy host may see or edit its WAF settings (upstream proxy_hosts:*
// permissions, including ownership); a role with waf_policy:manage edits them on the hosts it sees.

import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import errs from "../../lib/error.js";
import { hostObjects } from "./objects/api.js";
import { listObjects } from "./objects/store.js";
import { CONFIDENCES, MODES, scheduleRegenerate } from "./policy.js";
import { scopeHosts } from "../rbac/scope.js";

const DEFAULTS = { enabled: false, mode: "detect-learn", minimum_confidence: "high" };

const toSettings = (row) => ({
	enabled: !!row.enabled,
	mode: row.mode,
	minimum_confidence: row.minimum_confidence,
});

const parseObjects = (value) => (typeof value === "string" ? JSON.parse(value) : value) ?? null;

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
		scopeHosts(query, accessData, "proxy_host", access.token.getUserId(1));
		const result = {};
		for (const row of await query) {
			result[row.proxy_host_id] = { ...toSettings(row), template: parseObjects(row.objects)?.template ?? null };
		}
		return result;
	},

	/**
	 * @param {Access} access
	 * @param {number} id  proxy host id
	 * @returns {Promise<{enabled, mode, minimum_confidence, objects, locations: Array<{path, inherit, enabled, mode, minimum_confidence}>}>}
	 * objects: of the policy (WAF → Policy) the host uses, {template?, threatPreventionPractices?: [id], ...};
	 * null: those of the default policy
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
				? { path: location.path, inherit: false, ...toSettings(own), objects: parseObjects(own.objects) }
				: { path: location.path, inherit: true, ...settings, objects: null };
		});
		return { ...settings, objects: parseObjects(row?.objects), locations };
	},

	/**
	 * @param {Access} access
	 * @param {number} id  proxy host id
	 * @param {{enabled, mode, minimum_confidence, objects?, locations?: Array<{path, inherit?, enabled, mode, minimum_confidence, objects?}>}} data
	 *   objects: {template} or references (see get); absent: unchanged
	 */
	set: async (access, id, data) => {
		// the WAF mode is a security setting: a role with waf_policy:manage changes it on the hosts
		// it sees without managing the hosts (Security Analyst)
		try {
			await access.can("proxy_hosts:update", id);
		} catch {
			await access.can("waf_policy:manage");
			await access.can("proxy_hosts:get", id);
		}
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
		const all = await listObjects();
		const objects = data.objects === undefined ? undefined : hostObjects(data.objects, all);
		// own objects of locations (null: those of the host)
		const locationObjects = new Map(
			(data.locations || []).filter((l) => !l.inherit).map((l) => [l.path, hostObjects(l.objects ?? null, all)]),
		);

		const now = new Date();
		await db().transaction(async (trx) => {
			const values = { ...toSettings(data), modified_on: now };
			if (objects !== undefined) values.objects = objects ? JSON.stringify(objects) : null;
			await trx("npmos_waf_host")
				.insert({ proxy_host_id: id, ...values })
				.onConflict("proxy_host_id")
				.merge();
			if (data.locations) {
				await trx("npmos_waf_location").where({ proxy_host_id: id }).delete();
				const rows = data.locations
					.filter((l) => !l.inherit)
					.map((l) => {
						const own = locationObjects.get(l.path);
						return {
							proxy_host_id: id,
							path: l.path,
							...toSettings(l),
							objects: own ? JSON.stringify(own) : null,
							modified_on: now,
						};
					});
				if (rows.length) {
					await trx("npmos_waf_location").insert(rows);
				}
			}
		});

		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "waf",
			object_id: id,
			meta: { name: parseJson(host.domain_names).join(", "), ...toSettings(data), template: objects?.template },
		});
		scheduleRegenerate();
		return internalWafHosts.get(access, id);
	},
};

export default internalWafHosts;
