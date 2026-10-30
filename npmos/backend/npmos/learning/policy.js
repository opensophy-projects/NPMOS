// Exceptions of learning in the policy (instant effect of a label): read by the generator of the policy
// (waf/objects/store.js). Its own file so that the generator does not import the rest of learning.
import db from "../../db.js";
import { exceptionActive, exceptionOf } from "./model.js";

export const LABEL_TABLE = "npmos_learning_label";

export const parseLabel = (row) => ({
	...row,
	scopes: typeof row.scopes === "string" ? JSON.parse(row.scopes || "[]") : (row.scopes ?? []),
	features: typeof row.features === "string" ? JSON.parse(row.features || "{}") : (row.features ?? {}),
	banned: typeof row.banned === "string" ? JSON.parse(row.banned || "[]") : (row.banned ?? []),
	exception: !!row.exception,
});

/**
 * Exceptions of the labels in force, by proxy host.
 * @param {Date} [now]
 * @returns {Promise<Map<number, Array<{name, action, condition}>>>}
 */
export const learningExceptions = async (now = new Date()) => {
	const rows = await db()(LABEL_TABLE)
		.where("exception", true)
		.whereNull("undone_on")
		.whereNotNull("proxy_host_id")
		.where((q) => q.whereNull("expires_on").orWhere("expires_on", ">", now))
		.orderBy("id");
	const byHost = new Map();
	for (const row of rows.map(parseLabel)) {
		if (!exceptionActive(row, now)) continue;
		byHost.set(row.proxy_host_id, [...(byHost.get(row.proxy_host_id) || []), exceptionOf(row)]);
	}
	return byHost;
};
