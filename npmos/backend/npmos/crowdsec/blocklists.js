// Local blocklists instead of the community blocklist of the CrowdSec cloud: a list of IPs and
// CIDRs from a file or a URL (also the export of another NPMOS node) becomes decisions in the LAPI,
// scenario npmos/blocklist/<id>. A sync replaces the decisions of the list.
import http from "node:http";
import https from "node:https";
import db from "../../db.js";
import { decrypt } from "../secrets.js";
import { durationMinutes } from "./config.js";
import { deleteDecisions, pushDecisions } from "./lapi.js";
import { parseList } from "./lists.js";

const CHUNK = 1000;
const FETCH_TIMEOUT_MS = 30000;
const MAX_BYTES = 20 * 1024 * 1024;

export const scenarioOf = (id) => `npmos/blocklist/${id}`;

/**
 * GET of a list; insecure: the certificate is not verified (another NPMOS node with a self-signed one)
 * @returns {Promise<string>}
 */
export const fetchList = (url, { token = "", insecure = false } = {}) =>
	new Promise((resolve, reject) => {
		if (!/^https?:\/\//.test(url)) return reject(new Error("The URL must start with http:// or https://"));
		const client = url.startsWith("https:") ? https : http;
		const req = client.get(
			url,
			{
				headers: { "User-Agent": "npmos", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
				rejectUnauthorized: !insecure,
				timeout: FETCH_TIMEOUT_MS,
			},
			(res) => {
				if (res.statusCode !== 200) {
					res.resume();
					return reject(new Error(`${url}: HTTP ${res.statusCode}`));
				}
				const chunks = [];
				let size = 0;
				res.on("data", (chunk) => {
					size += chunk.length;
					if (size > MAX_BYTES) req.destroy(new Error("The list is larger than 20 MB"));
					else chunks.push(chunk);
				});
				res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
				res.on("error", reject);
			},
		);
		req.on("timeout", () => req.destroy(new Error(`${url}: no answer in ${FETCH_TIMEOUT_MS / 1000} s`)));
		req.on("error", (err) =>
			reject(new Error(err.message.startsWith(url) ? err.message : `${url}: ${err.code || err.message}`)),
		);
	});

/**
 * Downloads (url) or reads (file) the list and replaces its decisions.
 * @param {object} row  of npmos_crowdsec_blocklist
 * @param {string[]} allowlist  IPs and CIDRs never banned
 * @returns {Promise<{count: number, invalid: number}>}
 */
export const syncList = async (row, allowlist) => {
	const now = new Date();
	try {
		const text =
			row.source === "url"
				? await fetchList(row.url, { token: decrypt(row.token_enc || ""), insecure: !!row.insecure })
				: row.content || "";
		const { entries, invalid } = parseList(text, allowlist);
		const scenario = scenarioOf(row.id);
		await deleteDecisions({ scenario });
		if (row.enabled) {
			durationMinutes(row.duration);
			for (let i = 0; i < entries.length; i += CHUNK) {
				await pushDecisions({
					scenario,
					origin: "lists",
					message: `NPMOS blocklist ${row.name}`,
					decisions: entries.slice(i, i + CHUNK).map((value) => ({
						scope: value.includes("/") ? "Range" : "Ip",
						value,
						type: row.decision,
						duration: row.duration,
					})),
				});
			}
		}
		const count = row.enabled ? entries.length : 0;
		await db()("npmos_crowdsec_blocklist").where("id", row.id).update({ synced_on: now, count, error: "" });
		return { count, invalid };
	} catch (err) {
		await db()("npmos_crowdsec_blocklist")
			.where("id", row.id)
			.update({ synced_on: now, error: String(err.message).slice(0, 1000) });
		throw err;
	}
};

/** URL lists whose refresh time has come */
export const dueLists = async (now = Date.now()) => {
	const rows = await db()("npmos_crowdsec_blocklist")
		.where({ source: "url", enabled: true })
		.andWhere("refresh_minutes", ">", 0);
	return rows.filter((r) => !r.synced_on || new Date(r.synced_on).getTime() + r.refresh_minutes * 60000 <= now);
};
