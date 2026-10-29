// Client of the local API of CrowdSec (LAPI) for NPMOS. NPMOS is a machine of its own ("npmos-…",
// registered with the token of npmos-init: config.yaml.local) for alerts and decisions, and reads
// machines and bouncers from the database of CrowdSec (the LAPI has no API for them).
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import pjson from "../../package.json" with { type: "json" };
import { DATA_DIR } from "./hub.js";

export const LAPI_URL = process.env.NPMOS_CROWDSEC_URL || "http://crowdsec:8080";
export const METRICS_URL = process.env.NPMOS_CROWDSEC_METRICS_URL || "http://crowdsec:6060/metrics";
const SECRETS_DIR = process.env.NPMOS_SECRETS_DIR || "/run/npmos-secrets";
const TIMEOUT_MS = 10000;
// the LAPI refuses the login of a machine whose User-Agent is not "name/version"
const USER_AGENT = `npmos/${pjson.version}`;

export class LapiError extends Error {
	constructor(message, status = 0) {
		super(message);
		this.status = status;
	}
}

const secret = async (name) => {
	try {
		return (await readFile(path.join(SECRETS_DIR, name), "utf8")).trim();
	} catch {
		throw new LapiError(`The secret ${name} is missing (npmos-init)`);
	}
};

export const bouncerKey = () => secret("bouncer_key");
export const registrationToken = () => secret("crowdsec_registration_token");

/** machine id from the password: a new password is a new machine, never a clash */
export const machineId = (password) => `npmos-${createHash("sha256").update(password).digest("hex").slice(0, 12)}`;

let jwt = { token: "", expires: 0 };

const request = async (method, url, { headers = {}, body, raw = false } = {}) => {
	let response;
	try {
		response = await fetch(url, {
			method,
			headers: {
				"User-Agent": USER_AGENT,
				...(body === undefined ? {} : { "Content-Type": "application/json" }),
				...headers,
			},
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: AbortSignal.timeout(TIMEOUT_MS),
		});
	} catch (err) {
		throw new LapiError(`CrowdSec is unreachable: ${err.cause?.code || err.message}`);
	}
	const text = await response.text();
	if (!response.ok) {
		let message = text;
		try {
			message = JSON.parse(text).message || text;
		} catch {}
		throw new LapiError(`CrowdSec: ${message || `HTTP ${response.status}`}`, response.status);
	}
	if (raw) return text;
	return text ? JSON.parse(text) : null;
};

const register = async (id, password) => {
	try {
		await request("POST", `${LAPI_URL}/v1/watchers`, {
			body: { machine_id: id, password, registration_token: await registrationToken() },
		});
	} catch (err) {
		// 403: already registered (with this password, since the id comes from it)
		if (err.status !== 403) throw err;
	}
};

const login = async () => {
	const password = await secret("crowdsec_machine_password");
	const id = machineId(password);
	const doLogin = () =>
		request("POST", `${LAPI_URL}/v1/watchers/login`, { body: { machine_id: id, password, scenarios: [] } });
	let result;
	try {
		result = await doLogin();
	} catch (err) {
		if (err.status !== 401 && err.status !== 403) throw err;
		await register(id, password);
		result = await doLogin();
	}
	jwt = { token: result.token, expires: new Date(result.expire).getTime() - 60000 };
	return jwt.token;
};

const machine = async (method, pathname, options = {}) => {
	const token = jwt.token && jwt.expires > Date.now() ? jwt.token : await login();
	try {
		return await request(method, `${LAPI_URL}${pathname}`, {
			...options,
			headers: { Authorization: `Bearer ${token}` },
		});
	} catch (err) {
		if (err.status !== 401) throw err;
		return request(method, `${LAPI_URL}${pathname}`, {
			...options,
			headers: { Authorization: `Bearer ${await login()}` },
		});
	}
};

const qs = (params) => {
	const q = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
	const s = q.toString();
	return s ? `?${s}` : "";
};

export const health = async () => {
	await request("GET", `${LAPI_URL}/health`, { raw: true });
	return true;
};

/** @param {{since?, until?, ip?, range?, scope?, value?, scenario?, has_active_decision?, limit?, origin?}} params */
export const alerts = async (params = {}) =>
	(await machine("GET", `/v1/alerts${qs({ include_capi: false, ...params })}`)) || [];
export const alert = (id) => machine("GET", `/v1/alerts/${encodeURIComponent(id)}`);
export const deleteAlert = (id) => machine("DELETE", `/v1/alerts/${encodeURIComponent(id)}`);

/** active decisions as the bouncers see them */
export const decisions = async (params = {}) =>
	(await request("GET", `${LAPI_URL}/v1/decisions${qs(params)}`, { headers: { "X-Api-Key": await bouncerKey() } })) ||
	[];

/** @param {{ip?, range?, scope?, value?, type?, origin?, scenario?}} params */
export const deleteDecisions = (params) => machine("DELETE", `/v1/decisions${qs(params)}`);
export const deleteDecision = (id) => machine("DELETE", `/v1/decisions/${encodeURIComponent(id)}`);

/**
 * One alert carrying decisions (how cscli adds decisions by hand)
 * @param {{scenario: string, message: string, origin: string, decisions: {scope, value, type, duration}[]}} a
 * @returns {Promise<string[]>} ids of the alerts
 */
export const pushDecisions = ({ scenario, message, origin, decisions: list }) => {
	const now = new Date().toISOString();
	const first = list[0];
	return machine("POST", "/v1/alerts", {
		body: [
			{
				scenario,
				scenario_hash: "",
				scenario_version: "",
				message,
				events_count: 1,
				start_at: now,
				stop_at: now,
				capacity: 0,
				leakspeed: "0",
				simulated: false,
				events: [],
				source: {
					scope: first.scope,
					value: first.value,
					...(first.scope === "Ip" ? { ip: first.value } : {}),
				},
				decisions: list.map((d) => ({ ...d, origin, scenario })),
			},
		],
	});
};

/** Prometheus text format → [{name, labels, value}] */
export const parseMetrics = (text) => {
	const rows = [];
	for (const line of text.split("\n")) {
		if (!line || line.startsWith("#")) continue;
		const m = /^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)/.exec(line);
		if (!m) continue;
		const labels = {};
		for (const l of (m[3] || "").matchAll(/([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"/g)) {
			labels[l[1]] = l[2].replace(/\\(.)/g, "$1");
		}
		rows.push({ name: m[1], labels, value: Number(m[4]) });
	}
	return rows;
};

export const metrics = async () => parseMetrics(await request("GET", METRICS_URL, { raw: true }));

const DB_FILE = path.join(DATA_DIR, "crowdsec.db");

/** machines and bouncers, read-only from the SQLite database of CrowdSec */
export const registry = async () => {
	const { default: Database } = await import("better-sqlite3");
	let database;
	try {
		database = new Database(DB_FILE, { readonly: true, fileMustExist: true, timeout: 2000 });
	} catch (err) {
		throw new LapiError(`The CrowdSec database is not readable: ${err.message}`);
	}
	try {
		const date = (v) =>
			v
				? new Date(
						String(v)
							.replace(" ", "T")
							.replace(/(\.\d{3})\d*/, "$1"),
					).toISOString()
				: null;
		const machines = database
			.prepare(
				"SELECT machine_id, ip_address, created_at, last_push, last_heartbeat, is_validated, version, auth_type, osname, osversion FROM machines ORDER BY machine_id",
			)
			.all()
			.map((m) => ({
				name: m.machine_id,
				ip_address: m.ip_address || "",
				created_on: date(m.created_at),
				last_push: date(m.last_push),
				last_heartbeat: date(m.last_heartbeat),
				validated: !!m.is_validated,
				version: m.version || "",
				auth_type: m.auth_type || "",
				os: [m.osname, m.osversion].filter(Boolean).join(" "),
			}));
		const bouncers = database
			.prepare(
				"SELECT name, ip_address, created_at, last_pull, revoked, type, version, auth_type FROM bouncers ORDER BY name",
			)
			.all()
			.map((b) => ({
				name: b.name,
				ip_address: b.ip_address || "",
				created_on: date(b.created_at),
				last_pull: date(b.last_pull),
				valid: !b.revoked,
				type: b.type || "",
				version: b.version || "",
				auth_type: b.auth_type || "",
			}));
		return { machines, bouncers };
	} finally {
		database.close();
	}
};
