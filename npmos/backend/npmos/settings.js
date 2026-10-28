// NPMOS settings: stored in npmos_setting, edited in the GUI.
//
// Some settings are read by the container start scripts (envs.sh/start.sh) before the backend
// runs. For those the backend writes /data/npmos/runtime.env; envs.sh reads it at the next start
// and it overrides the env of compose. The running value is what this process got from envs.sh,
// so "saved but not applied yet" is visible in the GUI.
import { mkdir, rename, writeFile } from "node:fs/promises";
import db from "../db.js";
import errs from "../lib/error.js";

const RUNTIME_ENV_FILE = "/data/npmos/runtime.env";

const envBool = (name) => process.env[name] === "true";

/**
 * @type {Record<string, {default: () => any, validate: (v: any) => boolean, env?: string}>}
 * env: written to runtime.env, applied by a restart of the npmos container
 */
const DEFINITIONS = {
	"waf.enabled": {
		env: "NGINX_LOAD_OPENAPPSEC_ATTACHMENT_MODULE",
		default: () => envBool("NGINX_LOAD_OPENAPPSEC_ATTACHMENT_MODULE"),
		validate: (v) => typeof v === "boolean",
	},
	// open-appsec agent (WAF -> Agent), applied by the agent's entrypoint, see waf/agent-settings.js
	"waf.agent": {
		default: () => ({
			crowdsec: { enabled: false, mode: "prevent" },
			failOpen: { enabled: true, timeoutMs: 50 },
		}),
		validate: (v) =>
			typeof v?.crowdsec?.enabled === "boolean" &&
			["prevent", "detect"].includes(v.crowdsec.mode) &&
			typeof v?.failOpen?.enabled === "boolean" &&
			Number.isInteger(v.failOpen.timeoutMs) &&
			v.failOpen.timeoutMs >= 10 &&
			v.failOpen.timeoutMs <= 10000,
	},
	// security events (System → Settings → Events), see events/ingest.js: raw events and hourly
	// aggregates are kept this many days
	"events.retention": {
		default: () => ({ days: 30, aggregateDays: 365 }),
		validate: (v) =>
			Number.isInteger(v?.days) &&
			v.days >= 1 &&
			v.days <= 365 &&
			Number.isInteger(v?.aggregateDays) &&
			v.aggregateDays >= v.days &&
			v.aggregateDays <= 1830,
	},
	// OIDC groups → roles (Administration → Roles), see rbac/index.js
	"rbac.oidc": {
		default: () => ({ claim: "groups", requestScope: false }),
		validate: (v) =>
			typeof v?.claim === "string" &&
			/^[A-Za-z0-9_.:/-]{1,100}$/.test(v.claim) &&
			typeof v?.requestScope === "boolean",
	},
};

const table = () => db()("npmos_setting");

const definition = (key) => {
	const def = DEFINITIONS[key];
	if (!def) {
		throw new errs.ValidationError(`Unknown NPMOS setting: ${key}`);
	}
	return def;
};

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);

/**
 * @param   {string} key
 * @returns {Promise<any>}
 */
const getSetting = async (key) => {
	const def = definition(key);
	const row = await table().where("key", key).first();
	return row ? parse(row.value) : def.default();
};

/**
 * Value the running process uses (env as resolved by envs.sh at container start)
 * @param   {string} key
 * @returns {any}
 */
const getRunningValue = (key) => {
	const def = definition(key);
	return def.env ? envBool(def.env) : undefined;
};

const writeRuntimeEnv = async () => {
	const rows = await table().whereIn(
		"key",
		Object.keys(DEFINITIONS).filter((k) => DEFINITIONS[k].env),
	);
	const lines = rows.map((row) => `${DEFINITIONS[row.key].env}=${parse(row.value)}`);
	await mkdir("/data/npmos", { recursive: true });
	const tmp = `${RUNTIME_ENV_FILE}.tmp`;
	await writeFile(tmp, `${lines.join("\n")}\n`, { mode: 0o600 });
	await rename(tmp, RUNTIME_ENV_FILE);
};

/**
 * @param   {string} key
 * @param   {any}    value
 * @returns {Promise<any>} the stored value
 */
const setSetting = async (key, value) => {
	const def = definition(key);
	if (!def.validate(value)) {
		throw new errs.ValidationError(`Invalid value for ${key}`);
	}
	await table()
		.insert({ key, value: JSON.stringify(value), modified_on: new Date() })
		.onConflict("key")
		.merge();
	if (def.env) {
		await writeRuntimeEnv();
	}
	return value;
};

export { getRunningValue, getSetting, setSetting };
