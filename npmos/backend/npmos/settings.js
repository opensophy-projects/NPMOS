// NPMOS settings: stored in npmos_setting, edited in the GUI.
//
// Some settings are read by the container start scripts (envs.sh/start.sh) before the backend
// runs. For those the backend writes /data/npmos/runtime.env; envs.sh reads it at the next start
// and it overrides the env of compose. The running value is what this process got from envs.sh,
// so "saved but not applied yet" is visible in the GUI.
import { mkdir, rename, writeFile } from "node:fs/promises";
import db from "../db.js";
import errs from "../lib/error.js";
import { defaults as crowdsecDefaults, normalize as normalizeCrowdsec } from "./crowdsec/config.js";
import { envLines, normalize as normalizeEnv } from "./system/env.js";

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
	// (no CrowdSec IP reputation: the agent waited ~1 s for it on every request, see agent-settings.js)
	"waf.agent": {
		default: () => ({
			failOpen: { enabled: true, timeoutMs: 50 },
		}),
		validate: (v) =>
			typeof v?.failOpen?.enabled === "boolean" &&
			Number.isInteger(v.failOpen.timeoutMs) &&
			v.failOpen.timeoutMs >= 10 &&
			v.failOpen.timeoutMs <= 10000,
	},
	// the block page (Agents → Block page), see block-page.js: what a visitor sees when a request is refused
	"block.page": {
		default: () => ({
			enabled: true,
			title: "Access denied",
			text: "The security system of this site has blocked your request. If you think this is a mistake, contact the administrator and give them the request ID below.",
			contact: "",
			details: true,
			accent: "#e11d48",
			language: "en",
		}),
		validate: (v) =>
			typeof v?.enabled === "boolean" &&
			typeof v.title === "string" &&
			v.title.length <= 200 &&
			typeof v.text === "string" &&
			v.text.length <= 2000 &&
			typeof v.contact === "string" &&
			v.contact.length <= 500 &&
			typeof v.details === "boolean" &&
			/^#[0-9a-f]{6}$/i.test(v.accent) &&
			["en", "ru"].includes(v.language ?? "en"),
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
	// env settings of NPMplus set in the GUI (System → Settings), see system/env.js: {ENV: value},
	// written to runtime.env
	"system.env": {
		default: () => ({}),
		validate: (v) =>
			v !== null &&
			typeof v === "object" &&
			!Array.isArray(v) &&
			Object.entries(v).every(([env, value]) => normalizeEnv(env, value) === value),
		envMap: true,
	},
	// default policy of open-appsec (WAF → Policy), see waf/objects: {mode, threatPreventionPractices:
	// [id], ...}; null: the built-in defaults
	"waf.policy": {
		default: () => null,
		validate: (v) => {
			if (v === null) return true;
			if (typeof v !== "object" || Array.isArray(v)) return false;
			const ids = (x) => Array.isArray(x) && x.every((id) => Number.isInteger(id) && id > 0);
			const id = (x) => x === null || (Number.isInteger(x) && x > 0);
			return (
				["prevent-learn", "detect-learn", "prevent", "detect", "inactive"].includes(v.mode) &&
				["threatPreventionPractices", "accessControlPractices", "triggers", "exceptions"].every(
					(k) => v[k] === undefined || ids(v[k]),
				) &&
				["customResponse", "sourceIdentifiers", "trustedSources"].every((k) => v[k] === undefined || id(v[k]))
			);
		},
	},
	// PKI and mTLS, see pki/index.js. public_url: address of NPMOS where clients and servers get CRLs
	// and one-time links (empty: no CRL distribution point in certificates, links on the address of
	// the GUI); templates of certificates
	pki: {
		default: () => ({
			public_url: "",
			crl_days: 30,
			client_days: 365,
			server_days: 397,
			key_type: "ec-p256",
			p12_compatible: true,
			templates: [],
		}),
		validate: (v) =>
			typeof v?.public_url === "string" &&
			(v.public_url === "" || /^https?:\/\/[A-Za-z0-9.:[\]_-]+(\/[A-Za-z0-9._~/-]*)?$/.test(v.public_url)) &&
			[v.crl_days, v.client_days, v.server_days].every((d) => Number.isInteger(d) && d >= 1 && d <= 3650) &&
			v.crl_days <= 365 &&
			typeof v.key_type === "string" &&
			typeof v.p12_compatible === "boolean" &&
			Array.isArray(v.templates) &&
			v.templates.length <= 100,
	},
	// CrowdSec (CrowdSec → Settings), see crowdsec/config.js: generated into the config volume of
	// CrowdSec and the bouncer of NPMOS
	crowdsec: {
		default: crowdsecDefaults,
		validate: (v) => {
			try {
				return JSON.stringify(normalizeCrowdsec(v)) === JSON.stringify(v);
			} catch {
				return false;
			}
		},
	},
	// export of this node's decisions for other NPMOS nodes: sha256 of the bearer token, "" = off
	"crowdsec.share": {
		default: () => ({ token_hash: "" }),
		validate: (v) => typeof v?.token_hash === "string" && /^([0-9a-f]{64})?$/.test(v.token_hash),
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
		Object.keys(DEFINITIONS).filter((k) => DEFINITIONS[k].env || DEFINITIONS[k].envMap),
	);
	const lines = rows.flatMap((row) =>
		DEFINITIONS[row.key].envMap ? envLines(parse(row.value)) : [`${DEFINITIONS[row.key].env}=${parse(row.value)}`],
	);
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
	if (def.env || def.envMap) {
		await writeRuntimeEnv();
	}
	return value;
};

export { getRunningValue, getSetting, setSetting };
