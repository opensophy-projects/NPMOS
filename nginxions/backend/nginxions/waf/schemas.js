// OpenAPI files of the WAF policy (schemaValidation of a practice, docs/WAF-POLICY.md): uploaded in WAF -> Policy, kept
// in the data volume of NginxionS and copied into the data of CrowdSec (its "schemas" folder), where AppSec loads them
// (waf/engines.js). A practice names them in schemaValidation.files.
import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import internalAuditLog from "../../internal/audit-log.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import { DATA_DIR as CROWDSEC_DATA } from "../crowdsec/hub.js";
import { renderAppsecPolicy, SCHEMA_DIR, schemaFiles } from "./engines.js";
import { listObjects } from "./objects/store.js";

export const STORE = process.env.NGINXIONS_OPENAPI_DIR || "/data/nginxions/openapi";
export const MAX_BYTES = 5 * 1024 * 1024;
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.(ya?ml|json)$/;

/** a name of a file (also a file of the store) */
export const checkName = (name) => {
	if (typeof name !== "string" || !NAME.test(name) || name.includes("..")) {
		throw new errs.ValidationError("an OpenAPI file is named like api.yaml, api.yml or api.json");
	}
	return name;
};

/**
 * What an OpenAPI file describes; an error if it is not one.
 * @param {Buffer|string} content
 * @returns {{version: string, title: string, paths: number}}
 */
export const describe = (content) => {
	if (!content?.length) throw new errs.ValidationError("the file is empty");
	if (content.length > MAX_BYTES) throw new errs.ValidationError("the file is larger than 5 MB");
	let doc;
	try {
		// JSON is YAML
		doc = YAML.parse(String(content), { maxAliasCount: 100 });
	} catch (err) {
		throw new errs.ValidationError(`not YAML or JSON: ${err.message}`);
	}
	const version =
		typeof doc?.openapi === "string" ? doc.openapi : typeof doc?.swagger === "string" ? doc.swagger : "";
	if (!/^(3\.[0-9]|2\.0)/.test(version)) {
		throw new errs.ValidationError("not an OpenAPI 3 or Swagger 2.0 file (no openapi or swagger version)");
	}
	if (!doc.paths || typeof doc.paths !== "object") throw new errs.ValidationError("the file has no paths");
	return {
		version,
		title: String(doc.info?.title ?? "").slice(0, 200),
		paths: Object.keys(doc.paths).length,
	};
};

/** the files of the store: [{name, size, modifiedOn, version, title, paths}] */
export const listSchemas = async () => {
	let names;
	try {
		names = await readdir(STORE);
	} catch (err) {
		if (err.code === "ENOENT") return [];
		throw err;
	}
	const out = [];
	for (const name of names.filter((n) => NAME.test(n)).sort()) {
		const file = path.join(STORE, name);
		const info = await stat(file);
		let meta = { version: "", title: "", paths: 0 };
		try {
			meta = describe(await readFile(file));
		} catch {
			// a file broken on disk is listed without its description
		}
		out.push({ name, size: info.size, modifiedOn: info.mtime.toISOString(), ...meta });
	}
	return out;
};

/**
 * The files a policy uses, copied into the data of CrowdSec (before it loads its appsec-config); the others are
 * removed there. A file the store does not have is left out (the policy warns about it).
 * @param {string[]} names
 * @returns {Promise<string[]>} the names missing in the store
 */
export const syncToCrowdsec = async (names, { dataDir = CROWDSEC_DATA } = {}) => {
	const dir = path.join(dataDir, "schemas", SCHEMA_DIR);
	await mkdir(dir, { recursive: true });
	const missing = [];
	const wanted = new Set();
	for (const name of names) {
		try {
			checkName(name);
			const content = await readFile(path.join(STORE, name));
			wanted.add(name);
			const target = path.join(dir, name);
			let old = null;
			try {
				old = await readFile(target);
			} catch {
				// not there yet
			}
			if (!old?.equals(content)) {
				await writeFile(`${target}.tmp`, content, { mode: 0o644 });
				await rename(`${target}.tmp`, target);
			}
		} catch {
			missing.push(name);
		}
	}
	for (const name of await readdir(dir)) {
		if (!wanted.has(name)) await rm(path.join(dir, name), { force: true });
	}
	return missing;
};

/**
 * The appsec-config of the policy with the hashes of its OpenAPI files: a file uploaded again under its name is a
 * change of the config, and CrowdSec reloads it.
 * @param {{rules: object[], engines: object[]}} parsed  appsecRules of the policy
 */
export const appsecPolicyText = async (parsed) => {
	const text = renderAppsecPolicy(parsed);
	if (text === null) return null;
	const lines = [];
	for (const name of schemaFiles(parsed)) {
		try {
			const hash = createHash("sha256")
				.update(await readFile(path.join(STORE, checkName(name))))
				.digest("hex");
			lines.push(`# ${name} sha256:${hash}`);
		} catch {
			lines.push(`# ${name} missing`);
		}
	}
	return lines.length ? `${text}${lines.join("\n")}\n` : text;
};

const audit = (access, action, name) =>
	internalAuditLog.add(access, { action, object_type: "waf", meta: { openapi: name } });

/** the practices that name each file: {name: [practice]} */
const usage = async () => {
	const out = {};
	for (const o of await listObjects()) {
		if (o.kind !== "threat_prevention") continue;
		for (const f of Array.isArray(o.spec?.schemaValidation?.files) ? o.spec.schemaValidation.files : []) {
			out[f] = [...(out[f] ?? []), o.name];
		}
	}
	return out;
};

/** a file of the policy changed: CrowdSec loads it again (crowdsec/index.js) */
const reapply = () =>
	import("../crowdsec/index.js")
		.then(({ applyPolicyEngines }) => applyPolicyEngines())
		.catch((err) => logger.error(`WAF: OpenAPI files were not applied: ${err.message}`));

const internalWafSchemas = {
	/** @param {Access} access */
	list: async (access) => {
		await access.can("waf_policy:view");
		const used = await usage();
		return (await listSchemas()).map((s) => ({ ...s, usedBy: used[s.name] ?? [] }));
	},

	/**
	 * @param {Access} access
	 * @param {string} name
	 * @param {Buffer} content
	 */
	upload: async (access, name, content) => {
		await access.can("waf_policy:manage");
		checkName(name);
		const meta = describe(content);
		await mkdir(STORE, { recursive: true, mode: 0o700 });
		const file = path.join(STORE, name);
		await writeFile(`${file}.tmp`, content, { mode: 0o600 });
		await rename(`${file}.tmp`, file);
		await audit(access, "updated", name);
		if ((await usage())[name]) reapply();
		return { name, size: content.length, ...meta };
	},

	/**
	 * @param {Access} access
	 * @param {string} name
	 */
	download: async (access, name) => {
		await access.can("waf_policy:view");
		checkName(name);
		try {
			return await readFile(path.join(STORE, name));
		} catch {
			throw new errs.ItemNotFoundError(name);
		}
	},

	/**
	 * @param {Access} access
	 * @param {string} name  not used by a practice
	 */
	remove: async (access, name) => {
		await access.can("waf_policy:manage");
		checkName(name);
		const used = (await usage())[name] ?? [];
		if (used.length) throw new errs.ValidationError(`${name} is used by ${used.join(", ")}`);
		await rm(path.join(STORE, name), { force: true });
		await audit(access, "deleted", name);
		return true;
	},
};

export default internalWafSchemas;
