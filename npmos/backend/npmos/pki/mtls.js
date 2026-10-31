// mTLS of hosts and streams (docs/ROADMAP.md, phase 6, section 5.1): which CAs a host trusts, on
// or optional, rules on fields of the client certificate, locations that require it, X-Client-*
// headers to the upstream. The nginx templates get npmos_mtls from prepareHost (hook in
// internal/nginx.js) and read the CAs and CRLs of the host from files written here.
//
// Trust: nginx verifies a chain up to a root in the CA file, so a certificate of another
// intermediate CA (trust domain) of the same root would pass; the issuer DN is therefore checked
// against the selected CAs. External CAs are trusted as a whole (no issuer check).
// Revocation: with ssl_crl, nginx checks the CRL of every CA of the chain, so the CRL file has
// them all; when a CA of the host has no CRL (external without one), revocation is not checked.
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import internalNginx from "../../internal/nginx.js";
import internalProxyHostAccessList from "../../internal/proxy-host-access-list.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import proxyHostModel from "../../models/proxy_host.js";
import streamModel from "../../models/stream.js";
import internalPki, { onCrlChange } from "./index.js";
import { escapeRe, RULE_FIELDS, RULE_OPS, ruleRegex, trustSet } from "./trust.js";
import { ASCII_VALUE } from "./x509.js";
import { scopeHosts } from "../rbac/scope.js";

const DIR = process.env.NPMOS_MTLS_DIR || "/data/npmos/pki/nginx";

export const HOST_TYPES = ["proxy_host", "stream"];
export const MODES = ["on", "optional"];
/** how revocation is checked: crl (the CRL files, nginx reloads when one changes) or ocsp (asks NPMOS, no reload) */
export const REVOCATIONS = ["crl", "ocsp"];
/** the OCSP responder of NPMOS for nginx itself (conf.d/npmos-ocsp.conf) */
const OCSP_RESPONDER = process.env.NPMOS_OCSP_RESPONDER || "http://127.0.0.1:7089/api/npmos/pki/public/ocsp/auto";
export { RULE_FIELDS, RULE_OPS, ruleRegex, trustSet };
export const DEFAULTS = {
	enabled: false,
	ca_ids: [],
	mode: "on",
	depth: 2,
	send_ca_names: true,
	rules: [],
	required_paths: [],
	headers: true,
	revocation: "crl",
};

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);

const files = (hostType, id) => ({
	ca: `${DIR}/${hostType}-${id}.ca.pem`,
	crl: `${DIR}/${hostType}-${id}.crl.pem`,
});

/** writes a file when its content changes; true if it changed */
const writeIfChanged = async (file, content) => {
	try {
		if ((await readFile(file, "utf8")) === content) return false;
	} catch {}
	await mkdir(DIR, { recursive: true });
	await writeFile(`${file}.tmp`, content, { mode: 0o644 });
	await rename(`${file}.tmp`, file);
	return true;
};

const writeFiles = async (hostType, id, set) => {
	const f = files(hostType, id);
	let changed = await writeIfChanged(f.ca, set.certs);
	if (set.crls) {
		changed = (await writeIfChanged(f.crl, set.crls)) || changed;
	} else {
		await rm(f.crl, { force: true });
	}
	return changed;
};

const toBinding = (row) =>
	row
		? {
				enabled: !!row.enabled,
				ca_ids: parse(row.ca_ids) || [],
				mode: row.mode,
				depth: row.depth,
				send_ca_names: !!row.send_ca_names,
				rules: parse(row.rules) || [],
				required_paths: parse(row.required_paths) || [],
				headers: !!row.headers,
				revocation: REVOCATIONS.includes(row.revocation) ? row.revocation : "crl",
			}
		: { ...DEFAULTS };

/**
 * Hook of internal/nginx.js generateConfig: npmos_mtls of the template (and npmos_mtls_required of
 * locations), files of the CAs and CRLs. Without a binding the upstream mTLS settings stay.
 * @param {string} hostType
 * @param {object} host  copy being rendered
 */
export const prepareHost = async (hostType, host) => {
	if (!HOST_TYPES.includes(hostType)) return;
	try {
		const row = await db()("npmos_mtls_host").where({ host_type: hostType, host_id: host.id }).first();
		const binding = toBinding(row);
		if (!binding.enabled || !binding.ca_ids.length || !(host.certificate_id > 0)) return;
		const set = trustSet(binding.ca_ids, await db()("npmos_pki_ca"));
		if (!set.ids.length) return;
		const ocsp = binding.revocation === "ocsp" && hostType === "proxy_host";
		// with OCSP nginx asks NPMOS about every new connection: no CRL file, nothing to reload on a revocation
		await writeFiles(hostType, host.id, ocsp ? { ...set, crls: "" } : set);
		const f = files(hostType, host.id);
		host.npmos_mtls = {
			mode: hostType === "stream" ? "on" : binding.mode,
			depth: binding.depth,
			send_ca_names: binding.send_ca_names,
			ca_file: f.ca,
			crl_file: set.crls && !ocsp ? f.crl : "",
			ocsp_url: ocsp ? OCSP_RESPONDER : "",
			issuers: set.issuers?.length ? `^(?:${set.issuers.map(escapeRe).join("|")})$` : "",
			rules: binding.rules.map(ruleRegex),
			headers: binding.headers,
			root_required: binding.mode === "optional" && binding.required_paths.includes("/"),
			// the log of the location replaces the access log of nginx: refused requests keep both
			access_log: process.env.LOGROTATE === "true",
		};
		if (binding.mode === "optional" && Array.isArray(host.locations)) {
			for (const location of host.locations) {
				location.npmos_mtls_required = binding.required_paths.includes(location.path);
			}
		}
	} catch (err) {
		// fail closed: the configuration of the host is not written without its mTLS
		logger.error(`NPMOS mTLS: ${hostType} ${host.id}: ${err.message}`);
		throw err;
	}
};

const hostModel = (hostType) => (hostType === "proxy_host" ? proxyHostModel : streamModel);

const getHost = async (hostType, id) => {
	const host = await db()(hostType).where({ id, is_deleted: 0 }).first();
	if (!host) throw new errs.ItemNotFoundError(id);
	return host;
};

const hostName = (hostType, host) =>
	hostType === "proxy_host" ? (parse(host.domain_names) || []).join(", ") : `:${host.incoming_port}`;

/** regenerates the nginx configuration of a host; {nginx_online, nginx_err} */
const reconfigure = async (hostType, id) => {
	const model = hostModel(hostType);
	const row = await model.query().where({ id, is_deleted: 0 }).withGraphFetched(model.defaultAllowGraph).first();
	if (!row?.enabled) return null;
	let host = row;
	if (hostType === "proxy_host") {
		host = await internalProxyHostAccessList.populateLocationAccessLists(
			internalProxyHostAccessList.cleanAccessListTypes(row),
		);
	}
	const meta = await internalNginx.configure(model, hostType, host);
	return { nginx_online: meta.nginx_online, nginx_err: meta.nginx_err };
};

/** CRLs or CAs changed: files of the hosts that trust them, then nginx reloads */
const refreshFor = async (caIds) => {
	const cas = await db()("npmos_pki_ca");
	const rows = await db()("npmos_mtls_host").where({ enabled: true });
	let changed = false;
	for (const row of rows) {
		// revocation by OCSP: the answers of NPMOS change, nginx needs nothing
		if (row.revocation === "ocsp" && row.host_type === "proxy_host") continue;
		const set = trustSet(parse(row.ca_ids) || [], cas);
		if (!set.ids.some((id) => caIds.includes(id))) continue;
		const hadCrl = await readFile(files(row.host_type, row.host_id).crl, "utf8").then(
			() => true,
			() => false,
		);
		if (hadCrl !== !!set.crls) {
			// ssl_crl appears or disappears in the configuration
			await reconfigure(row.host_type, row.host_id);
			continue;
		}
		changed = (await writeFiles(row.host_type, row.host_id, set)) || changed;
	}
	if (changed) await internalNginx.reload();
};

onCrlChange(refreshFor);

/**
 * CAs are deleted (with their intermediate CAs): hosts stop trusting them. A host with mTLS on that would trust
 * no CA left is not opened silently: with check=true its name is returned and nothing changes.
 * @param {number[]} caIds
 * @returns {Promise<string[]>} names of the hosts that would trust nothing (check), or of the changed hosts
 */
export const detachCas = async (caIds, check = false) => {
	const gone = new Set(caIds);
	const rows = await db()("npmos_mtls_host");
	const names = [];
	for (const row of rows) {
		const ids = parse(row.ca_ids) || [];
		if (!ids.some((id) => gone.has(id))) continue;
		const left = ids.filter((id) => !gone.has(id));
		const host = await db()(row.host_type).where({ id: row.host_id, is_deleted: 0 }).first();
		const name = host ? hostName(row.host_type, host) : `${row.host_type} #${row.host_id}`;
		if (check) {
			if (row.enabled && host && !left.length) names.push(name);
			continue;
		}
		await db()("npmos_mtls_host")
			.where({ host_type: row.host_type, host_id: row.host_id })
			.update({ ca_ids: JSON.stringify(left), enabled: row.enabled && left.length > 0, modified_on: new Date() });
		if (host) {
			await reconfigure(row.host_type, row.host_id);
			names.push(name);
		}
	}
	return names;
};

/** names of hosts that trust a CA (directly or through its root or intermediate) */
export const usedBy = async (caId) => {
	const cas = await db()("npmos_pki_ca");
	const rows = await db()("npmos_mtls_host");
	const names = [];
	for (const row of rows) {
		if (!trustSet(parse(row.ca_ids) || [], cas).ids.includes(caId)) continue;
		const host = await db()(row.host_type).where({ id: row.host_id, is_deleted: 0 }).first();
		if (host) names.push(hostName(row.host_type, host));
	}
	return names;
};

/**
 * Where the PKI is used: hosts that trust each CA (with mTLS on), hosts that serve each custom
 * certificate of NPMplus (server certificates of the PKI).
 * @returns {Promise<{cas: Record<number, string[]>, certificates: Record<number, string[]>}>}
 */
export const usage = async () => {
	const cas = await db()("npmos_pki_ca");
	const result = { cas: {}, certificates: {} };
	const names = new Map();
	for (const hostType of HOST_TYPES) {
		for (const host of await db()(hostType).where({ is_deleted: 0 })) {
			names.set(`${hostType}-${host.id}`, hostName(hostType, host));
			if (host.certificate_id > 0) {
				result.certificates[host.certificate_id] = [
					...(result.certificates[host.certificate_id] || []),
					hostName(hostType, host),
				];
			}
		}
	}
	for (const row of await db()("npmos_mtls_host").where({ enabled: true })) {
		const name = names.get(`${row.host_type}-${row.host_id}`);
		if (!name) continue;
		for (const id of trustSet(parse(row.ca_ids) || [], cas).ids) {
			result.cas[id] = [...(result.cas[id] || []), name];
		}
	}
	return result;
};

/**
 * Which hosts each certificate opens: for every host with mTLS on, the CAs whose client
 * certificates it accepts. Proxy hosts check the issuer, so these are the selected CAs and the
 * intermediate CAs of selected roots; streams cannot, so a trust domain there accepts every
 * intermediate CA of its root. Rules on fields of certificates may narrow it further.
 * @returns {Promise<Array<{host_type: string, host_id: number, name: string, mode: string, ca_ids: number[],
 *   accepts: number[], rules: number}>>}
 */
export const protectedHosts = async () => {
	const cas = await db()("npmos_pki_ca");
	const result = [];
	for (const row of await db()("npmos_mtls_host").where({ enabled: true })) {
		const host = await db()(row.host_type).where({ id: row.host_id, is_deleted: 0 }).first();
		if (!host) continue;
		const ids = trustSet(parse(row.ca_ids) || [], cas).ids;
		const accepts = new Set(ids);
		if (row.host_type === "stream") {
			for (const ca of cas) if (ids.includes(ca.parent_id)) accepts.add(ca.id);
		}
		result.push({
			host_type: row.host_type,
			host_id: row.host_id,
			name: hostName(row.host_type, host),
			mode: row.mode,
			ca_ids: parse(row.ca_ids) || [],
			accepts: [...accepts],
			rules: (parse(row.rules) || []).length,
			// a host without its certificate serves no TLS: its mTLS is not in force
			active: !!host.enabled && host.certificate_id > 0,
		});
	}
	return result;
};

/** ASCII-only text for subjects of CAs (nginx prints UTF-8 escaped) */
const ascii = (text) =>
	text
		.normalize("NFKD")
		.replace(/[^\x20-\x7e]/g, "")
		.replace(/[^A-Za-z0-9 _.@:'()&-]+/g, "-")
		.replace(/\s+/g, " ")
		.trim()
		.slice(0, 60);

const validate = (data, hostType, host, cas) => {
	const b = { ...DEFAULTS, ...data };
	if (typeof b.enabled !== "boolean") throw new errs.ValidationError("enabled: boolean");
	if (!Array.isArray(b.ca_ids) || !b.ca_ids.every((id) => cas.some((ca) => ca.id === id))) {
		throw new errs.ValidationError("ca_ids: CAs of PKI and mTLS");
	}
	b.ca_ids = [...new Set(b.ca_ids)];
	if (b.enabled && !b.ca_ids.length) throw new errs.ValidationError("Choose at least one CA");
	if (b.enabled && !(host.certificate_id > 0)) {
		throw new errs.ValidationError("mTLS needs TLS: choose a certificate of the host first");
	}
	if (!MODES.includes(b.mode)) throw new errs.ValidationError(`mode: ${MODES.join(", ")}`);
	if (!Number.isInteger(b.depth) || b.depth < 1 || b.depth > 5) throw new errs.ValidationError("depth: 1 to 5");
	if (!Array.isArray(b.rules) || b.rules.length > 20) throw new errs.ValidationError("rules: 20 at most");
	b.rules = b.rules.map((rule) => {
		if (!(rule?.field in RULE_FIELDS))
			throw new errs.ValidationError(`field: ${Object.keys(RULE_FIELDS).join(", ")}`);
		if (!RULE_OPS.includes(rule.op)) throw new errs.ValidationError(`op: ${RULE_OPS.join(", ")}`);
		const values = (Array.isArray(rule.values) ? rule.values : []).map((v) => String(v).trim()).filter(Boolean);
		if (!values.length || values.length > 50) throw new errs.ValidationError("values: 1 to 50");
		if (rule.op === "regex") {
			const re = values[0];
			if (values.length !== 1 || re.length > 200 || /["\n\r]|\\\\/.test(re)) {
				throw new errs.ValidationError('regex: one expression up to 200 characters, without " and \\\\');
			}
			try {
				new RegExp(re);
			} catch (err) {
				throw new errs.ValidationError(`regex: ${err.message}`);
			}
		} else {
			for (const v of values) {
				const ok = rule.field === "serial" ? /^[0-9A-Fa-f]{1,64}$/.test(v) : ASCII_VALUE.test(v);
				if (!ok) {
					throw new errs.ValidationError(
						rule.field === "serial"
							? `serial: hexadecimal (${v})`
							: `${rule.field}: Latin letters, digits, space and _ . @ : ' ( ) & - (${v})`,
					);
				}
			}
		}
		return {
			field: rule.field,
			op: rule.op,
			values: rule.field === "serial" && rule.op === "one_of" ? values.map((v) => v.toUpperCase()) : values,
		};
	});
	if (!REVOCATIONS.includes(b.revocation)) throw new errs.ValidationError(`revocation: ${REVOCATIONS.join(", ")}`);
	if (hostType === "stream" && b.revocation !== "crl") {
		throw new errs.ValidationError("Streams check revocation by the CRL only");
	}
	if (hostType === "stream") {
		if (b.mode !== "on" || b.rules.length || b.required_paths.length) {
			throw new errs.ValidationError("Streams support mode on without rules and locations");
		}
		b.headers = false;
	}
	const paths = ["/", ...(parse(host.locations) || []).map((l) => l.path)];
	if (!Array.isArray(b.required_paths) || !b.required_paths.every((p) => paths.includes(p))) {
		throw new errs.ValidationError(`required_paths: of ${paths.join(", ")}`);
	}
	if (b.mode === "on") b.required_paths = [];
	for (const key of ["send_ca_names", "headers"]) {
		if (typeof b[key] !== "boolean") throw new errs.ValidationError(`${key}: boolean`);
	}
	return b;
};

const permission = (hostType) => (hostType === "proxy_host" ? "proxy_hosts" : "streams");

const internalMtls = {
	/**
	 * mTLS of every host the user can see: {proxy_host: {<id>: {...}}, stream: {...}}
	 * @param {Access} access
	 */
	list: async (access) => {
		const result = { proxy_host: {}, stream: {} };
		for (const hostType of HOST_TYPES) {
			let accessData;
			try {
				accessData = await access.can(`${permission(hostType)}:list`);
			} catch {
				continue;
			}
			const query = db()("npmos_mtls_host")
				.join(hostType, `${hostType}.id`, "npmos_mtls_host.host_id")
				.where("npmos_mtls_host.host_type", hostType)
				.where(`${hostType}.is_deleted`, 0)
				.select("npmos_mtls_host.*");
			scopeHosts(query, accessData, hostType, access.token.getUserId(1));
			for (const row of await query) {
				result[hostType][row.host_id] = toBinding(row);
			}
		}
		return result;
	},

	/**
	 * @param {Access} access
	 * @returns {Promise<object>} binding with paths of the host, its certificate and the mTLS of NPMplus
	 */
	get: async (access, hostType, id) => {
		await access.can(`${permission(hostType)}:get`, id);
		const host = await getHost(hostType, id);
		const row = await db()("npmos_mtls_host").where({ host_type: hostType, host_id: id }).first();
		const meta = parse(host.meta) || {};
		return {
			...toBinding(row),
			name: hostName(hostType, host),
			has_certificate: host.certificate_id > 0,
			// streams have no rules in nginx: a trust domain there accepts every intermediate CA of its root
			issuer_check: hostType === "proxy_host",
			paths: hostType === "proxy_host" ? ["/", ...(parse(host.locations) || []).map((l) => l.path)] : [],
			upstream_ca_certificate_id: meta.npmplus_mtls_certificate_id > 0 ? meta.npmplus_mtls_certificate_id : null,
		};
	},

	/**
	 * Saves the mTLS of a host and regenerates its nginx configuration.
	 * @param {Access} access
	 */
	set: async (access, hostType, id, data) => {
		// like the WAF: who edits the host, or a role with pki:manage on the hosts it sees
		try {
			await access.can(`${permission(hostType)}:update`, id);
		} catch {
			await access.can("pki:manage");
			await access.can(`${permission(hostType)}:get`, id);
		}
		const host = await getHost(hostType, id);
		const binding = validate(data, hostType, host, await db()("npmos_pki_ca").select("id"));
		const values = {
			modified_on: new Date(),
			enabled: binding.enabled,
			ca_ids: JSON.stringify(binding.ca_ids),
			mode: binding.mode,
			depth: binding.depth,
			send_ca_names: binding.send_ca_names,
			rules: JSON.stringify(binding.rules),
			required_paths: JSON.stringify(binding.required_paths),
			headers: binding.headers,
			revocation: binding.revocation,
		};
		await db()("npmos_mtls_host")
			.insert({ host_type: hostType, host_id: id, ...values })
			.onConflict(["host_type", "host_id"])
			.merge();
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "mtls",
			object_id: id,
			meta: { name: hostName(hostType, host), host_type: hostType, enabled: binding.enabled, mode: binding.mode },
		});
		const nginx = await reconfigure(hostType, id);
		return { ...(await internalMtls.get(access, hostType, id)), nginx };
	},
};

/**
 * mTLS on in one step (the switch of the hosts table): the CAs the host had before, or a trust
 * domain of its own, made with a root when there is none (pki:manage).
 * @param {Access} access
 */
internalMtls.quick = async (access, hostType, id) => {
	if (!HOST_TYPES.includes(hostType)) throw new errs.ValidationError(`host_type: ${HOST_TYPES.join(", ")}`);
	await access.can(`${permission(hostType)}:get`, id);
	const host = await getHost(hostType, id);
	if (!(host.certificate_id > 0)) {
		throw new errs.ValidationError("mTLS needs TLS: choose a certificate of the host first");
	}
	const row = await db()("npmos_mtls_host").where({ host_type: hostType, host_id: id }).first();
	const current = toBinding(row);
	const cas = await db()("npmos_pki_ca");
	const key = `${hostType}-${id}`;
	let caIds = current.ca_ids.filter((caId) => cas.some((ca) => ca.id === caId));
	if (!caIds.length) {
		// the trust domain of this host, made by an earlier switch
		const own = cas.find((ca) => parse(ca.meta)?.host === key && ca.key_enc);
		if (own) {
			caIds = [own.id];
		} else {
			await access.can("pki:manage");
			const now = new Date();
			let root = cas.find((ca) => ca.kind === "root" && ca.key_enc && new Date(ca.not_after) > now);
			if (!root) {
				const suffix = cas.some((ca) => ca.name === "NPMOS mTLS Root CA") ? ` ${now.getFullYear()}` : "";
				const created = await internalPki.createCa(access, {
					kind: "root",
					name: `NPMOS mTLS Root CA${suffix}`,
					subject: { common_name: `NPMOS mTLS Root CA${suffix}`, organization: "NPMOS" },
				});
				root = { id: created.id };
			}
			const label = hostName(hostType, host).split(", ")[0];
			// names and subjects of CAs are unique: a CA left from a deleted host of the same name
			const taken = (name, cn) => cas.some((ca) => ca.name === name || parse(ca.subject)?.common_name === cn);
			let name = `mTLS ${label}`.slice(0, 80);
			let cn = `mTLS ${ascii(hostType === "stream" ? `stream ${label}` : label) || key}`;
			if (taken(name, cn)) {
				name = `${name} (${key})`;
				cn = `${cn} (${key})`;
			}
			const domain = await internalPki.createCa(access, {
				kind: "intermediate",
				name,
				parent_id: root.id,
				subject: { common_name: cn, organization: "NPMOS" },
			});
			await db()("npmos_pki_ca")
				.where({ id: domain.id })
				.update({ meta: JSON.stringify({ ...domain.meta, host: key }) });
			caIds = [domain.id];
		}
	}
	return internalMtls.set(access, hostType, id, { ...current, enabled: true, ca_ids: caIds });
};

export default internalMtls;
