// PKI of NPMOS (docs/ROADMAP.md, phase 6; docs/adr/0009-pki-mtls.md): own root and intermediate
// CAs ("trust domains"), external CAs for verification only, client and server certificates
// (from a template, from a request), renewal, revocation, CRLs, PKCS#12 and one-time links.
//
// Keys of CAs are encrypted with the key of NPMOS (secrets.js) and leave it only with
// pki:export_key. The key of an issued certificate is handed out once and not kept, unless the
// administrator asks to keep it (encrypted) for later downloads.
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import internalCertificate from "../../internal/certificate.js";
import internalNginx from "../../internal/nginx.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import { decrypt, encrypt } from "../secrets.js";
import { getSetting, setSetting } from "../settings.js";
import { startDenials } from "./denials.js";
import * as ops from "./ops.js";
import {
	generateKey,
	KEY_TYPES,
	normalizeSans,
	normalizeSubject,
	PkiError,
	PROFILES,
	parseCert,
	REVOKE_REASONS,
	randomPassword,
	randomSerial,
	splitPem,
} from "./x509.js";

const ROOT_DAYS = { default: 3650, max: 9125 };
const INTERMEDIATE_DAYS = { default: 1825, max: 7300 };
// CRLs are generated again when less than this is left before their next update
const CRL_REFRESH_MS = 7 * 86400000;
const LINK_HOURS = { default: 24, max: 24 * 14 };

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);

/** errors of the PKI as validation errors of the API */
const guard = async (fn) => {
	try {
		return await fn();
	} catch (err) {
		if (err instanceof PkiError) throw new errs.ValidationError(err.message);
		throw err;
	}
};

/** listeners of CRL changes (mTLS files of hosts): (caIds) => Promise<void> */
const crlListeners = [];
export const onCrlChange = (fn) => crlListeners.push(fn);

const notifyCrl = async (caIds) => {
	for (const fn of crlListeners) {
		try {
			await fn(caIds);
		} catch (err) {
			logger.error(`NPMOS PKI: CRL listener failed: ${err.message}`);
		}
	}
};

const settings = () => getSetting("pki");

const crlUrl = (s, caId) =>
	s.public_url ? `${s.public_url.replace(/\/$/, "")}/api/npmos/pki/public/crl/${caId}.crl` : undefined;

const ocspUrl = (s, caId) =>
	s.public_url ? `${s.public_url.replace(/\/$/, "")}/api/npmos/pki/public/ocsp/${caId}` : undefined;

/** OCSP answers by request, for a minute: clients and nginx ask again and again */
const ocspCache = new Map();
const OCSP_CACHE_MS = 60 * 1000;

const daysUntil = (date, from = new Date()) => Math.floor((new Date(date).getTime() - from.getTime()) / 86400000);

const clampDays = (days, fallback, max) => {
	const value = days === undefined || days === null ? fallback : days;
	if (!Number.isInteger(value) || value < 1 || value > max) {
		throw new PkiError(`days: 1 to ${max}`);
	}
	return value;
};

// ---------------------------------------------------------------------------------------------
// CAs

const caRow = async (id, trx = db()) => {
	const row = await trx("npmos_pki_ca").where({ id }).first();
	if (!row) throw new errs.ItemNotFoundError(id);
	return row;
};

/** certificates of a CA and its ancestors, the CA first */
export const chainPem = async (ca) => {
	const chain = [ca.cert_pem];
	let parentId = ca.parent_id;
	while (parentId) {
		const parent = await caRow(parentId);
		chain.push(parent.cert_pem);
		parentId = parent.parent_id;
	}
	return chain.join("");
};

const toCa = (row, counts = {}) => ({
	id: row.id,
	created_on: row.created_on,
	name: row.name,
	kind: row.kind,
	parent_id: row.parent_id,
	upstream_certificate_id: row.upstream_certificate_id,
	subject: parse(row.subject),
	subject_dn: row.subject_dn,
	serial: row.serial,
	not_before: row.not_before,
	not_after: row.not_after,
	fingerprint: row.fingerprint,
	key_type: row.key_type,
	has_key: !!row.key_enc,
	certificates: splitPem(row.cert_pem).length,
	has_crl: !!row.crl_pem,
	crl_number: row.crl_number,
	crl_updated_on: row.crl_updated_on,
	crl_next_update: row.crl_next_update,
	issued: counts.issued || 0,
	active: counts.active || 0,
	revoked: counts.revoked || 0,
	meta: parse(row.meta) || {},
});

/**
 * External CAs uploaded in NPMplus (Certificates → mTLS) are shown and usable as external CAs:
 * their rows follow the certificates of NPMplus.
 */
export const syncUpstream = async () => {
	const upstream = await db()("certificate")
		.where({ provider: "mtls", is_deleted: 0 })
		.select("id", "nice_name", "meta");
	const rows = await db()("npmos_pki_ca").whereNotNull("upstream_certificate_id");
	const now = new Date();
	for (const cert of upstream) {
		// NPMplus keeps the PEM in /data/tls/mtls, not in the database
		const pem =
			(await readFile(`/data/tls/mtls/npm-${cert.id}.pem`, "utf8").catch(() => "")) ||
			parse(cert.meta)?.certificate ||
			"";
		const blocks = splitPem(pem);
		if (!blocks.length) continue;
		let info;
		try {
			info = parseCert(blocks[0]);
		} catch {
			continue;
		}
		const existing = rows.find((r) => r.upstream_certificate_id === cert.id);
		if (existing && existing.cert_pem === blocks.join("")) continue;
		const { subject } = await ops.names(blocks[0]);
		const values = {
			modified_on: now,
			subject: JSON.stringify(info.subject),
			subject_dn: subject,
			serial: info.serial,
			not_before: info.notBefore,
			not_after: info.notAfter,
			fingerprint: info.fingerprint,
			key_type: info.keyType,
			cert_pem: blocks.join(""),
		};
		if (existing) {
			await db()("npmos_pki_ca").where({ id: existing.id }).update(values);
		} else {
			let name = `NPMplus: ${cert.nice_name || `#${cert.id}`}`.slice(0, 100);
			if (await db()("npmos_pki_ca").where({ name }).first()) name = `${name.slice(0, 90)} (#${cert.id})`;
			await db()("npmos_pki_ca").insert({
				...values,
				created_on: now,
				name,
				kind: "external",
				upstream_certificate_id: cert.id,
				meta: JSON.stringify({ source: "npmplus" }),
			});
		}
	}
	const gone = rows.filter((r) => !upstream.some((c) => c.id === r.upstream_certificate_id)).map((r) => r.id);
	if (gone.length) {
		await db()("npmos_pki_ca").whereIn("id", gone).delete();
	}
};

const caCounts = async () => {
	const now = new Date();
	const rows = await db()("npmos_pki_cert")
		.whereNull("deleted_on")
		.select("ca_id", "revoked_on", "replaced_by", "not_after");
	const counts = {};
	for (const r of rows) {
		const c = counts[r.ca_id] || { issued: 0, active: 0, revoked: 0 };
		c.issued++;
		if (r.revoked_on) c.revoked++;
		else if (!r.replaced_by && new Date(r.not_after) > now) c.active++;
		counts[r.ca_id] = c;
	}
	return counts;
};

/**
 * Generates the CRL of an own CA and stores it.
 * @returns {Promise<boolean>} false: the CA has no key (nothing generated)
 */
export const regenerateCrl = async (caId) => {
	const ca = await caRow(caId);
	if (ca.kind === "external" || !ca.key_enc) return false;
	const s = await settings();
	const revokedCerts = await db()("npmos_pki_cert").where({ ca_id: caId }).whereNotNull("revoked_on");
	const crlNumber = (ca.crl_number || 0) + 1;
	const crlPem = await ops.makeCrl({
		caCertPem: ca.cert_pem,
		caKeyPem: decrypt(ca.key_enc),
		revoked: revokedCerts,
		crlNumber,
		days: s.crl_days,
	});
	const now = new Date();
	await db()("npmos_pki_ca")
		.where({ id: caId })
		.update({
			crl_pem: crlPem,
			crl_number: crlNumber,
			crl_updated_on: now,
			crl_next_update: new Date(now.getTime() + s.crl_days * 86400000),
			modified_on: now,
		});
	return true;
};

/**
 * CRLs close to their next update are generated again (daily timer and start). nginx refuses
 * every client certificate of a CA whose CRL has expired, so this must keep running.
 */
export const refreshCrls = async () => {
	const now = Date.now();
	const rows = await db()("npmos_pki_ca").whereNot("kind", "external").whereNotNull("key_enc");
	const changed = [];
	for (const ca of rows) {
		if (ca.crl_next_update && new Date(ca.crl_next_update).getTime() - now > CRL_REFRESH_MS) continue;
		try {
			await regenerateCrl(ca.id);
			changed.push(ca.id);
		} catch (err) {
			logger.error(`NPMOS PKI: CRL of CA ${ca.id} (${ca.name}) was not generated: ${err.message}`);
		}
	}
	if (changed.length) await notifyCrl(changed);
	return changed;
};

const uniqueName = async (name, exceptId) => {
	if (typeof name !== "string" || !name.trim() || name.trim().length > 100) {
		throw new PkiError("name: 1 to 100 characters");
	}
	const existing = await db()("npmos_pki_ca").where({ name: name.trim() }).first();
	if (existing && existing.id !== exceptId) throw new PkiError(`A CA named ${name.trim()} already exists`);
	return name.trim();
};

/** CAs must have distinct subjects: nginx tells them apart by the issuer DN of a certificate */
const uniqueDn = async (dn) => {
	const existing = await db()("npmos_pki_ca").where({ subject_dn: dn }).whereNot("kind", "external").first();
	if (existing) throw new PkiError(`The CA ${existing.name} has the same subject (${dn}); change the common name`);
};

const insertCa = async (values) => {
	const now = new Date();
	const [id] = await db()("npmos_pki_ca")
		.insert({ created_on: now, modified_on: now, meta: JSON.stringify({}), ...values })
		.returning("id");
	return typeof id === "object" ? id.id : id;
};

const caFields = async (certPem) => {
	const info = parseCert(certPem);
	const { subject } = await ops.names(certPem);
	return {
		info,
		values: {
			subject: JSON.stringify(info.subject),
			subject_dn: subject,
			serial: info.serial,
			not_before: info.notBefore,
			not_after: info.notAfter,
			fingerprint: info.fingerprint,
			key_type: info.keyType,
			cert_pem: certPem,
		},
	};
};

// ---------------------------------------------------------------------------------------------
// certificates

const status = (row, now = new Date()) => {
	if (row.revoked_on) return "revoked";
	if (new Date(row.not_after) <= now) return "expired";
	if (row.replaced_by) return "replaced";
	return "active";
};

const toCert = (row, now = new Date()) => ({
	id: row.id,
	created_on: row.created_on,
	ca_id: row.ca_id,
	profile: row.profile,
	serial: row.serial,
	common_name: row.common_name,
	subject: parse(row.subject),
	sans: parse(row.sans),
	not_before: row.not_before,
	not_after: row.not_after,
	days_left: daysUntil(row.not_after, now),
	fingerprint: row.fingerprint,
	key_type: row.key_type,
	status: status(row, now),
	revoked_on: row.revoked_on,
	revoke_reason: row.revoke_reason,
	replaced_by: row.replaced_by,
	template: row.template,
	notes: row.notes,
	has_key: !!row.key_enc,
	owner_user_id: row.owner_user_id,
	certificate_id: row.certificate_id,
});

const certRow = async (id) => {
	const row = await db()("npmos_pki_cert").where({ id }).whereNull("deleted_on").first();
	if (!row) throw new errs.ItemNotFoundError(id);
	return row;
};

const fileName = (row) =>
	(row.common_name.replace(/[^\p{L}\p{N}._-]+/gu, "_").slice(0, 60) || `cert-${row.id}`).replace(/^\.+/, "");

const p12For = async (row, keyPem, password, compatible) => {
	const ca = await caRow(row.ca_id);
	return ops.pkcs12({
		certPem: row.cert_pem,
		keyPem,
		chainPem: await chainPem(ca),
		password,
		name: row.common_name,
		compatible,
	});
};

const newLink = async (access, row, { hours, filename, payload }) => {
	const token = randomBytes(24).toString("base64url");
	const now = new Date();
	await db()("npmos_pki_link").insert({
		created_on: now,
		expires_on: new Date(now.getTime() + hours * 3600000),
		cert_id: row.id,
		created_by: access.token.getUserId(0),
		token_hash: createHash("sha256").update(token).digest("hex"),
		filename,
		payload_enc: encrypt(payload.toString("base64")),
	});
	return {
		token,
		path: `/api/npmos/pki/public/download/${token}`,
		expires_on: new Date(now.getTime() + hours * 3600000),
	};
};

/** a template of certificates (PKI → Settings) */
const normalizeTemplate = (t, cas) => {
	if (typeof t?.id !== "string" || !/^[a-z0-9-]{1,40}$/.test(t.id)) throw new PkiError("template id: a-z, 0-9, -");
	if (typeof t.name !== "string" || !t.name.trim() || t.name.length > 100)
		throw new PkiError("template name: 1 to 100");
	if (!PROFILES.includes(t.profile)) throw new PkiError(`profile: ${PROFILES.join(", ")}`);
	if (t.ca_id !== null && !cas.some((ca) => ca.id === t.ca_id && ca.kind !== "external")) {
		throw new PkiError(`template ${t.name}: unknown CA`);
	}
	if (!KEY_TYPES[t.key_type]) throw new PkiError(`key_type: ${Object.keys(KEY_TYPES).join(", ")}`);
	const subject = { ...(t.subject || {}) };
	delete subject.common_name;
	const normalized = Object.keys(subject).length ? normalizeSubject({ ...subject, common_name: "x" }) : {};
	delete normalized.common_name;
	return {
		id: t.id,
		name: t.name.trim(),
		profile: t.profile,
		ca_id: t.ca_id ?? null,
		days: clampDays(t.days, 365, 3650),
		key_type: t.key_type,
		subject: normalized,
	};
};

const audit = (access, action, objectType, id, meta) =>
	internalAuditLog.add(access, { action, object_type: objectType, object_id: id, meta });

// ---------------------------------------------------------------------------------------------

const internalPki = {
	/**
	 * Overview of PKI and mTLS: CAs, certificates, settings.
	 * @param {Access} access
	 */
	overview: async (access) => {
		await access.can("pki:view");
		await syncUpstream();
		const counts = await caCounts();
		const cas = (await db()("npmos_pki_ca").orderBy("id")).map((row) => toCa(row, counts[row.id]));
		const now = new Date();
		const certificates = (await db()("npmos_pki_cert").whereNull("deleted_on").orderBy("id", "desc")).map((row) =>
			toCert(row, now),
		);
		return {
			cas,
			certificates,
			settings: await settings(),
			key_types: Object.keys(KEY_TYPES),
			revoke_reasons: REVOKE_REASONS,
		};
	},

	/**
	 * @param {Access} access
	 * @param {{public_url, crl_days, client_days, server_days, key_type, p12_compatible, templates}} data
	 */
	setSettings: async (access, data) => {
		await access.can("pki:manage");
		return guard(async () => {
			if (!KEY_TYPES[data.key_type]) throw new PkiError(`key_type: ${Object.keys(KEY_TYPES).join(", ")}`);
			const cas = await db()("npmos_pki_ca").select("id", "kind");
			const templates = (data.templates || []).map((t) => normalizeTemplate(t, cas));
			if (new Set(templates.map((t) => t.id)).size !== templates.length)
				throw new PkiError("template ids repeat");
			const before = await settings();
			const value = await setSetting("pki", {
				...data,
				public_url: (data.public_url || "").replace(/\/$/, ""),
				templates,
			});
			await audit(access, "updated", "pki", 0, { name: "pki" });
			// a shorter lifetime of CRLs or a new address: generate them again
			if (before.crl_days !== value.crl_days) {
				const ids = (await db()("npmos_pki_ca").whereNot("kind", "external").whereNotNull("key_enc")).map(
					(r) => r.id,
				);
				for (const id of ids) await regenerateCrl(id);
				await notifyCrl(ids);
			}
			return value;
		});
	},

	/**
	 * New root CA, or a new intermediate CA (trust domain) under a root.
	 * @param {Access} access
	 * @param {{kind: "root"|"intermediate", name, parent_id?, subject, key_type?, days?}} data
	 */
	createCa: async (access, data) => {
		await access.can("pki:manage");
		const result = await guard(async () => {
			const s = await settings();
			const name = await uniqueName(data.name);
			const subject = normalizeSubject(data.subject, { ascii: true });
			const keyType = data.key_type || s.key_type;
			const keyPem = generateKey(keyType);
			let certPem;
			let parent = null;
			if (data.kind === "root") {
				certPem = await ops.selfSign({
					keyPem,
					subject,
					days: clampDays(data.days, ROOT_DAYS.default, ROOT_DAYS.max),
					serial: randomSerial(),
				});
			} else if (data.kind === "intermediate") {
				parent = await caRow(data.parent_id);
				if (parent.kind !== "root" || !parent.key_enc)
					throw new PkiError("The parent must be a root CA of NPMOS with its key");
				if (new Date(parent.not_after) <= new Date()) throw new PkiError("The root CA has expired");
				const days = Math.min(
					clampDays(data.days, INTERMEDIATE_DAYS.default, INTERMEDIATE_DAYS.max),
					daysUntil(parent.not_after),
				);
				certPem = await ops.sign({
					csrPem: await ops.makeCsr({ keyPem, subject }),
					caCertPem: parent.cert_pem,
					caKeyPem: decrypt(parent.key_enc),
					profile: "intermediate",
					days,
					serial: randomSerial(),
					crlUrl: crlUrl(s, parent.id),
					ocspUrl: ocspUrl(s, parent.id),
				});
			} else {
				throw new PkiError("kind: root or intermediate");
			}
			const { values } = await caFields(certPem);
			await uniqueDn(values.subject_dn);
			const id = await insertCa({
				...values,
				name,
				kind: data.kind,
				parent_id: parent?.id ?? null,
				key_enc: encrypt(keyPem),
			});
			await regenerateCrl(id);
			return id;
		});
		await audit(access, "created", "pki", result, { name: data.name, kind: data.kind });
		return internalPki.getCa(access, result);
	},

	/**
	 * Import of a root CA with its key (moved from another system), or of an external CA for
	 * verification only (a bundle of certificates and optionally its CRL).
	 * @param {Access} access
	 * @param {{kind: "root"|"external", name, cert_pem, key_pem?, key_password?, crl_pem?}} data
	 */
	importCa: async (access, data) => {
		await access.can("pki:manage");
		const id = await guard(async () => {
			const name = await uniqueName(data.name);
			const blocks = splitPem(data.cert_pem);
			if (!blocks.length) throw new PkiError("No certificate (PEM) found");
			for (const block of blocks) {
				if (!parseCert(block).isCa)
					throw new PkiError("Every certificate must be a CA (basicConstraints CA:TRUE)");
			}
			if (data.kind === "root") {
				if (blocks.length !== 1) throw new PkiError("A root CA is one certificate");
				const { info, values } = await caFields(blocks[0]);
				if (!info.selfSigned) throw new PkiError("The certificate is not self-signed (not a root CA)");
				const keyPem = ops.readKey(data.key_pem || "", data.key_password);
				if (!ops.keyMatches(keyPem, blocks[0]))
					throw new PkiError("The key does not belong to the certificate");
				if (!/^[A-Za-z0-9 _.@:'()&=,-]+$/.test(values.subject_dn)) {
					throw new PkiError("The subject of the CA must be Latin letters, digits and _ . @ : ' ( ) & -");
				}
				await uniqueDn(values.subject_dn);
				const caId = await insertCa({
					...values,
					name,
					kind: "root",
					key_enc: encrypt(keyPem),
					meta: JSON.stringify({ imported: true }),
				});
				await regenerateCrl(caId);
				return caId;
			}
			if (data.kind === "external") {
				const { values } = await caFields(blocks[0]);
				values.cert_pem = blocks.join("");
				let crl = {};
				if (data.crl_pem?.trim()) {
					const { nextUpdate } = await ops.checkCrl(data.crl_pem, values.cert_pem);
					crl = { crl_pem: data.crl_pem.trim(), crl_updated_on: new Date(), crl_next_update: nextUpdate };
				}
				return insertCa({ ...values, ...crl, name, kind: "external" });
			}
			throw new PkiError("kind: root or external");
		});
		await audit(access, "created", "pki", id, { name: data.name, kind: data.kind, imported: true });
		return internalPki.getCa(access, id);
	},

	/** @param {Access} access */
	getCa: async (access, id) => {
		await access.can("pki:view");
		const counts = await caCounts();
		return toCa(await caRow(id), counts[id]);
	},

	/**
	 * Name; the CRL of an external CA (crl_pem: "" removes it).
	 * @param {Access} access
	 */
	updateCa: async (access, id, data) => {
		await access.can("pki:manage");
		const ca = await caRow(id);
		await guard(async () => {
			const values = { modified_on: new Date() };
			if (data.name !== undefined) values.name = await uniqueName(data.name, id);
			if (data.crl_pem !== undefined) {
				if (ca.kind !== "external") throw new PkiError("CRLs of NPMOS CAs are generated");
				if (data.crl_pem.trim()) {
					const { nextUpdate } = await ops.checkCrl(data.crl_pem, ca.cert_pem);
					Object.assign(values, {
						crl_pem: data.crl_pem.trim(),
						crl_updated_on: new Date(),
						crl_next_update: nextUpdate,
					});
				} else {
					Object.assign(values, { crl_pem: null, crl_updated_on: null, crl_next_update: null });
				}
			}
			await db()("npmos_pki_ca").where({ id }).update(values);
		});
		await audit(access, "updated", "pki", id, { name: data.name ?? ca.name });
		if (data.crl_pem !== undefined) await notifyCrl([id]);
		return internalPki.getCa(access, id);
	},

	/**
	 * Deletes a CA without certificates, intermediate CAs and hosts.
	 * @param {Access} access
	 * @param {(caId: number) => Promise<string[]>} usedBy  names of hosts that trust the CA
	 */
	deleteCa: async (access, id, usedBy) => {
		await access.can("pki:manage");
		const ca = await caRow(id);
		if (ca.upstream_certificate_id) {
			throw new errs.ValidationError("This CA comes from Certificates of NPMplus, delete it there");
		}
		const children = await db()("npmos_pki_ca").where({ parent_id: id });
		if (children.length)
			throw new errs.ValidationError(`Intermediate CAs depend on it: ${children.map((c) => c.name).join(", ")}`);
		const certs = await db()("npmos_pki_cert")
			.where({ ca_id: id })
			.whereNull("deleted_on")
			.count("id as count")
			.first();
		if (Number(certs.count) > 0) throw new errs.ValidationError("The CA has issued certificates");
		const hosts = await usedBy(id);
		if (hosts.length) throw new errs.ValidationError(`Hosts trust it: ${hosts.join(", ")}`);
		// deleted certificates were kept for the CRL of this CA only
		const deleted = await db()("npmos_pki_cert").where({ ca_id: id }).select("id");
		await db()("npmos_pki_link")
			.whereIn(
				"cert_id",
				deleted.map((r) => r.id),
			)
			.delete();
		await db()("npmos_pki_cert").where({ ca_id: id }).delete();
		await db()("npmos_pki_ca").where({ id }).delete();
		await audit(access, "deleted", "pki", id, { name: ca.name });
		return true;
	},

	/**
	 * Files of a CA: cert (PEM), chain (PEM, up to the root), crl (PEM), key (PEM encrypted with a
	 * password, pki:export_key).
	 * @param {Access} access
	 * @returns {Promise<{filename: string, type: string, data: string|Buffer}>}
	 */
	exportCa: async (access, id, format, password) => {
		await access.can("pki:view");
		const ca = await caRow(id);
		const base = ca.name.replace(/[^A-Za-z0-9._-]+/g, "_");
		if (format === "cert")
			return { filename: `${base}.crt`, type: "application/x-pem-file", data: splitPem(ca.cert_pem)[0] };
		if (format === "chain")
			return { filename: `${base}-chain.pem`, type: "application/x-pem-file", data: await chainPem(ca) };
		if (format === "crl") {
			if (!ca.crl_pem) throw new errs.ValidationError("The CA has no CRL");
			return { filename: `${base}.crl`, type: "application/x-pem-file", data: ca.crl_pem };
		}
		if (format === "key") {
			await access.can("pki:export_key");
			if (!ca.key_enc) throw new errs.ValidationError("NPMOS has no key of this CA");
			if (typeof password !== "string" || password.length < 8) {
				throw new errs.ValidationError("A password of 8 characters or more encrypts the exported key");
			}
			await audit(access, "exported", "pki", id, { name: ca.name, key: true });
			return {
				filename: `${base}.key`,
				type: "application/x-pem-file",
				data: ops.encryptKey(decrypt(ca.key_enc), password),
			};
		}
		throw new errs.ValidationError("format: cert, chain, crl, key");
	},

	/**
	 * Issues a certificate: from a request (csr_pem) or with a key generated here. With a generated
	 * key the result has a .p12 (password given or generated), PEM files and optionally a one-time
	 * link; the key is kept (encrypted) only with store_key.
	 * @param {Access} access
	 * @param {{ca_id, profile, subject, sans?, days?, key_type?, csr_pem?, template?, notes?, store_key?,
	 *   password?, compatible?, link_hours?, include_key_pem?, install?}} data
	 *   install: a server certificate also becomes a custom certificate of NPMplus (Certificates)
	 */
	issue: async (access, data, { replaces } = {}) => {
		await access.can("pki:issue");
		if (data.store_key) await access.can("pki:export_key");
		return guard(async () => {
			const s = await settings();
			const ca = await caRow(data.ca_id);
			if (ca.kind === "external" || !ca.key_enc)
				throw new PkiError("Certificates are issued by NPMOS CAs with a key");
			if (ca.kind === "root")
				throw new PkiError("A root CA only signs intermediate CAs; issue with a trust domain");
			if (new Date(ca.not_after) <= new Date()) throw new PkiError("The CA has expired");
			if (!PROFILES.includes(data.profile)) throw new PkiError(`profile: ${PROFILES.join(", ")}`);
			const sans = normalizeSans(data.sans);
			if (data.profile === "server" && !sans.dns.length && !sans.ip.length) {
				throw new PkiError("A server certificate needs DNS names or IP addresses");
			}
			const days = Math.min(
				clampDays(data.days, data.profile === "server" ? s.server_days : s.client_days, 3650),
				daysUntil(ca.not_after),
			);
			let keyPem = null;
			let csrPem;
			let rsa;
			if (data.csr_pem?.trim()) {
				({ rsa } = await ops.readCsr(data.csr_pem));
				csrPem = data.csr_pem;
			} else {
				const subject = normalizeSubject(data.subject);
				keyPem = generateKey(data.key_type || s.key_type);
				rsa = ops.isRsa(keyPem);
				csrPem = await ops.makeCsr({ keyPem, subject });
			}
			const certPem = await ops.sign({
				csrPem,
				caCertPem: ca.cert_pem,
				caKeyPem: decrypt(ca.key_enc),
				profile: data.profile,
				sans,
				days,
				serial: randomSerial(),
				crlUrl: crlUrl(s, ca.id),
				ocspUrl: ocspUrl(s, ca.id),
				rsa,
			});
			const info = parseCert(certPem);
			if (!info.subject.common_name) throw new PkiError("The request has no common name (CN)");
			const now = new Date();
			const [inserted] = await db()("npmos_pki_cert")
				.insert({
					created_on: now,
					modified_on: now,
					ca_id: ca.id,
					profile: data.profile,
					serial: info.serial,
					common_name: info.subject.common_name.slice(0, 255),
					subject: JSON.stringify(info.subject),
					sans: JSON.stringify(info.sans),
					not_before: info.notBefore,
					not_after: info.notAfter,
					fingerprint: info.fingerprint,
					key_type: info.keyType,
					cert_pem: certPem,
					key_enc: keyPem && data.store_key ? encrypt(keyPem) : null,
					template: String(data.template || "").slice(0, 100),
					notes: String(data.notes || "").slice(0, 500),
					owner_user_id: access.token.getUserId(0),
				})
				.returning("id");
			const id = typeof inserted === "object" ? inserted.id : inserted;
			const row = await certRow(id);
			const chain = await chainPem(ca);
			const files = { cert_pem: certPem, chain_pem: chain };
			let link = null;
			if (keyPem) {
				const password = data.password || randomPassword();
				if (password.length < 4) throw new PkiError("The password of the .p12 is 4 characters or more");
				const p12 = await p12For(row, keyPem, password, data.compatible ?? s.p12_compatible);
				files.p12_base64 = p12.toString("base64");
				files.password = password;
				files.filename = fileName(row);
				if (data.include_key_pem) files.key_pem = keyPem;
				if (data.link_hours) {
					const hours = clampDays(data.link_hours, LINK_HOURS.default, LINK_HOURS.max);
					link = await newLink(access, row, { hours, filename: `${fileName(row)}.p12`, payload: p12 });
				}
			}
			if (data.profile === "server" && keyPem && (data.install || replaces?.certificate_id)) {
				await installServer(access, row, keyPem, chain, replaces?.certificate_id);
			}
			await audit(access, replaces ? "renewed" : "created", "pki", id, {
				name: row.common_name,
				serial: row.serial,
				ca: ca.name,
				profile: row.profile,
			});
			return { certificate: toCert(await certRow(id)), files, link };
		});
	},

	/**
	 * Renewal: a new certificate with the subject, names, profile and CA of the old one; the old one
	 * is marked replaced (and revoked as superseded with revoke_old). A server certificate installed
	 * in NPMplus is replaced there.
	 * @param {Access} access
	 */
	renew: async (access, id, data = {}) => {
		const old = await certRow(id);
		if (old.revoked_on) throw new errs.ValidationError("A revoked certificate is not renewed; issue a new one");
		const subject = parse(old.subject);
		const result = await internalPki.issue(
			access,
			{
				...data,
				// a kept key stays kept
				store_key: data.store_key ?? !!old.key_enc,
				ca_id: data.ca_id ?? old.ca_id,
				profile: old.profile,
				subject,
				sans: parse(old.sans),
				key_type: data.key_type || old.key_type,
				template: old.template,
				notes: old.notes,
			},
			{ replaces: old },
		);
		await db()("npmos_pki_cert")
			.where({ id })
			.update({ replaced_by: result.certificate.id, certificate_id: null, modified_on: new Date() });
		if (data.revoke_old) await internalPki.revoke(access, [id], "superseded");
		return result;
	},

	/**
	 * Revokes certificates; the CRLs of their CAs are generated again and nginx reloads them.
	 * @param {Access} access
	 * @param {number[]} ids
	 */
	revoke: async (access, ids, reason = "unspecified") => {
		await access.can("pki:revoke");
		if (!REVOKE_REASONS.includes(reason)) throw new errs.ValidationError(`reason: ${REVOKE_REASONS.join(", ")}`);
		const rows = await db()("npmos_pki_cert").whereIn("id", ids).whereNull("revoked_on");
		if (!rows.length) return { revoked: 0 };
		const now = new Date();
		await db()("npmos_pki_cert")
			.whereIn(
				"id",
				rows.map((r) => r.id),
			)
			.update({ revoked_on: now, revoke_reason: reason, key_enc: null, modified_on: now });
		await db()("npmos_pki_link")
			.whereIn(
				"cert_id",
				rows.map((r) => r.id),
			)
			.delete();
		const caIds = [...new Set(rows.map((r) => r.ca_id))];
		// OCSP answers "revoked" at once
		ocspCache.clear();
		for (const caId of caIds) await regenerateCrl(caId);
		await notifyCrl(caIds);
		for (const row of rows) {
			await audit(access, "revoked", "pki", row.id, { name: row.common_name, serial: row.serial, reason });
		}
		return { revoked: rows.length };
	},

	/**
	 * Notes of a certificate (who or what it is for).
	 * @param {Access} access
	 */
	updateCert: async (access, id, { notes }) => {
		await access.can("pki:issue");
		const row = await certRow(id);
		await db()("npmos_pki_cert")
			.where({ id })
			.update({ notes: String(notes ?? "").slice(0, 500), modified_on: new Date() });
		await audit(access, "updated", "pki", id, { name: row.common_name });
		return toCert(await certRow(id));
	},

	/**
	 * Deletes certificates from the lists. A certificate still valid is revoked first
	 * (cessationOfOperation): its row stays hidden, so the CRL of its CA keeps listing it.
	 * @param {Access} access
	 * @param {number[]} ids
	 */
	deleteCerts: async (access, ids) => {
		await access.can("pki:revoke");
		const rows = await db()("npmos_pki_cert").whereIn("id", ids).whereNull("deleted_on");
		if (!rows.length) return { deleted: 0 };
		const now = new Date();
		const valid = rows.filter((r) => !r.revoked_on && new Date(r.not_after) > now);
		if (valid.length) {
			await internalPki.revoke(
				access,
				valid.map((r) => r.id),
				"cessationOfOperation",
			);
		}
		const list = rows.map((r) => r.id);
		await db()("npmos_pki_link").whereIn("cert_id", list).delete();
		await db()("npmos_pki_cert").whereIn("id", list).update({ deleted_on: now, key_enc: null, modified_on: now });
		for (const row of rows) {
			await audit(access, "deleted", "pki", row.id, { name: row.common_name, serial: row.serial });
		}
		return { deleted: rows.length, revoked: valid.length };
	},

	/**
	 * Files of a certificate: cert, chain (with the certificate), key and p12 (kept key, pki:export_key).
	 * @param {Access} access
	 */
	download: async (access, id, format, { password, compatible } = {}) => {
		await access.can("pki:view");
		const row = await certRow(id);
		const base = fileName(row);
		if (format === "cert") return { filename: `${base}.crt`, type: "application/x-pem-file", data: row.cert_pem };
		if (format === "chain") {
			return {
				filename: `${base}-fullchain.pem`,
				type: "application/x-pem-file",
				data: row.cert_pem + (await chainPem(await caRow(row.ca_id))),
			};
		}
		if (format === "key" || format === "p12") {
			await access.can("pki:export_key");
			if (!row.key_enc) throw new errs.ValidationError("NPMOS did not keep the key of this certificate");
			await audit(access, "exported", "pki", id, { name: row.common_name, key: true });
			if (format === "key")
				return { filename: `${base}.key`, type: "application/x-pem-file", data: decrypt(row.key_enc) };
			if (typeof password !== "string" || password.length < 4)
				throw new errs.ValidationError("password: 4 characters or more");
			const s = await settings();
			const data = await guard(() => p12For(row, decrypt(row.key_enc), password, compatible ?? s.p12_compatible));
			return { filename: `${base}.p12`, type: "application/x-pkcs12", data };
		}
		throw new errs.ValidationError("format: cert, chain, key, p12");
	},

	/**
	 * One-time link to the .p12 of a certificate with a kept key.
	 * @param {Access} access
	 */
	createLink: async (access, id, { hours, password, compatible }) => {
		await access.can("pki:export_key");
		const row = await certRow(id);
		if (!row.key_enc) throw new errs.ValidationError("NPMOS did not keep the key of this certificate");
		if (row.revoked_on) throw new errs.ValidationError("The certificate is revoked");
		return guard(async () => {
			const s = await settings();
			const pass = password || randomPassword();
			const p12 = await p12For(row, decrypt(row.key_enc), pass, compatible ?? s.p12_compatible);
			const link = await newLink(access, row, {
				hours: clampDays(hours, LINK_HOURS.default, LINK_HOURS.max),
				filename: `${fileName(row)}.p12`,
				payload: p12,
			});
			await audit(access, "exported", "pki", id, { name: row.common_name, link: true });
			return { link, password: pass };
		});
	},

	/**
	 * Without login: a one-time link. The file is removed when it is taken.
	 * @returns {Promise<{filename, data: Buffer}|null>}
	 */
	takeLink: async (token) => {
		if (typeof token !== "string" || !/^[A-Za-z0-9_-]{20,64}$/.test(token)) return null;
		const hash = createHash("sha256").update(token).digest("hex");
		const now = new Date();
		const row = await db()("npmos_pki_link").where({ token_hash: hash }).first();
		if (!row || row.used_on || !row.payload_enc || new Date(row.expires_on) <= now) return null;
		// the first request takes it
		const taken = await db()("npmos_pki_link")
			.where({ id: row.id })
			.whereNull("used_on")
			.update({ used_on: now, payload_enc: null });
		if (!taken) return null;
		return { filename: row.filename, data: Buffer.from(decrypt(row.payload_enc), "base64") };
	},

	/** Without login: the CRL of a CA in DER (its distribution point) */
	publicCrl: async (caId) => {
		const ca = await db()("npmos_pki_ca").where({ id: caId }).first();
		if (!ca?.crl_pem) return null;
		return ops.crlToDer(ca.crl_pem);
	},

	/**
	 * Without login: OCSP responder of an own CA (RFC 6960). Status from the database: good,
	 * revoked, or unknown for serials it never issued. null: no such CA or it has no key.
	 * @param {number} caId
	 * @param {Buffer} requestDer
	 */
	ocsp: async (caId, requestDer) => {
		if (!requestDer?.length || requestDer.length > 16 * 1024) return null;
		const key = `${caId}:${createHash("sha256").update(requestDer).digest("hex")}`;
		const cached = ocspCache.get(key);
		if (cached && cached.until > Date.now()) return cached.der;
		const ca = await db()("npmos_pki_ca").where({ id: caId }).first();
		if (!ca || ca.kind === "external" || !ca.key_enc) return null;
		// what it signed: certificates and trust domains below it
		const certs = await db()("npmos_pki_cert")
			.where({ ca_id: caId })
			.select("serial", "not_after", "revoked_on", "revoke_reason");
		const children = await db()("npmos_pki_ca").where({ parent_id: caId }).select("serial", "not_after");
		const der = await ops.ocspRespond({
			caCertPem: ca.cert_pem,
			caKeyPem: decrypt(ca.key_enc),
			certs: [...certs, ...children].filter((c) => c.serial),
			requestDer,
		});
		if (ocspCache.size > 1000) ocspCache.clear();
		ocspCache.set(key, { der, until: Date.now() + OCSP_CACHE_MS });
		return der;
	},

	/** links of a certificate (not their tokens) */
	links: async (access, id) => {
		await access.can("pki:view");
		const rows = await db()("npmos_pki_link").where({ cert_id: id }).orderBy("id", "desc");
		return rows.map((r) => ({
			id: r.id,
			created_on: r.created_on,
			expires_on: r.expires_on,
			used_on: r.used_on,
			active: !r.used_on && new Date(r.expires_on) > new Date(),
		}));
	},

	/** @param {Access} access */
	deleteLink: async (access, linkId) => {
		await access.can("pki:export_key");
		await db()("npmos_pki_link").where({ id: linkId }).delete();
		return true;
	},
};

/** a server certificate as a custom certificate of NPMplus (new, or replacing the files of the old) */
const installServer = async (access, row, keyPem, chain, existingId) => {
	const files = {
		certificate: { data: Buffer.from(row.cert_pem + chain) },
		certificate_key: { data: Buffer.from(keyPem) },
	};
	let certificateId = existingId;
	if (certificateId && !(await db()("certificate").where({ id: certificateId, is_deleted: 0 }).first())) {
		certificateId = null;
	}
	if (!certificateId) {
		const created = await internalCertificate.create(access, {
			provider: "other",
			nice_name: `${row.common_name} (PKI)`,
			meta: {},
		});
		certificateId = created.id;
	}
	await internalCertificate.upload(access, { id: certificateId, files });
	await db()("npmos_pki_cert").where({ id: row.id }).update({ certificate_id: certificateId });
	await internalNginx.reload();
};

/** start: CRLs that will expire soon, then every 6 hours; expired links are removed */
export const bootstrap = async () => {
	try {
		await refreshCrls();
	} catch (err) {
		logger.error(`NPMOS PKI: ${err.message}`);
	}
	const timer = setInterval(
		async () => {
			try {
				await refreshCrls();
				await db()("npmos_pki_link")
					.where("expires_on", "<", new Date(Date.now() - 7 * 86400000))
					.delete();
			} catch (err) {
				logger.error(`NPMOS PKI: ${err.message}`);
			}
		},
		6 * 3600 * 1000,
	);
	timer.unref();
	startDenials();
};

export default internalPki;
