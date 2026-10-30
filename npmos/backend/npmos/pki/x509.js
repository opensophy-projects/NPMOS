// Pure helpers of the PKI: validation of subjects and names, openssl configuration texts, serial
// numbers, the index of revoked certificates for CRLs, parsing of certificates. No database, no
// processes (unit tested in pki.test.js).
import { generateKeyPairSync, randomBytes, X509Certificate } from "node:crypto";
import net from "node:net";

/** key types offered; Ed25519 is not, browsers barely support it for client certificates */
export const KEY_TYPES = {
	"ec-p256": { type: "ec", options: { namedCurve: "prime256v1" } },
	"ec-p384": { type: "ec", options: { namedCurve: "secp384r1" } },
	"rsa-2048": { type: "rsa", options: { modulusLength: 2048 } },
	"rsa-3072": { type: "rsa", options: { modulusLength: 3072 } },
	"rsa-4096": { type: "rsa", options: { modulusLength: 4096 } },
};

/** reasons of revocation (RFC 5280), as openssl names them */
export const REVOKE_REASONS = [
	"unspecified",
	"keyCompromise",
	"CACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
];

export const PROFILES = ["client", "server"];

/** fields of a subject (API name → X.509 name) in the order they are written, most general first */
export const SUBJECT_FIELDS = {
	country: "C",
	state: "ST",
	locality: "L",
	organization: "O",
	organizational_unit: "OU",
	common_name: "CN",
	email: "emailAddress",
};

// Values of a subject: letters (any script), digits, space and a few marks. No / \ + , = " # $ ;
// < >: they would need escaping in -subj, openssl configs, RFC 2253 names and nginx rules.
const SUBJECT_VALUE = /^[\p{L}\p{N} _.@:'()&-]{1,64}$/u;
// Names of CAs are compared in nginx rules (issuer DN), so they are ASCII
const ASCII_VALUE = /^[A-Za-z0-9 _.@:'()&-]{1,64}$/;
const HOSTNAME = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}$/;

export class PkiError extends Error {}

export { ASCII_VALUE };

/**
 * Normalized subject: {common_name, organization?, organizational_unit?, country?, state?, locality?};
 * empty fields dropped.
 * @param {Record<string, string>} subject
 * @param {{ascii?: boolean}} [options]  ascii: names of CAs
 */
export const normalizeSubject = (subject, { ascii = false } = {}) => {
	const result = {};
	for (const field of Object.keys(SUBJECT_FIELDS)) {
		const value = typeof subject?.[field] === "string" ? subject[field].trim() : "";
		if (!value) continue;
		if (!(ascii ? ASCII_VALUE : SUBJECT_VALUE).test(value)) {
			throw new PkiError(
				ascii
					? `${field}: Latin letters, digits, space and _ . @ : ' ( ) & - only, up to 64`
					: `${field}: letters, digits, space and _ . @ : ' ( ) & - only, up to 64`,
			);
		}
		if (field === "email" && !EMAIL.test(value)) {
			throw new PkiError(`Invalid email: ${value}`);
		}
		if (field === "country" && !/^[A-Z]{2}$/.test(value)) {
			throw new PkiError("country: two capital letters (ISO 3166)");
		}
		result[field] = value;
	}
	if (!result.common_name) {
		throw new PkiError("common_name is required");
	}
	return result;
};

/** -subj argument of openssl: /C=../O=../CN=.. */
export const subjectArg = (subject) =>
	Object.entries(SUBJECT_FIELDS)
		.filter(([field]) => subject[field])
		.map(([field, name]) => `/${name}=${subject[field]}`)
		.join("");

/**
 * Subject alternative names, checked: {dns: [], ip: [], email: []}
 * @param {{dns?: string[], ip?: string[], email?: string[]}} sans
 */
export const normalizeSans = (sans = {}) => {
	const list = (value) => (Array.isArray(value) ? value : []).map((v) => String(v).trim()).filter(Boolean);
	const dns = [...new Set(list(sans.dns).map((v) => v.toLowerCase()))];
	const ip = [...new Set(list(sans.ip))];
	const email = [...new Set(list(sans.email))];
	for (const name of dns) {
		if (name.length > 253 || !HOSTNAME.test(name)) throw new PkiError(`Invalid DNS name: ${name}`);
	}
	for (const address of ip) {
		if (!net.isIP(address)) throw new PkiError(`Invalid IP address: ${address}`);
	}
	for (const address of email) {
		if (!EMAIL.test(address)) throw new PkiError(`Invalid email: ${address}`);
	}
	if (dns.length + ip.length + email.length > 100) throw new PkiError("Too many alternative names (100 at most)");
	return { dns, ip, email };
};

/** random 128-bit serial number as openssl prints it (upper-case hex, no leading zero byte) */
export const randomSerial = () => {
	const bytes = randomBytes(16);
	bytes[0] = (bytes[0] & 0x7f) | 0x01;
	return bytes.toString("hex").toUpperCase();
};

/**
 * Generates a key pair: PEM (PKCS#8) of the private key.
 * @param {string} keyType  see KEY_TYPES
 */
export const generateKey = (keyType) => {
	const spec = KEY_TYPES[keyType];
	if (!spec) throw new PkiError(`Unknown key type: ${keyType}`);
	const { privateKey } = generateKeyPairSync(spec.type, {
		...spec.options,
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
		publicKeyEncoding: { type: "spki", format: "pem" },
	});
	return privateKey;
};

/**
 * openssl configuration with the extensions of a certificate, section [ext].
 * @param {"root"|"intermediate"|"client"|"server"} profile
 * @param {{sans?: {dns: string[], ip: string[], email: string[]}, crlUrl?: string, ocspUrl?: string, rsa?: boolean}} [options]
 */
export const extConfig = (profile, { sans, crlUrl, ocspUrl, rsa = false } = {}) => {
	const lines = ["[req]", "distinguished_name = dn", "[dn]", "[ext]"];
	if (profile === "root") {
		lines.push("basicConstraints = critical, CA:TRUE", "keyUsage = critical, keyCertSign, cRLSign");
		lines.push("subjectKeyIdentifier = hash");
	} else if (profile === "intermediate") {
		lines.push("basicConstraints = critical, CA:TRUE, pathlen:0", "keyUsage = critical, keyCertSign, cRLSign");
		lines.push("subjectKeyIdentifier = hash", "authorityKeyIdentifier = keyid:always");
	} else {
		lines.push("basicConstraints = critical, CA:FALSE");
		lines.push(`keyUsage = critical, digitalSignature${rsa ? ", keyEncipherment" : ""}`);
		lines.push(`extendedKeyUsage = ${profile === "server" ? "serverAuth" : "clientAuth"}`);
		lines.push("subjectKeyIdentifier = hash", "authorityKeyIdentifier = keyid:always");
	}
	if (crlUrl) {
		if (!/^https?:\/\/[A-Za-z0-9.:[\]_/-]+$/.test(crlUrl)) throw new PkiError(`Invalid CRL URL: ${crlUrl}`);
		lines.push(`crlDistributionPoints = URI:${crlUrl}`);
	}
	if (ocspUrl) {
		if (!/^https?:\/\/[A-Za-z0-9.:[\]_/-]+$/.test(ocspUrl)) throw new PkiError(`Invalid OCSP URL: ${ocspUrl}`);
		lines.push(`authorityInfoAccess = OCSP;URI:${ocspUrl}`);
	}
	const names = [
		...(sans?.dns || []).map((v, i) => `DNS.${i + 1} = ${v}`),
		...(sans?.ip || []).map((v, i) => `IP.${i + 1} = ${v}`),
		...(sans?.email || []).map((v, i) => `email.${i + 1} = ${v}`),
	];
	if (names.length) {
		lines.push("subjectAltName = @san", "[san]", ...names);
	}
	return `${lines.join("\n")}\n`;
};

const utcTime = (date) => {
	const d = new Date(date);
	const pad = (n) => String(n).padStart(2, "0");
	return `${pad(d.getUTCFullYear() % 100)}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}Z`;
};

/**
 * index.txt of `openssl ca` with the revoked certificates of a CA (only they matter for a CRL).
 * @param {Array<{serial: string, not_after: Date|string, revoked_on: Date|string, revoke_reason?: string}>} revoked
 */
export const indexTxt = (revoked) =>
	revoked
		.map((c) => {
			const reason = REVOKE_REASONS.includes(c.revoke_reason) ? c.revoke_reason : "unspecified";
			return [
				"R",
				utcTime(c.not_after),
				`${utcTime(c.revoked_on)},${reason}`,
				c.serial,
				"unknown",
				"/CN=revoked",
			].join("\t");
		})
		.map((line) => `${line}\n`)
		.join("");

/**
 * index.txt for `openssl ocsp`: every certificate of a CA, valid (V) or revoked (R). A serial that
 * is not in it is answered "unknown".
 * @param {Array<{serial: string, not_after: Date|string, revoked_on?: Date|string|null, revoke_reason?: string}>} certs
 */
export const ocspIndex = (certs) =>
	certs
		.map((c) =>
			c.revoked_on
				? indexTxt([c]).trimEnd()
				: ["V", utcTime(c.not_after), "", c.serial, "unknown", "/CN=valid"].join("\t"),
		)
		.map((line) => `${line}\n`)
		.join("");

/** openssl configuration of `openssl ca -gencrl` */
export const crlConfig = (dir) =>
	[
		"[ca]",
		"default_ca = npmos_ca",
		"[npmos_ca]",
		`database = ${dir}/index.txt`,
		`crlnumber = ${dir}/crlnumber`,
		"default_md = sha256",
		"unique_subject = no",
		"crl_extensions = crl_ext",
		"[crl_ext]",
		"authorityKeyIdentifier = keyid:always",
		"",
	].join("\n");

/** PEM blocks of a type in a text (certificates by default) */
export const splitPem = (text, type = "CERTIFICATE") => {
	const re = new RegExp(`-----BEGIN ${type}-----[\\s\\S]+?-----END ${type}-----`, "g");
	return (String(text || "").match(re) || []).map((block) => `${block}\n`);
};

/**
 * What NPMOS keeps of a certificate.
 * @param {string} pem
 */
export const parseCert = (pem) => {
	let cert;
	try {
		cert = new X509Certificate(pem);
	} catch (err) {
		throw new PkiError(`Not a certificate: ${err.message}`);
	}
	const key = cert.publicKey;
	const details = key.asymmetricKeyDetails || {};
	let keyType = key.asymmetricKeyType;
	if (keyType === "ec")
		keyType = `ec-${{ prime256v1: "p256", secp384r1: "p384" }[details.namedCurve] || details.namedCurve}`;
	if (keyType === "rsa") keyType = `rsa-${details.modulusLength}`;
	return {
		cert,
		serial: cert.serialNumber.toUpperCase(),
		notBefore: new Date(cert.validFrom),
		notAfter: new Date(cert.validTo),
		fingerprint: cert.fingerprint256,
		isCa: cert.ca,
		keyType,
		selfSigned: cert.checkIssued(cert) && cert.verify(cert.publicKey),
		sans: parseSans(cert.subjectAltName),
		subject: parseSubject(cert.subject),
	};
};

/** "C=RU\nO=Org\nCN=name" (as Node prints it) → {country, organization, common_name} */
export const parseSubject = (text) => {
	const names = Object.fromEntries(Object.entries(SUBJECT_FIELDS).map(([field, name]) => [name, field]));
	const result = {};
	for (const line of String(text || "").split("\n")) {
		const at = line.indexOf("=");
		const field = names[line.slice(0, at)];
		if (at > 0 && field) result[field] = line.slice(at + 1);
	}
	return result;
};

/** "DNS:a, IP Address:1.2.3.4, email:x@y" → {dns, ip, email} */
export const parseSans = (text) => {
	const sans = { dns: [], ip: [], email: [] };
	for (const part of String(text || "").split(/,\s*/)) {
		const at = part.indexOf(":");
		const kind = part.slice(0, at);
		const value = part.slice(at + 1);
		if (kind === "DNS") sans.dns.push(value);
		else if (kind === "IP Address") sans.ip.push(value);
		else if (kind === "email") sans.email.push(value);
	}
	return sans;
};

/** a random password of a .p12 that is easy to type: 4 groups of 4 */
export const randomPassword = () => {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
	const bytes = randomBytes(16);
	const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
	return [0, 4, 8, 12].map((i) => chars.slice(i, i + 4).join("")).join("-");
};
