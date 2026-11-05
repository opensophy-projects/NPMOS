// The term of the TLS certificates of the hosts and when one needs attention. Public certificates get shorter
// (CA/Browser Forum: 200 days from March 2026, 100 from 2027, 47 from 2029; Let's Encrypt: 90 days, 64 from 2027,
// 45 from 2028, "shortlived" about 6 days today), so a fixed "14 days left" warns about every certificate that
// renews itself on time. A certificate NPMOS renews (ACME, renewal on) needs attention only once half of its
// renewal window has passed without a renewal; one replaced by hand gets 14 days, or a third of a shorter term.
import { X509Certificate } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import db from "../db.js";

export const DAY = 86400000;
/** a certificate replaced by hand: warn this many days ahead (a third of the term when that is shorter) */
export const MANUAL_WARN_DAYS = 14;
/** certbot renews a third of the term ahead, at most 30 days */
const CERTBOT_MAX_WINDOW_DAYS = 30;

const renewOn = () => !/^(false|0|no|off)$/i.test(process.env.ACME_RENEW || "true");
const renewDays = () => Number.parseInt(process.env.ACME_RENEW_DAYS || "0", 10) || 0;

/** how long before the end a certificate is renewed: the days of Settings -> ACME, or what certbot does */
export const renewWindow = (lifetime, days = renewDays()) =>
	days > 0 ? days * DAY : Math.min(CERTBOT_MAX_WINDOW_DAYS * DAY, (lifetime ?? 90 * DAY) / 3);

/**
 * The moment a certificate needs attention (ms since the epoch), null without an end.
 * @param {{notBefore?: string|Date|null, notAfter?: string|Date|null, auto: boolean, renewDays?: number}} c
 */
export const attentionAt = ({ notBefore, notAfter, auto, renewDays: days }) => {
	const end = notAfter ? new Date(notAfter).getTime() : Number.NaN;
	if (Number.isNaN(end)) return null;
	const start = notBefore ? new Date(notBefore).getTime() : Number.NaN;
	const lifetime = !Number.isNaN(start) && end > start ? end - start : null;
	if (auto) return end - renewWindow(lifetime, days) / 2;
	const lead = lifetime ? Math.min(MANUAL_WARN_DAYS * DAY, lifetime / 3) : MANUAL_WARN_DAYS * DAY;
	return end - lead;
};

const fileOf = (cert) =>
	cert.provider === "letsencrypt"
		? `/data/tls/certbot/live/npm-${cert.id}/fullchain.pem`
		: `/data/tls/custom/npm-${cert.id}/fullchain.pem`;

/** validity of the first certificate of a PEM file, read again only when the file changes */
const cache = new Map();
const validity = async (file) => {
	try {
		const { mtimeMs } = await stat(file);
		const hit = cache.get(file);
		if (hit && hit.mtimeMs === mtimeMs) return hit.value;
		const pem = await readFile(file, "utf8");
		const first = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
		const x509 = first ? new X509Certificate(first[0]) : null;
		const value = x509 ? { notBefore: new Date(x509.validFrom), notAfter: new Date(x509.validTo) } : null;
		cache.set(file, { mtimeMs, value });
		return value;
	} catch {
		return null;
	}
};

/** the term of a certificate row of NPMplus: start and end, renewed by NPMOS or not, when it needs attention */
export const termOf = async (cert) => {
	const file = await validity(fileOf(cert));
	const notBefore = file?.notBefore ?? null;
	const notAfter = file?.notAfter ?? (cert.expires_on ? new Date(cert.expires_on) : null);
	const auto = cert.provider === "letsencrypt" && renewOn();
	const attention = attentionAt({ notBefore, notAfter, auto });
	const lifetime = notBefore && notAfter ? notAfter.getTime() - notBefore.getTime() : null;
	return {
		not_before: notBefore ? notBefore.toISOString() : null,
		not_after: notAfter ? notAfter.toISOString() : null,
		lifetime_days: lifetime ? Math.round(lifetime / DAY) : null,
		auto_renew: auto,
		renew_from: auto && notAfter ? new Date(notAfter.getTime() - renewWindow(lifetime)).toISOString() : null,
		attention_from: attention === null ? null : new Date(attention).toISOString(),
	};
};

/** terms of all TLS certificates of the hosts: {<id>: term} */
export const certificateTerms = async () => {
	const rows = await db()("certificate")
		.where({ is_deleted: 0 })
		.whereNot("provider", "mtls")
		.select("id", "provider", "expires_on");
	const out = {};
	for (const cert of rows) out[cert.id] = await termOf(cert);
	return out;
};
