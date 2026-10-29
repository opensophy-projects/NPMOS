// Pure parts of mTLS (unit tested): the CAs a host trusts and the rules on client certificates as
// nginx expressions. See mtls.js.
import { splitPem } from "./x509.js";

export const RULE_OPS = ["one_of", "regex"];
/** fields of rules: part of $ssl_client_s_dn, or $ssl_client_serial */
export const RULE_FIELDS = {
	common_name: "CN",
	organization: "O",
	organizational_unit: "OU",
	email: "emailAddress",
	serial: null,
};

export const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Variable and regular expression of nginx for a rule.
 * @param {{field: string, op: "one_of"|"regex", values: string[]}} rule
 */
export const ruleRegex = (rule) => {
	const alternatives = rule.op === "regex" ? `(?:${rule.values[0]})` : `(?:${rule.values.map(escapeRe).join("|")})`;
	if (rule.field === "serial") {
		return { variable: "$ssl_client_serial", regex: `^${alternatives}$` };
	}
	return { variable: "$ssl_client_s_dn", regex: `(^|,)${RULE_FIELDS[rule.field]}=${alternatives}(,|$)` };
};

/**
 * CAs of a host: certificates for the CA file, CRLs, issuer DNs (null: no issuer check).
 * A root brings its intermediate CAs (their certificates may be sent by clients or not), an
 * intermediate brings its root (nginx needs the chain up to a root).
 * @param {number[]} caIds  selected
 * @param {Array} cas  all rows of npmos_pki_ca
 */
export const trustSet = (caIds, cas) => {
	const byId = new Map(cas.map((ca) => [ca.id, ca]));
	const ids = new Set();
	const issuers = new Set();
	let external = false;
	for (const id of caIds) {
		const ca = byId.get(id);
		if (!ca) continue;
		ids.add(ca.id);
		if (ca.kind === "external") {
			external = true;
		} else if (ca.kind === "root") {
			issuers.add(ca.subject_dn);
			for (const child of cas.filter((c) => c.parent_id === ca.id)) {
				ids.add(child.id);
				issuers.add(child.subject_dn);
			}
		} else {
			issuers.add(ca.subject_dn);
			let parent = byId.get(ca.parent_id);
			while (parent) {
				ids.add(parent.id);
				parent = byId.get(parent.parent_id);
			}
		}
	}
	const members = [...ids].map((id) => byId.get(id));
	return {
		ids: [...ids],
		certs: members.map((ca) => splitPem(ca.cert_pem).join("")).join(""),
		crls: members.every((ca) => ca.crl_pem) ? members.map((ca) => `${ca.crl_pem.trim()}\n`).join("") : null,
		issuers: external ? null : [...issuers],
	};
};
