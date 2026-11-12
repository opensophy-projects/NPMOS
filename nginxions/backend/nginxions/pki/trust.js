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
 * Checks a regular expression of a rule (nginx runs it, PCRE) without compiling it here: brackets and groups are
 * balanced, and no group that repeats holds a repetition of its own ((a+)+, (x*)*...), the pattern whose
 * backtracking grows exponentially (ReDoS on each TLS handshake). nginx -t checks the rest when the host is saved.
 * @param {string} re
 * @returns {string|null} what is wrong, or null
 */
export const regexProblem = (re) => {
	const groups = [{ quantified: false }];
	let last = null; // what a quantifier would repeat: "atom" or a closed group
	for (let i = 0; i < re.length; i++) {
		const c = re[i];
		if (c === "\\") {
			if (i + 1 >= re.length) return "a \\ at the end";
			i++;
			last = { quantified: false };
		} else if (c === "[") {
			let j = i + 1;
			if (re[j] === "^") j++;
			if (re[j] === "]") j++;
			while (j < re.length && re[j] !== "]") j += re[j] === "\\" ? 2 : 1;
			if (j >= re.length) return "a [ without ]";
			i = j;
			last = { quantified: false };
		} else if (c === "]") {
			last = { quantified: false };
		} else if (c === "(") {
			groups.push({ quantified: false });
			last = null;
			// (?:...), (?=...), (?!...), (?<=...), (?<!...), (?<name>...), (?i) and (?i:...): not a quantifier
			if (re[i + 1] === "?") {
				const m = /^\?(?:[:=!>|]|<[=!]|<[A-Za-z_]\w*>|P<[A-Za-z_]\w*>|'[A-Za-z_]\w*'|[A-Za-z^-]*[:)])/.exec(
					re.slice(i + 1),
				);
				if (!m) return `an unknown group at ${i + 1}`;
				i += m[0].length;
				if (m[0].endsWith(")")) groups.pop();
			}
		} else if (c === ")") {
			if (groups.length === 1) return "a ) without (";
			last = groups.pop();
		} else if (c === "*" || c === "+" || c === "?" || c === "{") {
			let end = i;
			if (c === "{") {
				const m = /^\{(\d+)(,(\d*))?\}/.exec(re.slice(i));
				if (!m) {
					last = { quantified: false };
					continue;
				}
				end = i + m[0].length - 1;
			}
			if (!last) return `nothing to repeat at ${i + 1}`;
			const repeats = c !== "?" && !(c === "{" && /^\{(\d+)(,\1)?\}$/.test(re.slice(i, end + 1)));
			if (repeats && last.quantified)
				return "a repeated group holds a repetition of its own, like (a+)+: its backtracking grows exponentially";
			if (repeats) groups[groups.length - 1].quantified = true;
			i = end;
			if (re[i + 1] === "?" || re[i + 1] === "+") i++;
			last = null;
		} else if (c === "|") {
			last = null;
		} else {
			last = { quantified: false };
		}
	}
	return groups.length === 1 ? null : "a ( without )";
};

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
 * @param {Array} cas  all rows of nginxions_pki_ca
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
