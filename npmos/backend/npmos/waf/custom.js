// WAF -> Policy (expert): the administrator's YAML fragments merged over the policy NPMOS generates
// from its objects. A fragment may use either syntax of local_policy.yaml (v1beta1 as
// open-appsec-npm, or v1beta2); it is merged in v1beta2 terms (objects/format.js).
//
// Merge rules:
//   - lists of named objects (practices, log triggers, responses, exceptions, trusted sources, source
//     identifiers, specific rules): an object with the name of a generated one replaces it, others
//     are added;
//   - policies.default: keys of the fragment replace the generated ones.
// Exceptions listed in policies.default apply to every host whose rule has none of its own, e.g.
// trusted IPs or countries as in docs/tutor.md.
import YAML from "yaml";
import db from "../../db.js";
import errs from "../../lib/error.js";
import { fromV1, SECTIONS_V2 } from "./objects/format.js";

const NAMED_SECTIONS = [
	"practices",
	"log-triggers",
	"custom-responses",
	"exceptions",
	"trusted-sources",
	"source-identifiers",
	...SECTIONS_V2.filter((s) => s !== "exceptions"),
];
const MAX_BYTES = 256 * 1024;

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

const checkNamedList = (list, where) => {
	if (!Array.isArray(list)) {
		throw new errs.ValidationError(`${where}: must be a list`);
	}
	const seen = new Set();
	list.forEach((item, i) => {
		if (!isObject(item) || typeof item.name !== "string" || !item.name) {
			throw new errs.ValidationError(`${where}[${i}]: every item needs a name`);
		}
		if (seen.has(item.name)) {
			throw new errs.ValidationError(`${where}: name ${item.name} is used twice`);
		}
		seen.add(item.name);
	});
};

/**
 * @param   {string} content  YAML
 * @returns {object}          the parsed fragment in v1beta2 terms ({} for an empty one)
 */
const parseCustom = (content) => {
	if (typeof content !== "string") {
		throw new errs.ValidationError("The policy fragment must be text");
	}
	if (Buffer.byteLength(content) > MAX_BYTES) {
		throw new errs.ValidationError("The policy fragment is larger than 256 KB");
	}
	let doc;
	try {
		doc = YAML.parse(content, { prettyErrors: true, uniqueKeys: true });
	} catch (err) {
		throw new errs.ValidationError(`YAML: ${err.message}`);
	}
	if (doc === null || doc === undefined) {
		return {};
	}
	if (!isObject(doc)) {
		throw new errs.ValidationError("The policy fragment must be a mapping (keys of local_policy.yaml)");
	}
	for (const key of Object.keys(doc)) {
		if (key === "apiVersion") {
			if (!["v1beta1", "v1beta2"].includes(doc.apiVersion)) {
				throw new errs.ValidationError("apiVersion: v1beta1 or v1beta2");
			}
		} else if (key === "policies") {
			if (!isObject(doc.policies)) {
				throw new errs.ValidationError("policies: must be a mapping");
			}
			for (const k of Object.keys(doc.policies)) {
				if (k !== "default" && k !== "specific-rules" && k !== "specificRules") {
					throw new errs.ValidationError(`policies.${k}: unknown key (default, specificRules)`);
				}
			}
			if (doc.policies.default !== undefined && !isObject(doc.policies.default)) {
				throw new errs.ValidationError("policies.default: must be a mapping");
			}
			for (const k of ["specific-rules", "specificRules"]) {
				if (doc.policies[k] !== undefined) {
					checkNamedList(doc.policies[k], `policies.${k}`);
				}
			}
		} else if (NAMED_SECTIONS.includes(key)) {
			checkNamedList(doc[key], key);
		} else {
			throw new errs.ValidationError(`${key}: unknown section (policies, ${NAMED_SECTIONS.join(", ")})`);
		}
	}
	return fromV1(doc);
};

const mergeNamed = (generated = [], custom = []) => {
	const result = generated.map((item) => custom.find((c) => c.name === item.name) || item);
	for (const item of custom) {
		if (!generated.some((g) => g.name === item.name)) {
			result.push(item);
		}
	}
	return result;
};

/**
 * @param   {object} policy  generated policy in v1beta2 terms (not changed)
 * @param   {object} custom  parsed fragment (parseCustom)
 * @returns {object}
 */
const mergeCustom = (policy, custom) => {
	const result = structuredClone(policy);
	if (custom.policies) {
		result.policies.default = { ...result.policies.default, ...(custom.policies.default || {}) };
		result.policies.specificRules = mergeNamed(result.policies.specificRules, custom.policies.specificRules);
	}
	for (const key of SECTIONS_V2) {
		if (custom[key]) {
			result[key] = mergeNamed(result[key], custom[key]);
		}
	}
	return result;
};

/** @returns {Promise<{id, content, comment, user_id, created_on}|undefined>} the fragment in force */
const getCurrentCustom = () => db()("npmos_waf_custom_policy").orderBy("id", "desc").first();

export { getCurrentCustom, mergeCustom, parseCustom };
