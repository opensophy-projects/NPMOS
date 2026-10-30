// Objects of the policy in the database and the policy built from them (v1beta2 terms): the default
// policy, a rule per protected proxy host and location, every object.
import db from "../../../db.js";
import { learningExceptions } from "../../learning/policy.js";
import { ruleHost } from "../../learning/model.js";
import { getSetting } from "../../settings.js";
import { BUILTIN, builtinSpec, DEFAULT_POLICY, KINDS, RULE_FIELDS } from "./model.js";

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);

/** creates the built-in objects and brings them up to date (they change with NPMOS) */
export const seedBuiltins = async () => {
	const knex = db();
	const now = new Date();
	for (const [name, { kind }] of Object.entries(BUILTIN)) {
		const spec = JSON.stringify(builtinSpec(name));
		const row = await knex("npmos_waf_object").where({ kind, name }).first();
		if (!row) {
			await knex("npmos_waf_object").insert({
				kind,
				name,
				spec,
				builtin: true,
				description: "",
				created_on: now,
				modified_on: now,
			});
		} else if (JSON.stringify(parse(row.spec)) !== spec || !row.builtin) {
			await knex("npmos_waf_object").where("id", row.id).update({ spec, builtin: true, modified_on: now });
		}
	}
};

/** @returns {Promise<Array<{id, kind, name, description, spec, builtin, created_on, modified_on}>>} */
export const listObjects = async () =>
	(await db()("npmos_waf_object").orderBy([{ column: "kind" }, { column: "builtin", order: "desc" }, "name"])).map(
		(row) => ({ ...row, spec: parse(row.spec), builtin: !!row.builtin }),
	);

/**
 * References of a rule ({field: id | [id]}) → names; fields not given stay undefined (inherited).
 */
export const resolveRule = (refs, byId) => {
	const out = {};
	for (const [field, { many }] of Object.entries(RULE_FIELDS)) {
		const value = refs?.[field];
		if (value === undefined) continue;
		if (many) out[field] = (Array.isArray(value) ? value : []).map((id) => byId.get(id)?.name).filter(Boolean);
		else out[field] = value === null ? "" : (byId.get(value)?.name ?? "");
	}
	return out;
};

/** names → ids (built-in names of templates and the default policy) */
export const idsOf = (refs, objects) => {
	const out = {};
	for (const [field, { kind, many }] of Object.entries(RULE_FIELDS)) {
		const value = refs?.[field];
		if (value === undefined) continue;
		const id = (name) => objects.find((o) => o.kind === kind && o.name === name)?.id;
		if (many) out[field] = (value || []).map(id).filter((v) => v !== undefined);
		else out[field] = value === null ? null : (id(value) ?? null);
	}
	return out;
};

/** the default policy with ids (setting waf.policy; before it is saved, the built-in defaults) */
export const getDefaultPolicy = async (objects) => {
	const saved = await getSetting("waf.policy");
	return saved ?? { mode: DEFAULT_POLICY.mode, ...idsOf(DEFAULT_POLICY, objects) };
};

/**
 * Objects of a location: its own fields replace those of the host; exceptions add up (default
 * policy, host, location).
 */
export const locationRule = (host, location) => {
	const rule = { ...host, ...location };
	// a location without practices is not left unprotected
	if (!location.threatPreventionPractices?.length) rule.threatPreventionPractices = host.threatPreventionPractices;
	if (rule.threatPreventionPractices === undefined) delete rule.threatPreventionPractices;
	if (host.exceptions !== undefined || location.exceptions !== undefined) {
		rule.exceptions = [...new Set([...(host.exceptions ?? []), ...(location.exceptions ?? [])])];
	}
	return rule;
};

const parseJson = (value) => (typeof value === "string" ? JSON.parse(value) : value) || [];

/**
 * The policy of NPMOS in v1beta2 terms.
 * Every object is in it (the expert fragment may refer to any). A protected host gets a rule per
 * domain (and per protected location) with its mode; its practices get the host's minimum
 * confidence (a copy "<practice>.<confidence>" when it differs from the practice); other objects
 * are the host's own or, if it has none, those of the default policy (the agent takes them).
 * Exceptions of a host come on top of those of the default policy.
 * A candidate (preview of a change) replaces what is stored: the objects, the default policy, the
 * objects of hosts ({<proxy host id>: objects}).
 * @param   {{objects?: object[], policy?: object, hostObjects?: Record<number, object|null>}} [candidate]
 * @returns {Promise<{doc: object, hosts: number}>}
 */
export const buildDoc = async (candidate = {}) => {
	const knex = db();
	const objects = candidate.objects ?? (await listObjects());
	const byId = new Map(objects.map((o) => [o.id, o]));
	const policy = candidate.policy ?? (await getDefaultPolicy(objects));
	const defaults = resolveRule(policy, byId);
	const doc = {
		policies: { default: { mode: policy.mode, ...defaults }, specificRules: [] },
	};
	for (const section of Object.values(KINDS)) doc[section] = [];
	for (const o of objects) doc[KINDS[o.kind]].push({ name: o.name, ...o.spec });

	const practices = new Map(doc.threatPreventionPractices.map((p) => [p.name, p]));
	/** the practice with a minimum confidence */
	const withConfidence = (name, confidence) => {
		const practice = practices.get(name);
		if (!practice || !confidence || practice.webAttacks?.minimumConfidence === confidence) return name;
		const copy = `${name}.${confidence}`;
		if (!practices.has(copy)) {
			const derived = structuredClone(practice);
			derived.name = copy;
			derived.webAttacks.minimumConfidence = confidence;
			practices.set(copy, derived);
			doc.threatPreventionPractices.push(derived);
		}
		return copy;
	};

	const proxyHosts = await knex("proxy_host")
		.select("id", "domain_names", "locations")
		.where({ is_deleted: 0, enabled: 1 })
		.orderBy("id");
	const hostRows = new Map((await knex("npmos_waf_host").select()).map((r) => [r.proxy_host_id, r]));
	const locationRows = new Map();
	for (const row of await knex("npmos_waf_location").select()) {
		locationRows.set(row.proxy_host_id, [...(locationRows.get(row.proxy_host_id) || []), row]);
	}

	let hosts = 0;
	const addRules = (base, domains, mode, confidence, own) => {
		const rule = {
			mode,
			threatPreventionPractices: (own.threatPreventionPractices ?? defaults.threatPreventionPractices ?? []).map(
				(p) => withConfidence(p, confidence),
			),
		};
		for (const field of [
			"accessControlPractices",
			"triggers",
			"customResponse",
			"sourceIdentifiers",
			"trustedSources",
		]) {
			if (own[field] !== undefined) rule[field] = own[field];
		}
		if (own.exceptions !== undefined) {
			rule.exceptions = [...new Set([...(defaults.exceptions ?? []), ...own.exceptions])];
		}
		domains.forEach((host, index) => {
			doc.policies.specificRules.push({ name: index > 0 ? `${base}.${index}` : base, host, ...rule });
		});
	};

	for (const proxyHost of proxyHosts) {
		const domains = parseJson(proxyHost.domain_names);
		const locations = parseJson(proxyHost.locations);
		const host = hostRows.get(proxyHost.id);
		const refs =
			candidate.hostObjects && proxyHost.id in candidate.hostObjects
				? candidate.hostObjects[proxyHost.id]
				: parse(host?.objects);
		const own = resolveRule(refs || {}, byId);
		// names as open-appsec-npm, so that its installations are imported as they are
		if (host?.enabled) {
			addRules(
				`npm-managed-specific-rule-proxyhost-${proxyHost.id}`,
				domains,
				host.mode,
				host.minimum_confidence,
				own,
			);
			hosts++;
		}
		for (const location of locationRows.get(proxyHost.id) || []) {
			const index = locations.findIndex((l) => l.path === location.path);
			if (index === -1) continue;
			addRules(
				`npm-managed-specific-rule-proxyhost-${proxyHost.id}-${index}`,
				domains.map((domain) => `${domain}${location.path}`),
				location.enabled ? location.mode : "inactive",
				location.minimum_confidence,
				locationRule(own, resolveRule(parse(location.objects) || {}, byId)),
			);
		}
	}

	// learning (phase 8): exceptions of labels in force, on every rule of their host (domains and locations)
	const learned = candidate.learning ?? (await learningExceptions());
	if (learned.size) {
		for (const rule of doc.policies.specificRules) {
			const extra = learned.get(ruleHost(rule.name)?.hostId);
			if (!extra) continue;
			rule.exceptions = [
				...new Set([...(rule.exceptions ?? defaults.exceptions ?? []), ...extra.map((e) => e.name)]),
			];
		}
		const added = new Set();
		for (const e of [...learned.values()].flat()) {
			if (added.has(e.name)) continue;
			added.add(e.name);
			doc.exceptions.push(e);
		}
	}
	return { doc, hosts };
};

/** what a rollback restores: objects (not built-in), default policy, WAF objects of hosts */
export const snapshot = async () => {
	const knex = db();
	return {
		objects: (await listObjects())
			.filter((o) => !o.builtin)
			.map(({ id, kind, name, description, spec }) => ({ id, kind, name, description, spec })),
		policy: await getSetting("waf.policy"),
		hosts: (await knex("npmos_waf_host").select("proxy_host_id", "objects")).map((h) => ({
			proxy_host_id: h.proxy_host_id,
			objects: parse(h.objects) ?? null,
		})),
		locations: (await knex("npmos_waf_location").select("proxy_host_id", "path", "objects"))
			.filter((l) => l.objects)
			.map((l) => ({ proxy_host_id: l.proxy_host_id, path: l.path, objects: parse(l.objects) })),
	};
};
