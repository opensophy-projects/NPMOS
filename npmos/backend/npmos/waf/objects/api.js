// WAF → Policy: objects of the policy, the default policy, preview of a change (validation and the
// diff of local_policy.yaml), versions with rollback, import and export of YAML (ADR-0008).
// Every change is applied at once (as the WAF settings of hosts) and saved as a version.
import YAML from "yaml";
import db from "../../../db.js";
import internalAuditLog from "../../../internal/audit-log.js";
import errs from "../../../lib/error.js";
import { setSetting } from "../../settings.js";
import { diffLines } from "../expert.js";
import { buildPolicy, getPolicyState, readPolicyFile, regenerateNow, render } from "../policy.js";
import { asV2, fromV1, toV1 } from "./format.js";
import { BUILTIN_PREFIX, KINDS, NAME, normalize, POLICY_MODES, RULE_FIELDS, TEMPLATES } from "./model.js";
import { getDefaultPolicy, idsOf, listObjects, snapshot } from "./store.js";

const VERSIONS_SHOWN = 50;
const SECTION_KIND = Object.fromEntries(Object.entries(KINDS).map(([kind, section]) => [section, kind]));

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);

/**
 * Checks the references of a rule (default policy, host): every id is an object of the right kind.
 * @returns {object} the references, only the known fields
 */
export const checkRefs = (refs, objects, what) => {
	const byId = new Map(objects.map((o) => [o.id, o]));
	const out = {};
	for (const [field, { kind, many }] of Object.entries(RULE_FIELDS)) {
		const value = refs?.[field];
		if (value === undefined) continue;
		const ids = many ? value : value === null ? [] : [value];
		if (many && !Array.isArray(value)) throw new errs.ValidationError(`${what}: ${field} must be a list`);
		for (const id of ids) {
			if (byId.get(id)?.kind !== kind) {
				throw new errs.ValidationError(`${what}: ${field}: no ${kind} object with id ${id}`);
			}
		}
		out[field] = many ? [...new Set(value)] : value;
	}
	return out;
};

/** the default policy to save: mode and references */
const checkPolicy = (policy, objects) => {
	if (!POLICY_MODES.includes(policy?.mode)) {
		throw new errs.ValidationError(`default policy: mode must be one of ${POLICY_MODES.join(", ")}`);
	}
	return { mode: policy.mode, ...checkRefs(policy, objects, "default policy") };
};

/** the objects a host uses: a template (built-in objects) or references; null: as the default policy */
export const hostObjects = (raw, objects) => {
	if (raw === null || raw === undefined) return null;
	// the API client of the GUI sends snake_case keys (threat_prevention_practices)
	const input = Object.fromEntries(
		Object.entries(raw).map(([key, value]) => [key.replace(/_([a-z])/g, (_, c) => c.toUpperCase()), value]),
	);
	if (input.template !== undefined) {
		const template = TEMPLATES[input.template];
		if (!template) {
			throw new errs.ValidationError(
				`WAF: unknown template ${input.template} (${Object.keys(TEMPLATES).join(", ")})`,
			);
		}
		return { template: input.template, ...idsOf(template, objects) };
	}
	return checkRefs(input, objects, "WAF objects of the host");
};

/** an object to save: name and specification checked, the specification completed */
const checkObject = (input, objects, id) => {
	const kind = input.kind;
	if (!KINDS[kind]) throw new errs.ValidationError(`unknown kind ${kind}`);
	if (!NAME.test(input.name || "")) {
		throw new errs.ValidationError(`name: lowercase letters, digits, ".", "_", "-", up to 100 characters`);
	}
	if (input.name.startsWith(BUILTIN_PREFIX)) {
		throw new errs.ValidationError(`name: "${BUILTIN_PREFIX}" is reserved for the built-in objects`);
	}
	if (objects.some((o) => o.kind === kind && o.name === input.name && o.id !== id)) {
		throw new errs.ValidationError(`name: ${input.name} is taken`);
	}
	const { spec, errors } = normalize(kind, input.spec);
	if (errors) throw new errs.ValidationError(`${input.name}: ${errors.join("; ")}`);
	if (kind === "trusted_sources") {
		const missing = (spec.sourcesIdentifiers || []).filter(
			(name) => !objects.some((o) => o.kind === "source_identifiers" && o.name === name),
		);
		if (missing.length)
			throw new errs.ValidationError(`${input.name}: no source identifiers ${missing.join(", ")}`);
	}
	return { kind, name: input.name, description: (input.description || "").slice(0, 500), spec };
};

/** who uses an object: the default policy, hosts (by id), trusted sources (by name) */
const usersOf = async (object, objects) => {
	const users = [];
	const refers = (refs) =>
		Object.entries(RULE_FIELDS).some(
			([field, { kind, many }]) =>
				kind === object.kind &&
				(many ? (refs?.[field] || []).includes(object.id) : refs?.[field] === object.id),
		);
	if (refers(await getDefaultPolicy(objects))) users.push("default");
	const hosts = await db()("npmos_waf_host")
		.join("proxy_host", "proxy_host.id", "npmos_waf_host.proxy_host_id")
		.where("proxy_host.is_deleted", 0)
		.select("npmos_waf_host.proxy_host_id", "npmos_waf_host.objects");
	for (const host of hosts) {
		if (refers(parse(host.objects))) users.push(`host:${host.proxy_host_id}`);
	}
	const locations = await db()("npmos_waf_location")
		.join("proxy_host", "proxy_host.id", "npmos_waf_location.proxy_host_id")
		.where("proxy_host.is_deleted", 0)
		.whereNotNull("npmos_waf_location.objects")
		.select("npmos_waf_location.proxy_host_id", "npmos_waf_location.path", "npmos_waf_location.objects");
	for (const l of locations) {
		if (refers(parse(l.objects))) users.push(`host:${l.proxy_host_id}${l.path}`);
	}
	if (object.kind === "source_identifiers") {
		for (const o of objects) {
			if (o.kind === "trusted_sources" && (o.spec.sourcesIdentifiers || []).includes(object.name)) {
				users.push(`object:${o.name}`);
			}
		}
	}
	return users;
};

const getObject = (objects, id) => {
	const object = objects.find((o) => o.id === id);
	if (!object) throw new errs.ItemNotFoundError(id);
	return object;
};

// ---------------------------------------------------------------- versions

const versionCount = async () => Number((await db()("npmos_waf_policy_version").count("id as count").first()).count);

const addVersion = async (access, comment) => {
	await db()("npmos_waf_policy_version").insert({
		created_on: new Date(),
		user_id: access ? access.token.getUserId(1) : null,
		comment: comment.slice(0, 255),
		state: JSON.stringify(await snapshot()),
	});
};

/** before the first change: the state as it was, so that it can be restored */
const ensureBaseline = async () => {
	if ((await versionCount()) === 0) await addVersion(null, "initial");
};

/**
 * After a change: a version, the audit log, the policy regenerated and applied.
 * @returns {Promise<object>} the state of the policy
 */
const changed = async (access, comment, meta = {}) => {
	await addVersion(access, comment);
	await internalAuditLog.add(access, {
		action: "updated",
		object_type: "waf",
		meta: { name: "WAF policy", comment, ...meta },
	});
	await regenerateNow({ force: true });
	return getPolicyState();
};

/**
 * Restores objects, default policy and objects of hosts of a snapshot. Objects are matched by kind
 * and name (ids of deleted objects are not reused): references are mapped to the current ids.
 */
const restore = async (state) => {
	const knex = db();
	const now = new Date();
	await knex.transaction(async (trx) => {
		const current = (await trx("npmos_waf_object").select()).map((r) => ({ ...r, builtin: !!r.builtin }));
		const ids = new Map();
		for (const o of state.objects) {
			const row = current.find((c) => c.kind === o.kind && c.name === o.name);
			const values = { description: o.description || "", spec: JSON.stringify(o.spec), modified_on: now };
			if (row && !row.builtin) {
				await trx("npmos_waf_object").where("id", row.id).update(values);
				ids.set(o.id, row.id);
			} else if (!row) {
				const [inserted] = await trx("npmos_waf_object")
					.insert({ kind: o.kind, name: o.name, builtin: false, created_on: now, ...values })
					.returning("id");
				ids.set(o.id, typeof inserted === "object" ? inserted.id : inserted);
			}
		}
		const keep = new Set(state.objects.map((o) => `${o.kind}/${o.name}`));
		const removed = current.filter((c) => !c.builtin && !keep.has(`${c.kind}/${c.name}`)).map((c) => c.id);
		if (removed.length) await trx("npmos_waf_object").whereIn("id", removed).delete();

		const map = (refs) => {
			if (!refs) return refs ?? null;
			const out = { ...refs };
			for (const [field, { many }] of Object.entries(RULE_FIELDS)) {
				if (out[field] === undefined || out[field] === null) continue;
				out[field] = many ? out[field].map((id) => ids.get(id) ?? id) : (ids.get(out[field]) ?? out[field]);
			}
			return out;
		};
		await trx("npmos_setting")
			.insert({ key: "waf.policy", value: JSON.stringify(map(state.policy)), modified_on: now })
			.onConflict("key")
			.merge();
		const hosts = new Map(state.hosts.map((h) => [h.proxy_host_id, h.objects]));
		for (const row of await trx("npmos_waf_host").select("proxy_host_id")) {
			const objects = map(hosts.get(row.proxy_host_id) ?? null);
			await trx("npmos_waf_host")
				.where("proxy_host_id", row.proxy_host_id)
				.update({ objects: objects ? JSON.stringify(objects) : null });
		}
		// versions before location objects have none
		const locations = new Map((state.locations ?? []).map((l) => [`${l.proxy_host_id} ${l.path}`, l.objects]));
		for (const row of await trx("npmos_waf_location").select("proxy_host_id", "path")) {
			const objects = map(locations.get(`${row.proxy_host_id} ${row.path}`) ?? null);
			await trx("npmos_waf_location")
				.where({ proxy_host_id: row.proxy_host_id, path: row.path })
				.update({ objects: objects ? JSON.stringify(objects) : null });
		}
	});
};

// ---------------------------------------------------------------- preview

/**
 * The state with a change, for the preview: {objects, policy, hostObjects}.
 * @param {{object?: object, id?: number, delete?: number, policy?: object, host?: {id: number, objects: object|null}}} change
 */
const candidateOf = async (change, objects) => {
	if (change.object) {
		const id = change.id ?? 0;
		if (id) {
			const old = getObject(objects, id);
			if (old.builtin) throw new errs.ValidationError(`${old.name} is built in and read-only`);
		}
		const object = { id, builtin: false, ...checkObject(change.object, objects, id) };
		return { objects: id ? objects.map((o) => (o.id === id ? object : o)) : [...objects, object] };
	}
	if (change.delete) {
		const object = getObject(objects, change.delete);
		const users = await usersOf(object, objects);
		if (users.length) throw new errs.ValidationError(`${object.name} is used: ${users.join(", ")}`);
		return { objects: objects.filter((o) => o.id !== change.delete) };
	}
	if (change.policy) return { objects, policy: checkPolicy(change.policy, objects) };
	if (change.host) return { objects, hostObjects: { [change.host.id]: hostObjects(change.host.objects, objects) } };
	return { objects };
};

// ---------------------------------------------------------------- import, export

/** the YAML to export: the default policy and the objects (not the generated rules of hosts) */
const exportDoc = async (format) => {
	const objects = await listObjects();
	const policy = await getDefaultPolicy(objects);
	const byId = new Map(objects.map((o) => [o.id, o]));
	const used = new Set();
	const defaults = { mode: policy.mode };
	for (const [field, { many }] of Object.entries(RULE_FIELDS)) {
		const value = policy[field];
		if (value === undefined || value === null) continue;
		const names = (many ? value : [value]).map((id) => byId.get(id)?.name).filter(Boolean);
		for (const id of many ? value : [value]) used.add(id);
		defaults[field] = many ? names : names[0];
	}
	const doc = { policies: { default: defaults, specificRules: [] } };
	for (const section of Object.values(KINDS)) doc[section] = [];
	for (const o of objects) {
		if (!o.builtin || used.has(o.id)) doc[KINDS[o.kind]].push({ name: o.name, ...o.spec });
	}
	return format === "v1beta1" ? toV1(doc) : asV2(doc);
};

/**
 * What an import does: objects to create or update (by kind and name), the default policy.
 * Built-in objects of the file are skipped; rules of hosts (specificRules) are not imported,
 * hosts get their objects in the GUI.
 */
const importPlan = (content, objects) => {
	let parsed;
	try {
		parsed = YAML.parse(content);
	} catch (err) {
		throw new errs.ValidationError(`YAML: ${err.message}`);
	}
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new errs.ValidationError("YAML: expected a local_policy.yaml document");
	}
	const doc = parsed.apiVersion === "v1beta2" ? parsed : fromV1(parsed);
	const plan = { create: [], update: [], skipped: [], errors: [], policy: null, rules: 0 };
	const names = new Map(objects.map((o) => [`${o.kind}/${o.name}`, o]));
	const incoming = [];
	for (const [section, kind] of Object.entries(SECTION_KIND)) {
		for (const item of Array.isArray(doc[section]) ? doc[section] : []) {
			if (typeof item?.name !== "string") {
				plan.errors.push(`${section}: an object without a name`);
				continue;
			}
			const existing = names.get(`${kind}/${item.name}`);
			if (item.name.startsWith(BUILTIN_PREFIX)) {
				plan.skipped.push(`${kind}/${item.name}`);
				continue;
			}
			incoming.push({ kind, name: item.name, spec: item, id: existing?.id });
		}
	}
	// trusted sources refer to source identifiers of the same file
	const withIncoming = [
		...objects,
		...incoming.filter((o) => !o.id).map((o, i) => ({ id: -1 - i, kind: o.kind, name: o.name, spec: {} })),
	];
	for (const o of incoming) {
		try {
			const checked = checkObject(
				o,
				withIncoming,
				o.id ?? withIncoming.find((w) => w.name === o.name && w.kind === o.kind).id,
			);
			if (!o.id) plan.create.push({ ...checked, id: o.id });
			// an object the document leaves as it is is not an update
			else if (JSON.stringify(checked.spec) !== JSON.stringify(objects.find((x) => x.id === o.id)?.spec)) {
				plan.update.push({ ...checked, id: o.id });
			}
		} catch (err) {
			plan.errors.push(err.message);
		}
	}
	const defaults = doc.policies?.default;
	if (defaults && typeof defaults === "object") {
		const find = (kind, name) => {
			const all = [...plan.create, ...plan.update, ...objects];
			// v1beta1 exports carry copies "<practice>.<mode>" of practices that inherit protections
			return (
				all.find((o) => o.kind === kind && o.name === name) ??
				all.find((o) => o.kind === kind && name.startsWith(`${o.name}.`))
			);
		};
		const policy = { mode: POLICY_MODES.includes(defaults.mode) ? defaults.mode : "inactive" };
		for (const [field, { kind, many }] of Object.entries(RULE_FIELDS)) {
			const value = defaults[field];
			if (value === undefined) continue;
			const list = (many ? value || [] : value ? [value] : []).map((name) => {
				const found = find(kind, name);
				if (!found) plan.errors.push(`policies.default.${field}: no ${kind} ${name}`);
				return found?.name;
			});
			policy[field] = many ? [...new Set(list.filter(Boolean))] : (list[0] ?? null);
		}
		plan.policy = policy;
	}
	plan.rules = Array.isArray(doc.policies?.specificRules) ? doc.policies.specificRules.length : 0;
	return plan;
};

const planSummary = (plan) => ({
	create: plan.create.map((o) => `${o.kind}/${o.name}`),
	update: plan.update.map((o) => `${o.kind}/${o.name}`),
	skipped: plan.skipped,
	errors: plan.errors,
	policy: plan.policy,
	rules: plan.rules,
});

// ---------------------------------------------------------------- API

const internalWafObjects = {
	/**
	 * Objects, the default policy, templates.
	 * @param {Access} access
	 */
	get: async (access) => {
		await access.can("waf_policy:view");
		const objects = await listObjects();
		return {
			objects,
			policy: await getDefaultPolicy(objects),
			templates: Object.fromEntries(
				Object.entries(TEMPLATES).map(([name, t]) => [name, { mode: t.mode, ...idsOf(t, objects) }]),
			),
			state: getPolicyState(),
		};
	},

	/**
	 * @param {Access} access
	 * @param {{kind, name, description?, spec}} data
	 */
	create: async (access, data) => {
		await access.can("waf_policy:manage");
		const objects = await listObjects();
		const object = checkObject(data, objects, 0);
		await ensureBaseline();
		const now = new Date();
		const [row] = await db()("npmos_waf_object")
			.insert({ ...object, spec: JSON.stringify(object.spec), builtin: false, created_on: now, modified_on: now })
			.returning("id");
		const id = typeof row === "object" ? row.id : row;
		const state = await changed(access, `created ${object.kind}/${object.name}`);
		return { id, ...object, builtin: false, state };
	},

	/**
	 * @param {Access} access
	 * @param {number} id
	 * @param {{kind, name, description?, spec}} data
	 */
	update: async (access, id, data) => {
		await access.can("waf_policy:manage");
		const objects = await listObjects();
		const old = getObject(objects, id);
		if (old.builtin) throw new errs.ValidationError(`${old.name} is built in and read-only (duplicate it)`);
		if (data.kind !== old.kind) throw new errs.ValidationError("the kind of an object cannot change");
		const object = checkObject(data, objects, id);
		if (old.name !== object.name && old.kind === "source_identifiers") {
			const users = (await usersOf(old, objects)).filter((u) => u.startsWith("object:"));
			if (users.length) throw new errs.ValidationError(`${old.name} is used by name: ${users.join(", ")}`);
		}
		await ensureBaseline();
		await db()("npmos_waf_object")
			.where("id", id)
			.update({ ...object, spec: JSON.stringify(object.spec), modified_on: new Date() });
		const state = await changed(access, `updated ${object.kind}/${object.name}`);
		return { id, ...object, builtin: false, state };
	},

	/**
	 * @param {Access} access
	 * @param {number} id
	 */
	delete: async (access, id) => {
		await access.can("waf_policy:manage");
		const objects = await listObjects();
		const object = getObject(objects, id);
		if (object.builtin) throw new errs.ValidationError(`${object.name} is built in`);
		const users = await usersOf(object, objects);
		if (users.length) throw new errs.ValidationError(`${object.name} is used: ${users.join(", ")}`);
		await ensureBaseline();
		await db()("npmos_waf_object").where("id", id).delete();
		return { state: await changed(access, `deleted ${object.kind}/${object.name}`) };
	},

	/**
	 * @param {Access} access
	 * @param {{mode, threatPreventionPractices?, ...}} data
	 */
	setPolicy: async (access, data) => {
		await access.can("waf_policy:manage");
		const objects = await listObjects();
		const policy = checkPolicy(data, objects);
		await ensureBaseline();
		await setSetting("waf.policy", policy);
		return { policy, state: await changed(access, "default policy") };
	},

	/**
	 * What local_policy.yaml becomes with a change (nothing is saved).
	 * @param {Access} access
	 * @param {object} change  see candidateOf
	 */
	preview: async (access, change) => {
		await access.can("waf_policy:view");
		const objects = await listObjects();
		let candidate;
		try {
			candidate = await candidateOf(change, objects);
		} catch (err) {
			if (err instanceof errs.ValidationError || err instanceof errs.ItemNotFoundError) {
				return { valid: false, error: err.message };
			}
			throw err;
		}
		const { policy, customId, format, reasons, warnings } = await buildPolicy({ candidate });
		const next = render(policy, customId !== null);
		const diff = diffLines((await readPolicyFile()) ?? "", next);
		return { valid: true, changed: diff.some((d) => d.op !== " "), diff, format, reasons, warnings };
	},

	/**
	 * @param {Access} access
	 */
	versions: async (access) => {
		await access.can("waf_policy:view");
		const rows = await db()("npmos_waf_policy_version as v")
			.leftJoin("user as u", "u.id", "v.user_id")
			.select("v.id", "v.comment", "v.created_on", "u.name as user_name")
			.orderBy("v.id", "desc")
			.limit(VERSIONS_SHOWN);
		return rows.map((r) => ({ id: r.id, comment: r.comment, created_on: r.created_on, user: r.user_name || null }));
	},

	/**
	 * Restores a version (as a new version, the history is kept).
	 * @param {Access} access
	 * @param {number} id
	 */
	rollback: async (access, id) => {
		await access.can("waf_policy:manage");
		const row = await db()("npmos_waf_policy_version").where({ id }).first();
		if (!row) throw new errs.ItemNotFoundError(id);
		await restore(parse(row.state));
		return { state: await changed(access, `rollback to version ${id}`) };
	},

	/**
	 * @param {Access} access
	 * @param {"v1beta2"|"v1beta1"} format
	 * @returns {Promise<string>}
	 */
	export: async (access, format = "v1beta2", section = null) => {
		await access.can("waf_policy:view");
		// one kind of objects (Agents → open-appsec → a kind → Code): the administrator's objects of it; the
		// built-in ones are named in the head (they are not imported)
		if (section) {
			const kind = Object.keys(KINDS).find((k) => KINDS[k] === section);
			if (!kind) throw new errs.ValidationError(`unknown section ${section}`);
			const objects = (await listObjects()).filter((o) => o.kind === kind);
			const builtin = objects.filter((o) => o.builtin).map((o) => o.name);
			const own = objects.filter((o) => !o.builtin).map((o) => ({ name: o.name, ...o.spec }));
			const doc = asV2({ policies: { default: { mode: "detect-learn" }, specificRules: [] }, [section]: own });
			const head = `# NPMOS: ${section} of WAF -> Policy (v1beta2)${builtin.length ? `\n# built in, read only: ${builtin.join(", ")}` : ""}\n`;
			return `${head}${YAML.stringify({ [section]: doc[section] ?? [] }, { lineWidth: 0, aliasDuplicateObjects: false })}`;
		}
		return `# NPMOS: objects and default policy of WAF -> Policy (${format})\n${YAML.stringify(await exportDoc(format), { lineWidth: 0, aliasDuplicateObjects: false })}`;
	},

	/**
	 * Imports objects and the default policy of a local_policy.yaml (either syntax).
	 * @param {Access}  access
	 * @param {string}  content
	 * @param {boolean} dryRun  only what would be done
	 */
	import: async (access, content, dryRun) => {
		await access.can(dryRun ? "waf_policy:view" : "waf_policy:manage");
		const plan = importPlan(content, await listObjects());
		if (dryRun || plan.errors.length) return { applied: false, ...planSummary(plan) };
		await ensureBaseline();
		const now = new Date();
		await db().transaction(async (trx) => {
			for (const o of plan.update) {
				await trx("npmos_waf_object")
					.where("id", o.id)
					.update({ spec: JSON.stringify(o.spec), modified_on: now });
			}
			for (const o of plan.create) {
				await trx("npmos_waf_object").insert({
					kind: o.kind,
					name: o.name,
					description: "",
					spec: JSON.stringify(o.spec),
					builtin: false,
					created_on: now,
					modified_on: now,
				});
			}
		});
		if (plan.policy) {
			const objects = await listObjects();
			await setSetting(
				"waf.policy",
				checkPolicy({ mode: plan.policy.mode, ...idsOf(plan.policy, objects) }, objects),
			);
		}
		const state = await changed(access, "import", { objects: plan.create.length + plan.update.length });
		return { applied: true, ...planSummary(plan), state };
	},
};

export default internalWafObjects;
