// The WAF policy of a host as code (Agents → open-appsec → a host → Code): the settings of WAF hosts
// (hosts.js) as YAML, with objects named instead of their ids. The same document is read back: checked
// without saving (dry run, with the change of the document), or applied as the GUI would apply it.
import YAML from "yaml";
import errs from "../../lib/error.js";
import { RULE_FIELDS } from "./objects/model.js";
import { listObjects } from "./objects/store.js";

/** modes and confidences of a host (policy.js; repeated here: that module starts the agent's side) */
const MODES = ["detect-learn", "prevent-learn"];
const CONFIDENCES = ["medium", "high", "critical"];
/** loaded on use: it reads the configuration of NPMplus */
const hosts = async () => (await import("./hosts.js")).default;

const HEADER = (name) =>
	`# open-appsec policy of the proxy host ${name}
# mode: ${MODES.join(" | ")}
# minimumConfidence: ${CONFIDENCES.join(" | ")} (the lowest confidence of an attack that is blocked)
# objects: left out = the objects of the base policy; template: <name>, or the objects by name
`;

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** references (ids) → names; a template stays a template */
const objectsToNames = (objects, all) => {
	if (!objects) return undefined;
	if (objects.template) return { template: objects.template };
	const byId = new Map(all.map((o) => [o.id, o.name]));
	const out = {};
	for (const [field, { many }] of Object.entries(RULE_FIELDS)) {
		const value = objects[field];
		if (value === undefined) continue;
		out[field] = many ? value.map((id) => byId.get(id) ?? id) : value === null ? null : (byId.get(value) ?? value);
	}
	return out;
};

/** names → references (ids) of objects of the right kind */
const objectsToIds = (objects, all, what) => {
	if (objects === undefined || objects === null) return null;
	if (!isObject(objects)) throw new errs.ValidationError(`${what}: objects must be a map`);
	if (objects.template !== undefined) return { template: objects.template };
	const out = {};
	for (const [key, value] of Object.entries(objects)) {
		const field = RULE_FIELDS[key];
		if (!field) throw new errs.ValidationError(`${what}: unknown field objects.${key}`);
		const id = (name) => {
			const found = all.find((o) => o.kind === field.kind && o.name === name);
			if (!found)
				throw new errs.ValidationError(`${what}: objects.${key}: no ${field.kind} object named ${name}`);
			return found.id;
		};
		if (field.many) {
			if (!Array.isArray(value)) throw new errs.ValidationError(`${what}: objects.${key} must be a list`);
			out[key] = value.map(id);
		} else {
			out[key] = value === null || value === "" ? null : id(value);
		}
	}
	return out;
};

const settingsDoc = (s, all) =>
	Object.fromEntries(
		Object.entries({
			enabled: s.enabled,
			mode: s.mode,
			minimumConfidence: s.minimum_confidence,
			objects: objectsToNames(s.objects, all),
		}).filter(([, v]) => v !== undefined),
	);

/** the settings of a host (get of hosts.js) as YAML */
export const toCode = (name, settings, all) => {
	const doc = settingsDoc(settings, all);
	const own = settings.locations.filter((l) => !l.inherit);
	if (own.length) doc.locations = own.map((l) => ({ path: l.path, ...settingsDoc(l, all) }));
	return HEADER(name) + YAML.stringify(doc, { lineWidth: 0 });
};

/** YAML → the data of set of hosts.js; locations not named inherit the host */
export const fromCode = (content, current, all) => {
	let doc;
	try {
		doc = YAML.parse(String(content ?? ""));
	} catch (err) {
		throw new errs.ValidationError(`YAML: ${err.message}`);
	}
	if (!isObject(doc)) throw new errs.ValidationError("YAML: the document must be a map");
	const known = ["enabled", "mode", "minimumConfidence", "objects", "locations"];
	for (const key of Object.keys(doc)) {
		if (!known.includes(key)) throw new errs.ValidationError(`unknown field ${key} (${known.join(", ")})`);
	}
	const settings = (d, what) => ({
		enabled: d.enabled ?? true,
		mode: d.mode,
		minimum_confidence: d.minimumConfidence ?? "high",
		objects: objectsToIds(d.objects, all, what),
	});
	const locations = doc.locations ?? [];
	if (!Array.isArray(locations)) throw new errs.ValidationError("locations must be a list");
	const byPath = new Map(locations.map((l) => [l?.path, l]));
	for (const path of byPath.keys()) {
		if (!current.locations.some((l) => l.path === path)) {
			throw new errs.ValidationError(`the host has no location ${path}`);
		}
	}
	const host = settings(doc, "WAF");
	return {
		...host,
		locations: current.locations.map((l) =>
			byPath.has(l.path)
				? { path: l.path, inherit: false, ...settings(byPath.get(l.path), `location ${l.path}`) }
				: { path: l.path, inherit: true, ...host, objects: null },
		),
	};
};

const internalWafHostCode = {
	/** @returns {Promise<{content: string}>} */
	get: async (access, id, name) => {
		const current = await (await hosts()).get(access, id);
		return { content: toCode(name, current, await listObjects()) };
	},

	/**
	 * Checks or applies a document. dry run: {valid, error?} without saving.
	 * @param {Access} access
	 * @param {number} id
	 * @param {{content: string, dry_run?: boolean, name: string}} data
	 */
	set: async (access, id, data) => {
		const current = await (await hosts()).get(access, id);
		const all = await listObjects();
		let input;
		try {
			input = fromCode(data.content, current, all);
			if (!MODES.includes(input.mode)) throw new errs.ValidationError(`mode must be one of ${MODES.join(", ")}`);
			for (const l of input.locations) {
				if (!l.inherit && !MODES.includes(l.mode)) {
					throw new errs.ValidationError(`location ${l.path}: mode must be one of ${MODES.join(", ")}`);
				}
			}
		} catch (err) {
			if (err instanceof errs.ValidationError) return { valid: false, error: err.message };
			throw err;
		}
		if (data.dry_run) return { valid: true };
		const saved = await (await hosts()).set(access, id, input);
		return { valid: true, applied: true, content: toCode(data.name, saved, all) };
	},
};

export default internalWafHostCode;
