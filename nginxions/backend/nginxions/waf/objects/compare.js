// What the agent applies compared with the policy NginxionS generated (applied.js): pure functions, no database.

const list = (v) => (Array.isArray(v) ? v : []);

/** every array under a key of that name, anywhere in the configuration */
const collect = (node, key, out = []) => {
	if (Array.isArray(node)) {
		for (const item of node) collect(item, key, out);
	} else if (node && typeof node === "object") {
		for (const [k, v] of Object.entries(node)) {
			if (k === key && Array.isArray(v)) out.push(...v);
			else collect(v, key, out);
		}
	}
	return out;
};

/** objects with these keys, anywhere in the configuration */
const objectsWith = (node, keys, out = []) => {
	if (Array.isArray(node)) {
		for (const item of node) objectsWith(item, keys, out);
	} else if (node && typeof node === "object") {
		if (keys.every((k) => k in node)) out.push(node);
		for (const v of Object.values(node)) objectsWith(v, keys, out);
	}
	return out;
};

const DETAILS = { "response-code-only": "Response Code", "block-page": "Block Page", redirect: "Redirect" };
const byName = (items, name) => items.find((i) => `${i.triggerName ?? i.name ?? ""}`.endsWith(`/${name}`));

/**
 * What the agent applies differently from the policy (v1beta2 terms): "asset:<host>", "response:<name>",
 * "rate-limit:<practice>". Empty: as written.
 * @param {object} doc      the policy NginxionS generated (objects/format.js terms)
 * @param {object} applied  the configuration of the agent
 * @returns {string[]}
 */
export const compareApplied = (doc, applied) => {
	const drift = new Set();
	const defaults = doc.policies?.default || {};
	const rules = [{ ...defaults, host: "*" }, ...list(doc.policies?.specificRules)];
	const assets = new Set(objectsWith(applied, ["assetName", "practices"]).map((r) => r.assetName));
	const responses = collect(applied, "webUserResponse");
	const rateLimits = collect(applied, "rateLimit").filter((r) => r && typeof r === "object" && "rules" in r);
	const customResponses = new Map(list(doc.customResponses).map((r) => [r.name, r]));
	const accessPractices = new Map(list(doc.accessControlPractices).map((p) => [p.name, p]));

	for (const rule of rules) {
		const host = rule.host === "*" || rule.host === "*:*" ? "Any" : rule.host;
		const practices = list(rule.threatPreventionPractices).length
			? rule.threatPreventionPractices
			: list(defaults.threatPreventionPractices);
		if (practices.length && !assets.has(host)) drift.add(`asset:${host}`);

		const responseName = rule.customResponse || defaults.customResponse;
		const response = customResponses.get(responseName);
		if (response) {
			const found = byName(responses, responseName);
			const wrong =
				!found ||
				found["details level"] !== DETAILS[response.mode] ||
				(response.mode === "redirect"
					? found["redirect URL"] !== response.redirectUrl
					: Number(found["response code"]) !== Number(response.httpResponseCode ?? 403));
			if (wrong) drift.add(`response:${responseName}`);
		}

		const accessName = list(rule.accessControlPractices)[0] ?? list(defaults.accessControlPractices)[0];
		const access = accessPractices.get(accessName);
		const limits = list(access?.rateLimit?.rules);
		if (access && limits.length && access.rateLimit?.overrideMode !== "inactive") {
			const found = byName(rateLimits, accessName);
			if (!found || list(found.rules).length !== limits.length) drift.add(`rate-limit:${accessName}`);
		}
	}
	return [...drift];
};
