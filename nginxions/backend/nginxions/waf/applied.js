// Does the agent apply what NginxionS wrote? nginxions-control reads the configuration the agent generated from
// local_policy.yaml (/tmp/local_appsec.policy in the openappsec container); it is compared here with the policy
// NginxionS generated last. A difference means the agent left something out (a field it does not read, docs/
// WAF-POLICY.md) or still runs an older policy. Shown in WAF -> Policy and on the page of the agent.
import { global as logger } from "../../logger.js";
import control from "../control/client.js";
import { compareApplied } from "./objects/compare.js";
import { getLastPolicy } from "./policy.js";

const CACHE_MS = 15000;
let cache = { at: 0, value: null };
let logged = "";

/**
 * The state of the policy in the agent: ok, drift (with what differs), pending (the agent has not generated its
 * configuration since the last change) or unknown (the agent or nginxions-control is not reachable).
 * @returns {Promise<{status: "ok"|"drift"|"pending"|"unknown", drift?: string[], modifiedAt?: string|null,
 *   error?: string}>}
 */
export const checkApplied = async () => {
	if (cache.value && Date.now() - cache.at < CACHE_MS) return cache.value;
	const { doc, changedAt } = getLastPolicy();
	let value;
	try {
		const { modifiedAt, policy } = await control.getAgentPolicy();
		if (!doc) {
			value = { status: "unknown", modifiedAt };
		} else if (!policy || (changedAt && (!modifiedAt || modifiedAt < changedAt))) {
			value = { status: "pending", modifiedAt };
		} else {
			const drift = compareApplied(doc, policy);
			value = { status: drift.length ? "drift" : "ok", drift, modifiedAt };
			// once per difference, not at every check
			if (drift.join() !== logged) {
				logged = drift.join();
				if (drift.length) logger.warn(`WAF: the agent applies the policy differently: ${drift.join(", ")}`);
			}
		}
	} catch (err) {
		value = { status: "unknown", error: err.message };
	}
	cache = { at: Date.now(), value };
	return value;
};
