// WAF (open-appsec): switching the nginx attachment on and off from the GUI.
// The attachment is a dynamic nginx module loaded at container start (start.sh, env
// NGINX_LOAD_OPENAPPSEC_ATTACHMENT_MODULE). The switch is stored as setting "waf.enabled"
// and applied by restarting the npmos container through npmos-control.
import internalAuditLog from "../../internal/audit-log.js";
import control from "../control/client.js";
import { getRunningValue, getSetting, setSetting } from "../settings.js";
import { getAgentStatus } from "./agent.js";

const internalWaf = {
	/**
	 * @param {Access} access
	 */
	getStatus: async (access) => {
		await access.can("npmos_services:list");
		const enabled = await getSetting("waf.enabled");
		const active = getRunningValue("waf.enabled");
		return { enabled, active, restartRequired: enabled !== active, agent: await getAgentStatus() };
	},

	/**
	 * Saves the switch and, if it differs from the running state, restarts npmos to apply it
	 * (npmos-control answers first, then restarts npmos and the agent that shares its namespaces).
	 * @param {Access}  access
	 * @param {boolean} enabled
	 * @param {boolean} [apply]  restart now
	 */
	setEnabled: async (access, enabled, apply = true) => {
		await access.can("npmos_services:manage");
		await setSetting("waf.enabled", enabled);
		await internalAuditLog.add(access, {
			action: enabled ? "enabled" : "disabled",
			object_type: "waf",
			meta: { name: "open-appsec" },
		});
		const active = getRunningValue("waf.enabled");
		const restarting = apply && enabled !== active;
		if (restarting) {
			await control.restartService("npmos", access.token.getUserId(1));
		}
		return { enabled, active, restartRequired: enabled !== active, restarting };
	},
};

export default internalWaf;
