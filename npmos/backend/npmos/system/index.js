// System → Settings: env settings of NPMplus in the GUI (docs/ENV-INVENTORY.md). Saved values go
// to runtime.env and are applied by a restart of npmos (through npmos-control), as the WAF switch.
// RBAC: settings:view / settings:manage.
import internalAuditLog from "../../internal/audit-log.js";
import errs from "../../lib/error.js";
import control from "../control/client.js";
import { getSetting, setSetting } from "../settings.js";
import { conflicts, normalize, running, SYSTEM_ENV } from "./env.js";

const state = async () => {
	const saved = await getSetting("system.env");
	const items = SYSTEM_ENV.map((def) => {
		const current = running(def.env);
		const value = saved[def.env] ?? current;
		return { ...def, value, running: current, pending: value !== current };
	});
	return { items, restartRequired: items.some((i) => i.pending) };
};

const internalSystem = {
	getSettings: async (access) => {
		await access.can("settings:view");
		return state();
	},

	/**
	 * @param {Access} access
	 * @param {{values: {env: string, value: any}[], apply?: boolean}} data
	 */
	setSettings: async (access, { values, apply = false }) => {
		await access.can("settings:manage");
		const saved = { ...(await getSetting("system.env")) };
		const changed = {};
		for (const { env, value } of values) {
			const normalized = normalize(env, value);
			if (normalized === undefined) throw new errs.ValidationError(`Invalid value for ${env}`);
			// a value equal to the running one and to the default needs no line in runtime.env
			const def = SYSTEM_ENV.find((d) => d.env === env);
			if (normalized === running(env) && normalized === def.default) delete saved[env];
			else saved[env] = normalized;
			changed[env] = normalized;
		}
		const effective = Object.fromEntries(SYSTEM_ENV.map((d) => [d.env, saved[d.env] ?? running(d.env)]));
		const problems = conflicts(effective);
		if (problems.length) throw new errs.ValidationError(problems.join("; "));
		await setSetting("system.env", saved);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "setting",
			meta: { name: "system.env", ...changed },
		});
		const result = await state();
		const restarting = apply && result.restartRequired;
		if (restarting) await control.restartService("npmos", access.token.getUserId(1));
		return { ...result, restarting };
	},

	/** restarts npmos to apply what was saved */
	apply: async (access) => {
		await access.can("settings:manage");
		const result = await state();
		if (result.restartRequired) await control.restartService("npmos", access.token.getUserId(1));
		return { ...result, restarting: result.restartRequired };
	},
};

export default internalSystem;
