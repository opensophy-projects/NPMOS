// System → Settings: env settings of NPMplus kept by NPMOS (applied by a restart of npmos).
import * as api from "src/api/backend/base";

export type EnvGroup = "general" | "network" | "nginx" | "tls" | "acme" | "logs" | "external";
export type EnvValue = boolean | number | string;

export interface EnvSetting {
	/** the env name, e.g. DISABLE_HTTP (a value, not a key: the API client leaves it as it is) */
	env: string;
	group: EnvGroup;
	type: "bool" | "int" | "workers" | "tz" | "url" | "email" | "token" | "secret";
	default: EnvValue;
	min?: number;
	max?: number;
	/** the setting makes NPMOS reach the internet */
	internet?: boolean;
	/** saved value (or the running one) */
	value: EnvValue;
	running: EnvValue;
	/** saved, applied at the next restart */
	pending: boolean;
}

export interface SystemSettings {
	items: EnvSetting[];
	restartRequired: boolean;
	restarting?: boolean;
}

export const getSystemSettings = () => api.get({ url: "/npmos/system/settings" }) as Promise<SystemSettings>;

export const setSystemSettings = (values: { env: string; value: EnvValue }[], apply: boolean) =>
	api.put({ url: "/npmos/system/settings", data: { values, apply } }) as Promise<SystemSettings>;

export const applySystemSettings = () => api.post({ url: "/npmos/system/settings/apply" }) as Promise<SystemSettings>;
