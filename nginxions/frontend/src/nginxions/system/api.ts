// System → Settings: env settings of NPMplus kept by NginxionS (applied by a restart of nginxions).
import * as api from "src/api/backend/base";

export type EnvGroup = "general" | "network" | "nginx" | "tls" | "acme" | "logs" | "external";
export type EnvValue = boolean | number | string;

export interface EnvSetting {
	/** the env name, e.g. DISABLE_HTTP (a value, not a key: the API client leaves it as it is) */
	env: string;
	group: EnvGroup;
	type: "bool" | "int" | "workers" | "tz" | "url" | "email" | "token" | "secret" | "profile";
	default: EnvValue;
	min?: number;
	max?: number;
	/** the setting makes NginxionS reach the internet */
	internet?: boolean;
	/** saved value (or the running one) */
	value: EnvValue;
	running: EnvValue;
	/** saved, applied at the next restart */
	pending: boolean;
}

interface SystemSettings {
	items: EnvSetting[];
	restartRequired: boolean;
	restarting?: boolean;
}

export const getSystemSettings = () => api.get({ url: "/nginxions/system/settings" }) as Promise<SystemSettings>;

export const setSystemSettings = (values: { env: string; value: EnvValue }[], apply: boolean) =>
	api.put({ url: "/nginxions/system/settings", data: { values, apply } }) as Promise<SystemSettings>;

export const applySystemSettings = () =>
	api.post({ url: "/nginxions/system/settings/apply" }) as Promise<SystemSettings>;
