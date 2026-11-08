// One API for the four host types of NPMplus (partial updates, enable/disable, delete, create).
import * as api from "src/api/backend/base";
import type { HostType } from "./rows";

const PATH: Record<HostType, string> = {
	proxy: "/nginx/proxy-hosts",
	redirect: "/nginx/redirection-hosts",
	stream: "/nginx/streams",
	dead: "/nginx/dead-hosts",
};

/** react-query keys of the host lists (the upstream modals invalidate the same keys) */
export const QUERY_KEY: Record<HostType, string> = {
	proxy: "proxy-hosts",
	redirect: "redirection-hosts",
	stream: "streams",
	dead: "dead-hosts",
};

/** object name of the type in the upstream locale ("proxy-host" → "Proxy Host") */
export const OBJECT: Record<HostType, string> = {
	proxy: "proxy-host",
	redirect: "redirection-host",
	stream: "stream",
	dead: "dead-host",
};

/** PUT accepts any subset of the fields; `meta` replaces the stored meta, so send all of it */
export const updateHost = (type: HostType, id: number, data: Record<string, unknown>) =>
	api.put({ url: `${PATH[type]}/${id}`, data });

export const toggleHost = (type: HostType, id: number, enabled: boolean) =>
	api.post({ url: `${PATH[type]}/${id}/${enabled ? "enable" : "disable"}` });

export const deleteHost = (type: HostType, id: number) => api.del({ url: `${PATH[type]}/${id}` });

/** creates a host from exported settings; only proxy hosts accept `enabled` on create */
export async function createHost(type: HostType, data: Record<string, any>) {
	const { enabled, ...rest } = data;
	const host = await api.post({ url: PATH[type], data: type === "proxy" ? data : rest });
	if (type !== "proxy" && enabled === false) {
		await toggleHost(type, host.id, false);
	}
	return host;
}
