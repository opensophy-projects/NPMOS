// ACME servers (Settings → ACME) and the DNS providers of lego, see npmos/backend/npmos/acme
import { useQuery } from "@tanstack/react-query";
import * as api from "src/api/backend/base";

export type AcmeClient = "certbot" | "lego";

export interface AcmeServer {
	id: number;
	name: string;
	preset: string;
	directory: string;
	client: AcmeClient;
	email: string;
	eabKid: string;
	/** "********" when set */
	eabHmacKey: string;
	profile: string;
	tlsVerify: boolean;
	isDefault: boolean;
	/** ACME certificates issued by it */
	usedBy: number;
}

export interface AcmePreset {
	id: string;
	name: string;
	directory: string;
	client: AcmeClient;
	/** "required": the keys of the account page; "auto": ZeroSSL issues them for the email */
	eab: "" | "required" | "auto";
	profiles?: string[];
	legoOnly?: boolean;
	caa?: string;
}

export interface AcmeServers {
	items: AcmeServer[];
	presets: AcmePreset[];
	clients: AcmeClient[];
}

export type AcmeServerInput = Partial<Omit<AcmeServer, "id" | "usedBy">>;

export const SECRET_SET = "********";

export const getAcmeServers = () => api.get({ url: "/npmos/acme/servers" }) as Promise<AcmeServers>;
export const createAcmeServer = (data: AcmeServerInput) =>
	api.post({ url: "/npmos/acme/servers", data }) as Promise<AcmeServer>;
export const updateAcmeServer = (id: number, data: AcmeServerInput) =>
	api.put({ url: `/npmos/acme/servers/${id}`, data }) as Promise<AcmeServer>;
export const deleteAcmeServer = (id: number) => api.del({ url: `/npmos/acme/servers/${id}` });
export const setDefaultAcmeServer = (id: number) =>
	api.post({ url: `/npmos/acme/servers/${id}/default` }) as Promise<AcmeServer>;

export const getLegoDnsProviders = () =>
	api.get({ url: "/npmos/acme/lego/dns-providers" }) as Promise<{ items: string[] }>;
export const getLegoDnsProviderHelp = (code: string) =>
	api.get({ url: `/npmos/acme/lego/dns-providers/${encodeURIComponent(code)}` }) as Promise<{
		code: string;
		help: string;
	}>;

export const useAcmeServers = () =>
	useQuery({ queryKey: ["npmos-acme-servers"], queryFn: getAcmeServers, staleTime: 30000 });

/**
 * The name of the ACME server of a certificate of NPMplus ("letsencrypt": meta.acmeServerId, the default server for
 * those of before), to tell which CA issued it. Undefined while the servers load or are not visible.
 */
export const useAcmeServerOf = () => {
	const { data } = useAcmeServers();
	return (cert?: { provider: string; meta?: Record<string, any> }) =>
		cert?.provider === "letsencrypt" && data?.items?.length
			? chosenServer(data, cert.meta?.acmeServerId)?.name
			: undefined;
};

/** the server a form chose, the default one when none is chosen */
export const chosenServer = (servers: AcmeServers | undefined, id: unknown): AcmeServer | undefined => {
	const items = servers?.items ?? [];
	return items.find((s) => s.id === Number(id)) ?? items.find((s) => s.isDefault) ?? items[0];
};
