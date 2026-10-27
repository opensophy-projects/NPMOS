// NPMOS API client (/api/npmos/*), see npmos/backend/npmos/routes.js
import * as api from "src/api/backend/base";

export interface Service {
	id: string;
	service: string;
	name: string;
	image: string;
	version: string | null;
	state: "created" | "running" | "paused" | "restarting" | "removing" | "exited" | "dead";
	status: string;
	created: number;
	restartable: boolean;
}

export interface ServiceLogLine {
	stream: "stdout" | "stderr";
	line: string;
}

export interface RestartResult {
	service: string;
	restarted: boolean;
	restarting?: boolean;
}

export const getServices = (): Promise<Service[]> => api.get({ url: "/npmos/services" });

export const getServiceLogs = (service: string, tail = 200): Promise<ServiceLogLine[]> =>
	api.get({ url: `/npmos/services/${encodeURIComponent(service)}/logs`, params: { tail } });

export const restartService = (service: string): Promise<RestartResult> =>
	api.post({ url: `/npmos/services/${encodeURIComponent(service)}/restart` });

export const regenerateNginx = (): Promise<{ regenerated: boolean }> => api.post({ url: "/npmos/nginx/regenerate" });

export const downloadDiagnostics = () =>
	api.download({ url: "/npmos/diagnostics" }, `npmos-diagnostics-${new Date().toISOString().slice(0, 19)}.zip`);
