import { useQuery } from "@tanstack/react-query";
import { getServiceLogs, getServices, getWafStatus, type Service, type ServiceLogLine, type WafStatus } from "./api";

export const useServices = (options = {}) =>
	useQuery<Service[], Error>({
		queryKey: ["npmos-services"],
		queryFn: getServices,
		refetchInterval: 5000,
		...options,
	});

export const useServiceLogs = (service: string, tail: number, follow: boolean) =>
	useQuery<ServiceLogLine[], Error>({
		queryKey: ["npmos-service-logs", service, tail],
		queryFn: () => getServiceLogs(service, tail),
		refetchInterval: follow ? 3000 : false,
	});

export const useWafStatus = (options = {}) =>
	useQuery<WafStatus, Error>({
		queryKey: ["npmos-waf"],
		queryFn: getWafStatus,
		refetchInterval: 10000,
		...options,
	});
