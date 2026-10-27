import { useQuery } from "@tanstack/react-query";
import { getServiceLogs, getServices, type Service, type ServiceLogLine } from "./api";

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
