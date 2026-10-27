import { useQuery } from "@tanstack/react-query";
import {
	getServiceLogs,
	getServices,
	getWafEvents,
	getWafHost,
	getWafHosts,
	getWafPolicy,
	getWafStatus,
	type Service,
	type ServiceLogLine,
	type WafEvents,
	type WafEventsView,
	type WafHost,
	type WafPolicyState,
	type WafSettings,
	type WafStatus,
} from "./api";

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

export const useWafHosts = (options = {}) =>
	useQuery<Record<string, WafSettings>, Error>({
		queryKey: ["npmos-waf-hosts"],
		queryFn: getWafHosts,
		staleTime: 15000,
		...options,
	});

/** id "new" (or a clone of nothing): no request, the form starts from the defaults */
export const useWafHost = (id: number | "new") =>
	useQuery<WafHost, Error>({
		queryKey: ["npmos-waf-host", id],
		queryFn: () => getWafHost(id as number),
		enabled: id !== "new",
	});

export const useWafPolicy = () =>
	useQuery<WafPolicyState & { content: string | null }, Error>({
		queryKey: ["npmos-waf-policy"],
		queryFn: getWafPolicy,
		refetchInterval: 10000,
	});

export const useWafEvents = (view: WafEventsView, query: string, follow: boolean) =>
	useQuery<WafEvents, Error>({
		queryKey: ["npmos-waf-events", view, query],
		queryFn: () => getWafEvents({ view, query: query || undefined }),
		refetchInterval: follow ? 5000 : false,
		placeholderData: (previous) => previous,
	});
