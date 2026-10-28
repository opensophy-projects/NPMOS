import { useQuery } from "@tanstack/react-query";
import {
	type Analytics,
	type AnalyticsPeriod,
	type EventQuery,
	type EventsPage,
	type EventsSettings,
	getAnalytics,
	getEvent,
	getEvents,
	getEventsSettings,
	getHostChanges,
	getHostHistory,
	getServiceLogs,
	getServices,
	getUpstreamChecks,
	getWafAgent,
	getWafCustomPolicy,
	getWafHost,
	getWafHosts,
	getWafPolicy,
	getWafStatus,
	type HostChange,
	type HostLastChange,
	type HostObjectType,
	type SecurityEventFull,
	type Service,
	type ServiceLogLine,
	type UpstreamCheck,
	type WafAgentState,
	type WafCustomPolicy,
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

export const useAnalytics = (period: AnalyticsPeriod, host: string, options = {}) =>
	useQuery<Analytics, Error>({
		queryKey: ["npmos-analytics", period, host],
		queryFn: () => getAnalytics(period, host || undefined),
		refetchInterval: 30000,
		placeholderData: (previous) => previous,
		...options,
	});

/** a page of stored events; `follow`: refreshed every 5 s */
export const useEvents = (query: EventQuery, follow: boolean, options = {}) =>
	useQuery<EventsPage, Error>({
		queryKey: ["npmos-events", query],
		queryFn: () => getEvents(query),
		refetchInterval: follow ? 5000 : false,
		placeholderData: (previous) => previous,
		...options,
	});

export const useEvent = (id: string, time: string) =>
	useQuery<SecurityEventFull, Error>({
		queryKey: ["npmos-event", id, time],
		queryFn: () => getEvent(id, time),
		staleTime: Number.POSITIVE_INFINITY,
	});

export const useEventsSettings = (options = {}) =>
	useQuery<EventsSettings, Error>({
		queryKey: ["npmos-events-settings"],
		queryFn: getEventsSettings,
		...options,
	});

export const useWafAgent = () =>
	useQuery<WafAgentState, Error>({
		queryKey: ["npmos-waf-agent"],
		queryFn: getWafAgent,
		refetchInterval: 10000,
	});

export const useWafCustomPolicy = () =>
	useQuery<WafCustomPolicy, Error>({
		queryKey: ["npmos-waf-custom-policy"],
		queryFn: getWafCustomPolicy,
	});

export const useHostChanges = (options = {}) =>
	useQuery<HostLastChange[], Error>({
		queryKey: ["npmos-host-changes"],
		queryFn: getHostChanges,
		staleTime: 15000,
		// the upstream dialogs save without telling this page
		refetchInterval: 30000,
		...options,
	});

export const useHostHistory = (type: HostObjectType, id: number) =>
	useQuery<HostChange[], Error>({
		queryKey: ["npmos-host-history", type, id],
		queryFn: () => getHostHistory(type, id),
	});

/** the backend caches each check for 30 s */
export const useUpstreamChecks = (options = {}) =>
	useQuery<UpstreamCheck[], Error>({
		queryKey: ["npmos-upstreams"],
		queryFn: getUpstreamChecks,
		refetchInterval: 60000,
		...options,
	});
