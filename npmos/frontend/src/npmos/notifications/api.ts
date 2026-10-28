// Notifications (System → Notifications): channels, rules, deliveries. Keys are camelCase here, the
// API client converts them.
import * as api from "src/api/backend/base";

export type ChannelType = "email" | "webhook" | "telegram";
export type RuleType = "attack_spike" | "agent_down" | "policy_error" | "service_down" | "cert_expiry" | "host_problem";
export type Language = "ru" | "en";

export interface EmailConfig {
	host: string;
	port: number;
	security: "none" | "starttls" | "tls";
	verifyTls: boolean;
	username: string;
	/** sent only to change it; never returned */
	password?: string | null;
	hasPassword?: boolean;
	from: string;
	to: string[];
	language: Language;
}

export interface WebhookConfig {
	url: string;
	secret?: string | null;
	hasSecret?: boolean;
	language: Language;
}

export interface TelegramConfig {
	token?: string | null;
	hasToken?: boolean;
	chatId: string;
	apiUrl: string;
	language: Language;
}

export type ChannelConfig = EmailConfig | WebhookConfig | TelegramConfig;

export interface Channel {
	id: number;
	name: string;
	type: ChannelType;
	enabled: boolean;
	config: ChannelConfig;
	modifiedOn: string;
}

export interface Rule {
	id: number;
	name: string;
	type: RuleType;
	enabled: boolean;
	params: Record<string, string | number>;
	channelIds: number[];
	repeatMinutes: number;
	notifyResolved: boolean;
	/** keys of the alerts active now */
	active: string[];
}

export interface Delivery {
	id: number;
	createdOn: string;
	ruleId: number | null;
	channelId: number | null;
	status: "firing" | "resolved" | "test";
	title: string;
	ok: boolean;
	error: string;
}

export interface Notifications {
	channels: Channel[];
	rules: Rule[];
	log: Delivery[];
	ruleTypes: { type: RuleType; severity: string; defaults: Record<string, string | number> }[];
	channelTypes: ChannelType[];
}

export const getNotifications = () => api.get({ url: "/npmos/notifications" }) as Promise<Notifications>;

export type ChannelInput = { name: string; type?: ChannelType; enabled?: boolean; config?: ChannelConfig };

export const createChannel = (data: ChannelInput) =>
	api.post({ url: "/npmos/notifications/channels", data }) as Promise<Channel>;
export const updateChannel = (id: number, data: Partial<ChannelInput>) =>
	api.put({ url: `/npmos/notifications/channels/${id}`, data }) as Promise<Channel>;
export const deleteChannel = (id: number) => api.del({ url: `/npmos/notifications/channels/${id}` });
export const testChannel = (id: number) =>
	api.post({ url: `/npmos/notifications/channels/${id}/test` }) as Promise<{ ok: boolean; error: string }>;

export type RuleInput = Omit<Rule, "id" | "active">;

export const createRule = (data: RuleInput) => api.post({ url: "/npmos/notifications/rules", data }) as Promise<Rule>;
export const updateRule = (id: number, data: Partial<RuleInput>) =>
	api.put({ url: `/npmos/notifications/rules/${id}`, data }) as Promise<Rule>;
export const deleteRule = (id: number) => api.del({ url: `/npmos/notifications/rules/${id}` });
