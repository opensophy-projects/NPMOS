// Learning of the agent (/api/npmos/learning/*), see npmos/backend/npmos/learning
import * as api from "src/api/backend/base";

export type Decision = "benign" | "malicious" | "dismiss";
export type ScopeType = "parameterValue" | "parameterName" | "url" | "source";
export type Reason = "blocked" | "grey" | "detected";

export interface Scope {
	type: ScopeType;
	value: string;
}

export interface QueueGroup {
	key: string;
	hostId: number;
	hostName: string;
	hostMode: string | null;
	host: string;
	uri: string;
	parameter: string;
	indicators: string;
	incidentType: string;
	sample: string;
	eventId: number | null;
	events: number;
	sources: number;
	blocked: number;
	score: number | null;
	first: string | null;
	last: string | null;
	reason: Reason;
	new: boolean;
	scopes: Scope[];
}

export interface Suggestion {
	id: string;
	asset: string;
	hostId: number;
	hostName: string;
	type: ScopeType;
	title: string;
	severity: string;
	attackTypes: string[];
	metrics: { name: string; value: number }[];
}

export interface Queue {
	period: string;
	total: number;
	counts: Record<Reason, number>;
	limit: number;
	offset: number;
	items: QueueGroup[];
	suggestions: Suggestion[];
	suggestionsError: string | null;
}

export interface GroupDetails extends QueueGroup {
	sourceList: { ip: string; events: number }[];
	labelled: boolean;
}

export interface Label {
	id: number;
	createdOn: string;
	user: { id: number; name: string } | null;
	origin: "group" | "tuning";
	hostId: number | null;
	host: string;
	decision: Decision;
	scopes: Scope[];
	features: Record<string, any>;
	note: string;
	exception: boolean;
	exceptionActive: boolean;
	expiresOn: string | null;
	banned: string[];
	banDuration: string;
	syncedOn: string | null;
	syncError: string;
	undoneOn: string | null;
	undoneBy: { id: number; name: string } | null;
}

export interface LabelsPage {
	items: Label[];
	total: number;
	limit: number;
	offset: number;
}

export interface HostStats {
	readiness: string;
	level: number;
	recommendation: string;
	ready: boolean;
	requests: number;
	elapsed: string;
}

export interface LearningHost {
	id: number;
	name: string;
	mode: string;
	minimumConfidence: string;
	stats: HostStats | null;
	labels: { benign: number; malicious: number; dismiss: number; exceptions: number };
	enforced: number;
	falsePositives: { before: number; after: number };
	queue: number;
	readyToPrevent: boolean;
}

export interface LabelInput {
	key?: string;
	/** an event of the group (the group of an event card may be out of the queue) */
	eventId?: number;
	suggestion?: Suggestion;
	decision: Decision;
	scopes?: Scope[];
	exception?: boolean;
	ttlDays?: number;
	ban?: boolean;
	banDuration?: string;
	note?: string;
}

export const TTL_DAYS = [7, 14, 30, 90, 0];
export const BAN_DURATIONS = ["1h", "4h", "24h", "168h", "720h"];

export const getQueue = (params: Record<string, string | number | undefined>): Promise<Queue> =>
	api.get({ url: "/npmos/learning/queue", params });

export const getGroup = (key: string): Promise<GroupDetails> =>
	api.get({ url: `/npmos/learning/groups/${encodeURIComponent(key)}` });

export const getEventGroup = (eventId: string | number): Promise<GroupDetails> =>
	api.get({ url: `/npmos/learning/events/${eventId}/group` });

export const getLabels = (params: Record<string, string | number | undefined>): Promise<LabelsPage> =>
	api.get({ url: "/npmos/learning/labels", params });

export const createLabel = (data: LabelInput): Promise<Label | { id: number }> =>
	api.post({ url: "/npmos/learning/labels", data });

export const undoLabel = (id: number): Promise<{ ok: boolean }> => api.del({ url: `/npmos/learning/labels/${id}` });

export const getLearningHosts = (): Promise<{ hosts: LearningHost[]; tenant: string | null; error: string | null }> =>
	api.get({ url: "/npmos/learning/hosts" });
