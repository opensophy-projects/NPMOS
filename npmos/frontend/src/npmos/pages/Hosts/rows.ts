// Hosts: proxy, redirection, stream and 404 hosts of NPMplus as rows of one table
// (docs/ROADMAP.md, phase 2 "Hosts: one table"). Pure functions: rows, filters, sorting,
// recommendations and export; the page and the cells live next to it.
import type { Certificate, DeadHost, ProxyHost, RedirectionHost, Stream } from "src/api/backend";
import type { HostLastChange, HostObjectType, UpstreamCheck, WafSettings } from "../../api";

export const HOST_TYPES = ["proxy", "redirect", "stream", "dead"] as const;
export type HostType = (typeof HOST_TYPES)[number];

export type HostStatus = "online" | "error" | "disabled";
export type TlsKind = "none" | "letsencrypt" | "custom";
export type WafState = "off" | "detect" | "prevent";
export type MtlsState = "off" | "required" | "optional";
export type UpstreamState = "ok" | "down";

/** object type of each host type in the audit log and the NPMOS API */
export const OBJECT_TYPE: Record<HostType, HostObjectType> = {
	proxy: "proxy-host",
	redirect: "redirection-host",
	stream: "stream",
	dead: "dead-host",
};

/** days before a certificate expires that make it "expiring" (yellow) */
export const EXPIRING_DAYS = 14;

export interface HostRow {
	/** unique across types: `${type}-${id}` */
	key: string;
	type: HostType;
	id: number;
	/** domains, or `:port` of a stream */
	names: string[];
	/** where traffic goes, as text */
	target: string;
	/** stream protocols (tcp, udp) */
	protocols: string[];
	enabled: boolean;
	status: HostStatus;
	error: string | null;
	certificate?: Certificate;
	tls: TlsKind;
	/** whole days until the certificate expires (negative: expired), null without TLS */
	expiresInDays: number | null;
	/** WAF exists only on proxy hosts */
	waf: WafState | null;
	mtls: MtlsState;
	mtlsCaId: number;
	/** proxy hosts: "public" or the names of the access lists */
	accessPublic: boolean | null;
	accessListIds: number[];
	group: string;
	modifiedOn: string;
	/** proxy hosts and TCP streams: whether every upstream accepts connections; null: not checked */
	upstream: UpstreamState | null;
	/** "host:port — error" of the upstreams that do not answer */
	upstreamErrors: string[];
	/** the last change in the audit log */
	change: HostLastChange | null;
	raw: ProxyHost | RedirectionHost | Stream | DeadHost;
}

const DAY = 24 * 60 * 60 * 1000;

const tlsKind = (certificate?: Certificate): TlsKind => {
	if (!certificate) return "none";
	return certificate.provider === "letsencrypt" ? "letsencrypt" : "custom";
};

const expiresIn = (certificate: Certificate | undefined, now: number): number | null => {
	if (!certificate?.expiresOn) return null;
	return Math.floor((new Date(certificate.expiresOn).getTime() - now) / DAY);
};

const statusOf = (enabled: boolean, meta: Record<string, any> | undefined): HostStatus => {
	if (!enabled) return "disabled";
	return meta?.nginxOnline === false ? "error" : "online";
};

const mtlsOf = (meta: Record<string, any> | undefined): { mtls: MtlsState; mtlsCaId: number } => {
	const id = Number(meta?.npmplusMtlsCertificateId) || 0;
	if (id <= 0) return { mtls: "off", mtlsCaId: 0 };
	return { mtls: meta?.npmplusMtlsVerifyClientOptional === true ? "optional" : "required", mtlsCaId: id };
};

const groupOf = (meta: Record<string, any> | undefined) =>
	typeof meta?.directory === "string" ? meta.directory.trim() : "";

const wafOf = (settings: WafSettings | undefined): WafState => {
	if (!settings?.enabled) return "off";
	return settings.mode === "prevent-learn" ? "prevent" : "detect";
};

export interface Sources {
	proxy?: ProxyHost[];
	redirect?: RedirectionHost[];
	stream?: Stream[];
	dead?: DeadHost[];
	waf?: Record<string, WafSettings>;
	upstreams?: UpstreamCheck[];
	changes?: HostLastChange[];
}

const common = (
	type: HostType,
	host: { id: number; enabled: boolean; meta: Record<string, any>; certificate?: Certificate; modifiedOn: string },
	now: number,
) => ({
	key: `${type}-${host.id}`,
	type,
	id: host.id,
	enabled: host.enabled,
	status: statusOf(host.enabled, host.meta),
	error: host.meta?.nginxErr || null,
	certificate: host.certificate,
	tls: tlsKind(host.certificate),
	expiresInDays: expiresIn(host.certificate, now),
	...mtlsOf(host.meta),
	group: groupOf(host.meta),
	modifiedOn: host.modifiedOn,
});

const upstreamOf = (checks: UpstreamCheck[]): Pick<HostRow, "upstream" | "upstreamErrors"> => {
	if (!checks.length) return { upstream: null, upstreamErrors: [] };
	const failed = checks.filter((c) => !c.ok);
	return {
		upstream: failed.length ? "down" : "ok",
		upstreamErrors: failed.map((c) => `${c.host}:${c.port} — ${c.error ?? "?"}`),
	};
};

export function toRows(sources: Sources, now = Date.now()): HostRow[] {
	const rows: HostRow[] = [];
	// both lists are joined to the rows by audit object type and id
	const extras = (type: HostType, id: number) => ({
		...upstreamOf((sources.upstreams ?? []).filter((c) => c.type === OBJECT_TYPE[type] && c.objectId === id)),
		change: sources.changes?.find((c) => c.type === OBJECT_TYPE[type] && c.objectId === id) ?? null,
	});
	for (const host of sources.proxy ?? []) {
		rows.push({
			...common("proxy", host, now),
			...extras("proxy", host.id),
			names: host.domainNames,
			target: `${host.forwardScheme}://${host.forwardHost}:${host.forwardPort}`,
			protocols: [],
			waf: wafOf(sources.waf?.[host.id]),
			accessPublic: host.npmplusAccessListType !== "custom" || !(host.npmplusAccessListIds ?? []).length,
			accessListIds: host.npmplusAccessListIds ?? [],
			raw: host,
		});
	}
	for (const host of sources.redirect ?? []) {
		const scheme = host.forwardScheme === "$scheme" ? "" : `${host.forwardScheme}://`;
		rows.push({
			...common("redirect", host, now),
			...extras("redirect", host.id),
			names: host.domainNames,
			target: `${host.forwardHttpCode} → ${scheme}${host.forwardDomainName}`,
			protocols: [],
			waf: null,
			accessPublic: null,
			accessListIds: [],
			raw: host,
		});
	}
	for (const host of sources.stream ?? []) {
		const protocols = [host.tcpForwarding && "tcp", host.udpForwarding && "udp"].filter(Boolean) as string[];
		rows.push({
			...common("stream", host, now),
			...extras("stream", host.id),
			names: [`:${host.incomingPort}`],
			target: `${host.forwardingHost}:${host.forwardingPort}`,
			protocols,
			waf: null,
			accessPublic: null,
			accessListIds: [],
			raw: host,
		});
	}
	for (const host of sources.dead ?? []) {
		rows.push({
			...common("dead", host, now),
			...extras("dead", host.id),
			names: host.domainNames,
			target: "",
			protocols: [],
			waf: null,
			accessPublic: null,
			accessListIds: [],
			raw: host,
		});
	}
	return rows;
}

// ---- filters (kept in the URL), as in the Cloudflare DNS table: field, operator, value ----

export type TlsFilter = TlsKind | "expiring";

/** fields with a fixed list of values */
export const ENUM_FIELDS = ["type", "status", "tls", "waf", "mtls", "access", "upstream", "group"] as const;
/** free-text fields */
export const TEXT_FIELDS = ["name", "target"] as const;
export type FilterField = (typeof ENUM_FIELDS)[number] | (typeof TEXT_FIELDS)[number];
export const FILTER_FIELDS: FilterField[] = [
	"name",
	"type",
	"target",
	"status",
	"tls",
	"waf",
	"mtls",
	"access",
	"upstream",
	"group",
];
export const isTextField = (field: FilterField) => (TEXT_FIELDS as readonly string[]).includes(field);

/** is / is not for lists; contains / does not contain for text */
export type FilterOp = "is" | "not" | "has" | "nothas";
export const opsFor = (field: FilterField): FilterOp[] => (isTextField(field) ? ["has", "nothas"] : ["is", "not"]);

export interface FilterRule {
	field: FilterField;
	op: FilterOp;
	value: string;
}

export interface Filters {
	/** the search field */
	q: string;
	rules: FilterRule[];
}

export const emptyFilters = (): Filters => ({ q: "", rules: [] });

/** `f=field:op:value` (repeated); the value may contain ":" */
export function filtersFromParams(params: URLSearchParams): Filters {
	const rules: FilterRule[] = [];
	for (const raw of params.getAll("f")) {
		const [field, op, ...rest] = raw.split(":");
		const value = rest.join(":");
		if (!(FILTER_FIELDS as string[]).includes(field) || !value) continue;
		if (!opsFor(field as FilterField).includes(op as FilterOp)) continue;
		rules.push({ field: field as FilterField, op: op as FilterOp, value });
	}
	// links of the first version of the page: ?type=proxy
	for (const value of params.getAll("type")) {
		if ((HOST_TYPES as readonly string[]).includes(value)) rules.push({ field: "type", op: "is", value });
	}
	return { q: params.get("q") ?? "", rules };
}

export function filtersToParams(filters: Filters, params = new URLSearchParams()): URLSearchParams {
	const next = new URLSearchParams(params);
	if (filters.q) next.set("q", filters.q);
	else next.delete("q");
	next.delete("f");
	next.delete("type");
	for (const rule of filters.rules) {
		if (rule.value) next.append("f", `${rule.field}:${rule.op}:${rule.value}`);
	}
	return next;
}

const isExpiring = (row: HostRow) => row.expiresInDays !== null && row.expiresInDays < EXPIRING_DAYS;

/** does the row have this value in the field (enum fields) or contain the text (text fields) */
function fieldMatches(row: HostRow, field: FilterField, value: string): boolean {
	switch (field) {
		case "name":
			return row.names.some((n) => n.toLowerCase().includes(value.toLowerCase()));
		case "target":
			return row.target.toLowerCase().includes(value.toLowerCase());
		case "type":
			return row.type === value;
		case "status":
			return row.status === value;
		case "tls":
			return value === "expiring" ? isExpiring(row) : row.tls === value;
		case "waf":
			return row.waf === value;
		case "mtls":
			return row.mtls === value;
		case "access":
			if (row.accessPublic === null) return false;
			return value === "public"
				? row.accessPublic
				: !row.accessPublic && row.accessListIds.includes(Number(value));
		case "upstream":
			return row.upstream === value;
		case "group":
			return row.group === value;
	}
}

/**
 * Search plus rules. Rules "is" on the same field are alternatives (type is Proxy or Redirect),
 * every other rule must hold.
 */
export function matches(row: HostRow, filters: Filters): boolean {
	const q = filters.q.trim().toLowerCase();
	if (q) {
		const haystack = [...row.names, row.target, row.group, ...row.protocols].join(" ").toLowerCase();
		if (!haystack.includes(q)) return false;
	}
	const alternatives = new Map<FilterField, boolean>();
	for (const rule of filters.rules) {
		const hit = fieldMatches(row, rule.field, rule.value);
		if (rule.op === "is") {
			alternatives.set(rule.field, (alternatives.get(rule.field) ?? false) || hit);
		} else if (rule.op === "has") {
			if (!hit) return false;
		} else if (hit) {
			return false;
		}
	}
	return [...alternatives.values()].every(Boolean);
}

// ---- sorting ----

export type SortKey = "name" | "type" | "target" | "tls" | "waf" | "mtls" | "group" | "status" | "changed";
export interface Sort {
	key: SortKey;
	desc: boolean;
}

const rank: Record<string, number> = {
	// types in the order of the "Add" menu
	proxy: 0,
	redirect: 1,
	stream: 2,
	dead: 3,
	online: 0,
	error: 1,
	disabled: 2,
	off: 0,
	detect: 1,
	prevent: 2,
	required: 1,
	optional: 2,
};

const sortValue = (row: HostRow, key: SortKey): string | number => {
	switch (key) {
		case "name":
			// domains first, then stream ports
			return `${row.type === "stream" ? 1 : 0}${row.names[0] ?? ""}`;
		case "type":
			return rank[row.type];
		case "target":
			return row.target;
		case "tls":
			// soonest expiry first, hosts without TLS last
			return row.expiresInDays ?? Number.MAX_SAFE_INTEGER;
		case "waf":
			return row.waf === null ? -1 : rank[row.waf];
		case "mtls":
			return rank[row.mtls] ?? 0;
		case "group":
			return row.group || "￿";
		case "status":
			return rank[row.status];
		case "changed":
			// the newest change first
			return -(row.change ? new Date(row.change.createdOn).getTime() : 0);
	}
};

export function sortRows(rows: HostRow[], sort: Sort): HostRow[] {
	const dir = sort.desc ? -1 : 1;
	return [...rows].sort((a, b) => {
		const x = sortValue(a, sort.key);
		const y = sortValue(b, sort.key);
		const cmp =
			typeof x === "number" && typeof y === "number"
				? x - y
				: String(x).localeCompare(String(y), undefined, { numeric: true });
		return cmp * dir || (a.names[0] ?? "").localeCompare(b.names[0] ?? "");
	});
}

// ---- recommendations ----

export type RecommendationId =
	| "waf-global-off"
	| "no-tls"
	| "expired"
	| "expiring"
	| "nginx-error"
	| "upstream-down"
	| "waf-off"
	| "waf-detect";

export interface Recommendation {
	id: RecommendationId;
	/** alert: red, warning: yellow, info: neutral */
	level: "alert" | "warning" | "info";
	rows: HostRow[];
	/** filter rules that show the affected hosts */
	filter: FilterRule[];
}

export function recommendations(rows: HostRow[], wafGloballyEnabled: boolean | undefined): Recommendation[] {
	const active = rows.filter((r) => r.enabled);
	const web = active.filter((r) => r.type !== "stream");
	const proxies = active.filter((r) => r.type === "proxy");
	const list: Recommendation[] = [
		{
			id: "expired",
			level: "alert",
			rows: active.filter((r) => r.expiresInDays !== null && r.expiresInDays < 0),
			filter: [{ field: "tls", op: "is", value: "expiring" }],
		},
		{
			id: "nginx-error",
			level: "alert",
			rows: active.filter((r) => r.status === "error"),
			filter: [{ field: "status", op: "is", value: "error" }],
		},
		{
			id: "upstream-down",
			level: "alert",
			rows: active.filter((r) => r.upstream === "down"),
			filter: [{ field: "upstream", op: "is", value: "down" }],
		},
		{
			id: "expiring",
			level: "warning",
			rows: active.filter(
				(r) => r.expiresInDays !== null && r.expiresInDays >= 0 && r.expiresInDays < EXPIRING_DAYS,
			),
			filter: [{ field: "tls", op: "is", value: "expiring" }],
		},
		{
			id: "no-tls",
			level: "warning",
			rows: web.filter((r) => r.tls === "none"),
			filter: [{ field: "tls", op: "is", value: "none" }],
		},
		{
			id: "waf-global-off",
			level: "warning",
			rows: wafGloballyEnabled === false ? proxies.filter((r) => r.waf !== "off") : [],
			filter: [{ field: "type", op: "is", value: "proxy" }],
		},
		{
			id: "waf-off",
			level: "info",
			rows: proxies.filter((r) => r.waf === "off" && r.accessPublic),
			filter: [
				{ field: "type", op: "is", value: "proxy" },
				{ field: "waf", op: "is", value: "off" },
				{ field: "access", op: "is", value: "public" },
			],
		},
		{
			id: "waf-detect",
			level: "info",
			rows: proxies.filter((r) => r.waf === "detect"),
			filter: [{ field: "waf", op: "is", value: "detect" }],
		},
	];
	return list.filter((r) => r.rows.length);
}

// ---- export / import ----

export const EXPORT_FORMAT = "npmos-hosts";

/** fields of the API objects that are not settings of a host (accessListId: legacy, not accepted on create) */
const READONLY = [
	"id",
	"createdOn",
	"modifiedOn",
	"ownerUserId",
	"owner",
	"certificate",
	"accessLists",
	"accessListId",
];
const META_STATE = ["nginxOnline", "nginxErr"];

/** the settings of a host as the create API accepts them: no state, no empty (null) fields */
const settingsOf = (host: Record<string, any>) => {
	const data: Record<string, any> = {};
	for (const [key, value] of Object.entries(host)) {
		if (!READONLY.includes(key) && value !== null && value !== undefined) data[key] = value;
	}
	data.meta = { ...(host.meta ?? {}) };
	for (const key of META_STATE) delete data.meta[key];
	return data;
};

export function exportData(rows: HostRow[]) {
	return {
		format: EXPORT_FORMAT,
		version: 1,
		exportedAt: new Date().toISOString(),
		hosts: rows.map((row) => ({ type: row.type, data: settingsOf(row.raw) })),
	};
}

const csvCell = (value: string) => (/[",\n;]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value);

export function exportCsv(rows: HostRow[]): string {
	const head = ["name", "type", "target", "tls", "expires_in_days", "waf", "mtls", "access", "group", "status"];
	const lines = rows.map((r) =>
		[
			r.names.join(" "),
			r.type,
			r.target,
			r.tls,
			r.expiresInDays === null ? "" : String(r.expiresInDays),
			r.waf ?? "",
			r.mtls,
			r.accessPublic === null ? "" : r.accessPublic ? "public" : r.accessListIds.join(" "),
			r.group,
			r.status,
		]
			.map(csvCell)
			.join(","),
	);
	return [head.join(","), ...lines].join("\n");
}

export interface ImportItem {
	type: HostType;
	data: Record<string, any>;
}

/**
 * Validates an exported file and prepares the create payloads: references to certificates
 * and access lists that do not exist here are dropped (the host is created without them).
 */
export function parseImport(
	text: string,
	known: { certificateIds: number[]; accessListIds: number[] },
): { items: ImportItem[]; dropped: number } {
	const file = JSON.parse(text);
	if (file?.format !== EXPORT_FORMAT || !Array.isArray(file.hosts)) {
		throw new Error("format");
	}
	let dropped = 0;
	const items = file.hosts
		.filter((h: any) => (HOST_TYPES as readonly string[]).includes(h?.type) && h.data && typeof h.data === "object")
		.map((h: any) => {
			const data = settingsOf(h.data);
			if (data.certificateId && !known.certificateIds.includes(data.certificateId)) {
				data.certificateId = 0;
				dropped++;
			}
			const mtls = Number(data.meta.npmplusMtlsCertificateId) || 0;
			if (mtls && !known.certificateIds.includes(mtls)) {
				data.meta.npmplusMtlsCertificateId = 0;
				dropped++;
			}
			if (Array.isArray(data.npmplusAccessListIds)) {
				const ids = data.npmplusAccessListIds.filter((id: number) => known.accessListIds.includes(id));
				dropped += data.npmplusAccessListIds.length - ids.length;
				data.npmplusAccessListIds = ids;
			}
			return { type: h.type as HostType, data };
		});
	return { items, dropped };
}
