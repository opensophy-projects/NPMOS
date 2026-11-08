// Important notices of the overview (docs/ROADMAP.md, phase 2 "Overview"): what needs the
// administrator now, from data the UI already has. Phase 4 moves them into notifications.
import type { Certificate } from "src/api/backend";
import type { CertTerm, Service, WafStatus } from "../../api";
import { type FilterRule, filtersToParams, type Recommendation } from "../Hosts/rows";

export type NoticeLevel = "alert" | "warning" | "info";

export interface Notice {
	key: string;
	level: NoticeLevel;
	/** translation id of the text; `${id}.hint` explains what to do */
	id: string;
	data?: Record<string, string | number>;
	/** where it is fixed */
	link: string;
}

const DAY = 24 * 60 * 60 * 1000;
/** custom certificates and mTLS CAs are replaced by hand: warn two weeks ahead */
const CERT_WARN_DAYS = 14;
/** Let's Encrypt renews itself 30 days ahead: a week left means renewal fails */
const LE_WARN_DAYS = 7;

const hostsLink = (rules: FilterRule[]) => `/hosts?${filtersToParams({ q: "", rules }).toString()}`;

/** alerts and warnings of the hosts table (tips stay on the hosts page) */
export const hostNotices = (recs: Recommendation[]): Notice[] =>
	recs
		.filter((r) => r.level !== "info")
		.map((r) => ({
			key: `hosts-${r.id}`,
			level: r.level,
			id: `nginxions.hosts.rec.${r.id}`,
			data: { count: r.rows.length },
			link: hostsLink(r.filter),
		}));

/**
 * Expiring certificates and mTLS CAs. Certificates of hosts are already in the host notices
 * (`attached`: their ids), so only the others are listed here.
 */
export function certificateNotices(
	certificates: Certificate[],
	attached: number[] = [],
	now = Date.now(),
	terms?: Record<string, CertTerm>,
): Notice[] {
	const notices: Notice[] = [];
	for (const cert of certificates) {
		if (!cert.expiresOn || (cert.provider !== "mtls" && attached.includes(cert.id))) continue;
		const days = Math.floor((new Date(cert.expiresOn).getTime() - now) / DAY);
		// by the term of the certificate when NginxionS knows it (a renewal is late, or it must be replaced soon)
		const from = cert.provider !== "mtls" ? terms?.[String(cert.id)]?.attentionFrom : null;
		if (from) {
			if (days >= 0 && now < new Date(from).getTime()) continue;
		} else if (days >= (cert.provider === "letsencrypt" ? LE_WARN_DAYS : CERT_WARN_DAYS)) continue;
		const kind = cert.provider === "mtls" ? "ca" : "cert";
		notices.push({
			key: `cert-${cert.id}`,
			level: days < 0 ? "alert" : "warning",
			id: `nginxions.overview.notice.${kind}-${days < 0 ? "expired" : "expiring"}`,
			data: { name: cert.niceName || cert.domainNames?.[0] || `#${cert.id}`, days: Math.max(days, 0) },
			link: "/certificates",
		});
	}
	return notices;
}

export function wafNotices(status: WafStatus | undefined): Notice[] {
	if (!status?.enabled) return [];
	const notices: Notice[] = [];
	if (status.agent && !status.agent.reachable) {
		notices.push({
			key: "waf-agent",
			level: "alert",
			id: "nginxions.overview.notice.agent-down",
			link: "/agents/open-appsec?tab=agent",
		});
	}
	if (status.policy?.applied && !status.policy.applied.ok) {
		notices.push({
			key: "waf-policy",
			level: "alert",
			id: "nginxions.overview.notice.policy-failed",
			data: { error: status.policy.applied.error ?? "" },
			link: "/agents/open-appsec?tab=agent",
		});
	}
	if (status.restartRequired) {
		notices.push({
			key: "waf-restart",
			level: "warning",
			id: "nginxions.overview.notice.waf-restart",
			link: "/agents/open-appsec?tab=agent",
		});
	}
	return notices;
}

export const serviceProblem = (service: Service) => service.state !== "running" || /\(unhealthy\)/.test(service.status);

export function serviceNotices(services: Service[] | undefined): Notice[] {
	return (services ?? []).filter(serviceProblem).map((service) => ({
		key: `service-${service.service}`,
		level: "alert",
		id: "nginxions.overview.notice.service-down",
		data: { name: service.name || service.service, state: service.status || service.state },
		link: "/system/services",
	}));
}

const ORDER: Record<NoticeLevel, number> = { alert: 0, warning: 1, info: 2 };

export const sortNotices = (notices: Notice[]) => [...notices].sort((a, b) => ORDER[a.level] - ORDER[b.level]);
