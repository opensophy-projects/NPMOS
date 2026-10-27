// Sidebar navigation (docs/ROADMAP.md, phase 2). Only pages that exist are listed; WAF
// analytics, CrowdSec, PKI, roles, notifications and updates join their groups in later phases.
import {
	ACCESS_LISTS,
	ADMIN,
	CERTIFICATES,
	DEAD_HOSTS,
	hasPermission,
	type Permission,
	PROXY_HOSTS,
	REDIRECTION_HOSTS,
	type Section,
	STREAMS,
	VIEW,
} from "src/modules/Permissions";

export interface NavItem {
	/** unique, also the key of the expanded state */
	id: string;
	/** translation id */
	label: string;
	to?: string;
	items?: NavItem[];
	section?: Section;
	permission?: Permission;
}

export const navigation: NavItem[] = [
	{ id: "overview", label: "npmos.nav.overview", to: "/" },
	{
		id: "hosts",
		label: "npmos.nav.hosts",
		items: [
			{ id: "proxy", label: "proxy-hosts", to: "/nginx/proxy", section: PROXY_HOSTS },
			{ id: "redirection", label: "redirection-hosts", to: "/nginx/redirection", section: REDIRECTION_HOSTS },
			{ id: "streams", label: "streams", to: "/nginx/stream", section: STREAMS },
			{ id: "dead", label: "dead-hosts", to: "/nginx/404", section: DEAD_HOSTS },
		],
	},
	{
		id: "security",
		label: "npmos.nav.security",
		items: [
			{
				id: "waf",
				label: "npmos.waf",
				items: [
					{ id: "waf-events", label: "npmos.waf.events", to: "/waf/events", section: ADMIN },
					{ id: "waf-policy", label: "npmos.waf.expert", to: "/waf/policy", section: ADMIN },
					{ id: "waf-agent", label: "npmos.waf.agent", to: "/waf/agent", section: ADMIN },
				],
			},
			{ id: "access", label: "access-lists", to: "/access", section: ACCESS_LISTS },
		],
	},
	{ id: "certificates", label: "certificates", to: "/certificates", section: CERTIFICATES },
	{
		id: "administration",
		label: "npmos.nav.administration",
		items: [
			{ id: "users", label: "users", to: "/users", section: ADMIN },
			{ id: "audit", label: "auditlogs", to: "/audit-log", section: ADMIN },
		],
	},
	{
		id: "system",
		label: "npmos.nav.system",
		items: [
			{ id: "services", label: "npmos.services", to: "/system/services", section: ADMIN },
			{ id: "settings", label: "settings", to: "/settings", section: ADMIN },
		],
	},
];

type Me = { permissions?: Parameters<typeof hasPermission>[2]; roles?: string[] } | undefined;

/** Items the user may see; a group without visible items disappears. */
export const visibleItems = (items: NavItem[], me: Me): NavItem[] =>
	items.flatMap((item) => {
		if (item.items) {
			const children = visibleItems(item.items, me);
			return children.length ? [{ ...item, items: children }] : [];
		}
		if (item.section && !hasPermission(item.section, item.permission || VIEW, me?.permissions, me?.roles)) {
			return [];
		}
		return [item];
	});

/** Items whose label (or a parent's label) contains the query. */
export const filterItems = (items: NavItem[], query: string, translate: (id: string) => string): NavItem[] => {
	const q = query.trim().toLocaleLowerCase();
	if (!q) return items;
	return items.flatMap((item) => {
		if (translate(item.label).toLocaleLowerCase().includes(q)) {
			return [item];
		}
		if (item.items) {
			const children = filterItems(item.items, q, translate);
			return children.length ? [{ ...item, items: children }] : [];
		}
		return [];
	});
};

export const isActivePath = (to: string, pathname: string) =>
	to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(`${to}/`);

export const containsActive = (item: NavItem, pathname: string): boolean =>
	item.to ? isActivePath(item.to, pathname) : (item.items?.some((c) => containsActive(c, pathname)) ?? false);
