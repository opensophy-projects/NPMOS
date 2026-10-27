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
	/** visible when any of these sections is visible */
	anyOf?: Section[];
	permission?: Permission;
}

export const navigation: NavItem[] = [
	{ id: "overview", label: "npmos.nav.overview", to: "/" },
	// proxy, redirection, stream and 404 hosts in one table (src/npmos/pages/Hosts)
	{
		id: "hosts",
		label: "npmos.nav.hosts",
		to: "/hosts",
		anyOf: [PROXY_HOSTS, REDIRECTION_HOSTS, STREAMS, DEAD_HOSTS],
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
		const allowed = (section: Section) =>
			hasPermission(section, item.permission || VIEW, me?.permissions, me?.roles);
		if (item.section && !allowed(item.section)) {
			return [];
		}
		if (item.anyOf && !item.anyOf.some(allowed)) {
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
