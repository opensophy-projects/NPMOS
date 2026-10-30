// Sidebar navigation: sections with their pages as tabs (SectionTabs). Only pages that exist are listed.
// Items of NPMOS sections are shown by the roles of the user (`rbac`: resource whose "view" opens it).
import {
	ACCESS_LISTS,
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
	/** pages of a section: one item in the sidebar, tabs above the page (SectionTabs) */
	tabs?: NavItem[];
	section?: Section;
	/** visible when any of these sections is visible */
	anyOf?: Section[];
	permission?: Permission;
	/** RBAC resource (npmos/rbac): visible with its "view" */
	rbac?: string;
}

// Six sections, each a set of pages shown as tabs: few items in the sidebar, related pages next to
// each other. The addresses of the pages stay as they were (links and bookmarks keep working).
export const navigation: NavItem[] = [
	{
		id: "overview",
		label: "npmos.nav.overview",
		tabs: [
			{ id: "overview-status", label: "npmos.nav.overview", to: "/" },
			{ id: "services", label: "npmos.services", to: "/system/services", rbac: "services" },
		],
	},
	{
		id: "hosts",
		label: "npmos.nav.hosts",
		tabs: [
			// proxy, redirection, stream and 404 hosts in one table (src/npmos/pages/Hosts)
			{
				id: "hosts-list",
				label: "npmos.nav.hosts",
				to: "/hosts",
				anyOf: [PROXY_HOSTS, REDIRECTION_HOSTS, STREAMS, DEAD_HOSTS],
			},
			{ id: "access", label: "access-lists", to: "/access", section: ACCESS_LISTS },
		],
	},
	{
		id: "analytics",
		label: "npmos.nav.analytics",
		tabs: [
			{ id: "waf-analytics", label: "npmos.analytics", to: "/waf/analytics", rbac: "analytics" },
			{ id: "waf-events", label: "npmos.waf.events", to: "/waf/events", rbac: "waf_events" },
			{ id: "audit", label: "auditlogs", to: "/audit-log", rbac: "audit_log" },
		],
	},
	{
		id: "certificates-group",
		label: "certificates",
		tabs: [
			{ id: "certificates", label: "npmos.nav.all-certs", to: "/certificates", section: CERTIFICATES },
			{ id: "mtls", label: "npmos.nav.mtls", to: "/mtls", rbac: "pki" },
			{ id: "pki", label: "npmos.pki", to: "/pki", rbac: "pki" },
		],
	},
	{
		id: "agents",
		label: "npmos.nav.agents",
		tabs: [
			// one page per agent: its policies (GUI or code) and the agent itself
			{
				id: "agent-openappsec",
				label: "npmos.nav.agent-openappsec",
				to: "/agents/open-appsec",
				rbac: "waf_policy",
			},
			{ id: "crowdsec", label: "npmos.crowdsec", to: "/crowdsec", rbac: "crowdsec" },
		],
	},
	{
		id: "administration",
		label: "npmos.nav.administration",
		tabs: [
			{ id: "users", label: "users", to: "/users", rbac: "users" },
			{ id: "roles", label: "npmos.rbac.roles", to: "/roles", rbac: "roles" },
			{ id: "notifications", label: "npmos.notifications", to: "/system/notifications", rbac: "notifications" },
			{ id: "settings", label: "settings", to: "/settings", rbac: "settings" },
		],
	},
];

type Me = { permissions?: Parameters<typeof hasPermission>[2]; roles?: string[] } | undefined;

/** Items the user may see; a group without visible items disappears. */
export const visibleItems = (items: NavItem[], me: Me, can: (resource: string) => boolean): NavItem[] =>
	items.flatMap((item) => {
		if (item.items) {
			const children = visibleItems(item.items, me, can);
			return children.length ? [{ ...item, items: children }] : [];
		}
		if (item.tabs) {
			// the section opens on its first page the user may see
			const tabs = visibleItems(item.tabs, me, can);
			return tabs.length ? [{ ...item, tabs, to: tabs[0].to }] : [];
		}
		const allowed = (section: Section) =>
			hasPermission(section, item.permission || VIEW, me?.permissions, me?.roles);
		if (item.section && !allowed(item.section)) {
			return [];
		}
		if (item.anyOf && !item.anyOf.some(allowed)) {
			return [];
		}
		if (item.rbac && !can(item.rbac)) {
			return [];
		}
		return [item];
	});

export const isActivePath = (to: string, pathname: string) =>
	to === "/" ? pathname === "/" : pathname === to || pathname.startsWith(`${to}/`);

export const containsActive = (item: NavItem, pathname: string): boolean =>
	item.tabs
		? item.tabs.some((c) => containsActive(c, pathname))
		: item.to
			? isActivePath(item.to, pathname)
			: (item.items?.some((c) => containsActive(c, pathname)) ?? false);

/** the section (of the visible ones) the page belongs to */
export const sectionOf = (items: NavItem[], pathname: string): NavItem | undefined =>
	items.find((item) => item.tabs && containsActive(item, pathname));
