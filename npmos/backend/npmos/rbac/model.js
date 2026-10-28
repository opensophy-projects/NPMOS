// RBAC of NPMOS (docs/ROADMAP.md, phase 3; docs/adr/0007-rbac.md): resources, actions, built-in
// roles and the rules that turn the roles of a user into permissions. Pure functions, no database.
//
// Roles are the source of permissions. Upstream NPMplus keeps per-user permissions in
// user_permission (visibility + hidden/view/manage of six sections) and an "admin" flag in
// user.roles; NPMOS writes user_permission as the projection of the roles, and the "admin" flag
// is the built-in Administrator role.

/** resource → actions; any action other than "view" implies "view" */
export const RESOURCES = {
	proxy_hosts: ["view", "manage"],
	redirection_hosts: ["view", "manage"],
	streams: ["view", "manage"],
	dead_hosts: ["view", "manage"],
	access_lists: ["view", "manage"],
	certificates: ["view", "manage"],
	pki: ["view", "manage", "issue", "revoke", "export_key"],
	waf_policy: ["view", "manage", "apply"],
	waf_events: ["view"],
	waf_learning: ["view", "label"],
	analytics: ["view"],
	crowdsec: ["view", "manage"],
	notifications: ["view", "manage"],
	services: ["view", "manage"],
	users: ["view", "manage"],
	roles: ["view", "manage"],
	settings: ["view", "manage"],
	audit_log: ["view"],
};

/** the sections of upstream user_permission, by resource */
export const UPSTREAM_SECTIONS = [
	"proxy_hosts",
	"redirection_hosts",
	"dead_hosts",
	"streams",
	"access_lists",
	"certificates",
];

export const SCOPES = ["all", "own"];

export const ALL_PERMISSIONS = Object.entries(RESOURCES).flatMap(([resource, actions]) =>
	actions.map((action) => `${resource}:${action}`),
);

const all = (resource) => RESOURCES[resource].map((action) => `${resource}:${action}`);
const view = (...resources) => resources.map((resource) => `${resource}:view`);

const HOSTS = ["proxy_hosts", "redirection_hosts", "streams", "dead_hosts"];

/**
 * Built-in roles: their permissions live here (updated with NPMOS), only their OIDC groups are
 * edited. Administrator is the "admin" flag of upstream: everything, including what has no
 * permission label (login as another user, setting another user's password).
 */
export const BUILTIN = {
	administrator: { name: "Administrator", scope: "all", permissions: ALL_PERMISSIONS },
	operator: {
		name: "Operator",
		scope: "all",
		permissions: [
			...HOSTS.flatMap(all),
			...all("access_lists"),
			...all("certificates"),
			"pki:view",
			"pki:issue",
			"pki:revoke",
			...all("waf_policy"),
			"waf_events:view",
			"waf_learning:view",
			"analytics:view",
			...all("crowdsec"),
			"notifications:view",
			...all("services"),
			"audit_log:view",
		],
	},
	security_analyst: {
		name: "Security Analyst",
		scope: "all",
		permissions: [
			...view(...HOSTS, "access_lists", "certificates", "pki"),
			...all("waf_policy"),
			"waf_events:view",
			...all("waf_learning"),
			"analytics:view",
			...all("crowdsec"),
			"notifications:view",
			"audit_log:view",
		],
	},
	viewer: {
		name: "Viewer",
		scope: "all",
		permissions: view(
			...HOSTS,
			"access_lists",
			"certificates",
			"pki",
			"waf_policy",
			"waf_events",
			"waf_learning",
			"analytics",
			"crowdsec",
			"notifications",
			"services",
		),
	},
};

/** known permissions only, each other action adds its "view" */
export function normalize(permissions) {
	const result = new Set();
	for (const permission of permissions) {
		const [resource, action] = String(permission).split(":");
		if (!RESOURCES[resource]?.includes(action)) continue;
		result.add(permission);
		result.add(`${resource}:view`);
	}
	return [...result].sort((a, b) => ALL_PERMISSIONS.indexOf(a) - ALL_PERMISSIONS.indexOf(b));
}

/**
 * Permissions of a user from the roles.
 * @param {boolean} admin  upstream "admin" flag (= Administrator)
 * @param {Array<{scope: string, permissions: string[]}>} roles
 * @returns {{admin: boolean, scope: "all"|"own", permissions: Set<string>}}
 */
export function effective(admin, roles) {
	if (admin) {
		return { admin: true, scope: "all", permissions: new Set(ALL_PERMISSIONS) };
	}
	const permissions = new Set(roles.flatMap((role) => normalize(role.permissions)));
	// one role that sees all hosts is enough (roles add up)
	const scope = roles.some((role) => role.scope === "all") ? "all" : "own";
	return { admin: false, scope, permissions };
}

/** the upstream user_permission row of these permissions */
export function projection(eff) {
	const row = { visibility: eff.scope === "all" ? "all" : "user" };
	for (const section of UPSTREAM_SECTIONS) {
		row[section] = eff.permissions.has(`${section}:manage`)
			? "manage"
			: eff.permissions.has(`${section}:view`)
				? "view"
				: "hidden";
	}
	return row;
}

/** the permissions of an upstream user_permission row (migration to roles) */
export function fromProjection(row) {
	const permissions = [];
	for (const section of UPSTREAM_SECTIONS) {
		if (row[section] === "manage") permissions.push(`${section}:view`, `${section}:manage`);
		else if (row[section] === "view") permissions.push(`${section}:view`);
	}
	return { scope: row.visibility === "all" ? "all" : "own", permissions };
}

/**
 * Upstream sections that only the admin flag opened: the permission that opens them to a role.
 * `target`: the label acts on another user, never on an administrator (unless by one).
 */
export const UPSTREAM_GRANTS = {
	"auditlog:list": { permission: "audit_log:view" },
	"settings:list": { permission: "settings:view" },
	"settings:get": { permission: "settings:view" },
	"settings:update": { permission: "settings:manage" },
	"users:list": { permission: "users:view" },
	"users:get": { permission: "users:view" },
	"users:create": { permission: "users:manage", target: true },
	"users:update": { permission: "users:manage", target: true },
	"users:delete": { permission: "users:manage", target: true },
	"users:password": { permission: "users:manage", target: true },
};

/**
 * Decision on a permission label of access.can().
 * @param {string} label  "resource:action"
 * @param {{admin: boolean, scope: string, permissions: Set<string>}} eff
 * @param {{targetIsAdmin?: boolean}} [context]
 * @returns {"grant"|"deny"|"upstream"} upstream: let the upstream schema decide
 */
export function decide(label, eff, context = {}) {
	const [resource, action] = label.split(":");
	// labels of NPMOS resources (the upstream host sections use their own labels: list, get, ...)
	if (RESOURCES[resource]?.includes(action)) {
		return eff.permissions.has(label) ? "grant" : "deny";
	}
	// upstream per-user permissions are replaced by roles
	if (label === "users:permissions") {
		return eff.admin ? "upstream" : "deny";
	}
	const grant = UPSTREAM_GRANTS[label];
	if (grant && !eff.admin && eff.permissions.has(grant.permission)) {
		if (grant.target && context.targetIsAdmin) return "upstream";
		return "grant";
	}
	return "upstream";
}

/**
 * Who may give these permissions away: nobody can create or assign more than they have.
 * @returns {string[]} the permissions the actor lacks (empty: allowed)
 */
export function missing(actor, permissions, scope = "own") {
	if (actor.admin) return [];
	const lacking = normalize(permissions).filter((p) => !actor.permissions.has(p));
	if (scope === "all" && actor.scope !== "all") lacking.push("scope:all");
	return lacking;
}
