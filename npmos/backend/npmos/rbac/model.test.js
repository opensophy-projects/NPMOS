// node --test npmos/ (CI: backend job)
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BUILTIN, decide, effective, fromProjection, missing, normalize, projection } from "./model.js";

const UPSTREAM_DEFAULT = {
	visibility: "user",
	proxy_hosts: "manage",
	redirection_hosts: "manage",
	dead_hosts: "manage",
	streams: "manage",
	access_lists: "manage",
	certificates: "view",
};

describe("rbac model", () => {
	it("moves upstream permissions to a role and back without change", () => {
		const role = fromProjection(UPSTREAM_DEFAULT);
		assert.equal(role.scope, "own");
		assert.deepEqual(projection(effective(false, [role])), UPSTREAM_DEFAULT);
		const hidden = { ...UPSTREAM_DEFAULT, visibility: "all", streams: "hidden" };
		assert.deepEqual(projection(effective(false, [fromProjection(hidden)])), hidden);
	});

	it("adds roles up; any action brings view; unknown permissions are dropped", () => {
		assert.deepEqual(normalize(["pki:issue", "bogus:view", "pki:fly"]), ["pki:view", "pki:issue"]);
		const eff = effective(false, [
			{ scope: "own", permissions: ["proxy_hosts:manage"] },
			{ scope: "all", permissions: ["waf_events:view"] },
		]);
		assert.equal(eff.scope, "all");
		assert.ok(eff.permissions.has("proxy_hosts:view"));
		assert.ok(eff.permissions.has("waf_events:view"));
		assert.equal(effective(false, []).scope, "own");
	});

	it("Security Analyst sees WAF and events, changes WAF, not hosts", () => {
		const analyst = effective(false, [BUILTIN.security_analyst]);
		assert.equal(decide("waf_events:view", analyst), "grant");
		assert.equal(decide("waf_policy:manage", analyst), "grant");
		assert.equal(decide("services:manage", analyst), "deny");
		const row = projection(analyst);
		assert.equal(row.proxy_hosts, "view");
		assert.equal(row.streams, "view");
		// host changes stay with the upstream schema, which needs "manage" in user_permission
		assert.equal(decide("proxy_hosts:update", analyst), "upstream");
		assert.equal(decide("users:list", analyst), "upstream");
	});

	it("opens admin-only upstream sections to roles, never against administrators", () => {
		const eff = effective(false, [{ scope: "all", permissions: ["users:manage", "audit_log:view"] }]);
		assert.equal(decide("auditlog:list", eff), "grant");
		assert.equal(decide("users:list", eff), "grant");
		assert.equal(decide("users:update", eff, { targetIsAdmin: false }), "grant");
		assert.equal(decide("users:update", eff, { targetIsAdmin: true }), "upstream");
		assert.equal(decide("users:loginas", eff), "upstream");
		assert.equal(decide("settings:update", eff), "upstream");
		// per-user permissions are replaced by roles
		assert.equal(decide("users:permissions", eff), "deny");
		assert.equal(decide("users:permissions", effective(true, [])), "upstream");
	});

	it("administrator has everything", () => {
		const admin = effective(true, []);
		assert.equal(decide("pki:export_key", admin), "grant");
		assert.deepEqual(projection(admin).certificates, "manage");
		assert.deepEqual(missing(admin, ["roles:manage"], "all"), []);
	});

	it("nobody gives away more than they have", () => {
		const operator = effective(false, [BUILTIN.operator]);
		assert.deepEqual(missing(operator, ["proxy_hosts:manage", "waf_policy:apply"], "all"), []);
		assert.deepEqual(missing(operator, ["users:manage"]), ["users:view", "users:manage"]);
		const own = effective(false, [{ scope: "own", permissions: ["proxy_hosts:manage"] }]);
		assert.deepEqual(missing(own, ["proxy_hosts:view"], "all"), ["scope:all"]);
	});

	it("built-in roles name only known permissions", () => {
		for (const role of Object.values(BUILTIN)) {
			assert.deepEqual(normalize(role.permissions).length, new Set(role.permissions).size, role.name);
		}
	});
});
