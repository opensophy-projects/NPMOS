// NPMOS API: /api/npmos/*
import express from "express";
import jwtdecode from "../lib/express/jwt-decode.js";
import validator from "../lib/validator/index.js";
import { debug, express as logger } from "../logger.js";
import internalAnalytics from "./events/analytics.js";
import internalEvents from "./events/index.js";
import internalHosts, { HOST_OBJECTS } from "./hosts.js";
import internalRbac from "./rbac/index.js";
import internalServices from "./services.js";
import internalWafAgent from "./waf/agent-settings.js";
import internalWafExpert from "./waf/expert.js";
import internalWafHosts from "./waf/hosts.js";
import internalWaf from "./waf/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

const SERVICE_NAME = /^[a-z0-9][a-z0-9_.-]{0,63}$/;

/**
 * Wraps a handler: JSON result, errors to the common error handler
 * @param {(req: express.Request, res: express.Response) => Promise<any>} handler
 * @param {number} [status]
 */
const handle =
	(handler, status = 200) =>
	async (req, res, next) => {
		try {
			res.status(status).send(await handler(req, res));
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			next(err);
		}
	};

router.param("host_id", (req, res, next, id) => {
	if (!/^[1-9][0-9]{0,9}$/.test(id)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid host id" } });
	}
	req.params.host_id = Number.parseInt(id, 10);
	next();
});

router.param("version_id", (req, res, next, id) => {
	if (!/^[1-9][0-9]{0,9}$/.test(id)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid version id" } });
	}
	req.params.version_id = Number.parseInt(id, 10);
	next();
});

for (const name of ["role_id", "user_id"]) {
	router.param(name, (req, res, next, id) => {
		if (!/^[1-9][0-9]{0,9}$/.test(id)) {
			return res.status(400).send({ error: { code: 400, message: `Invalid ${name}` } });
		}
		req.params[name] = Number.parseInt(id, 10);
		next();
	});
}

router.param("event_id", (_req, res, next, id) => {
	if (!/^[1-9][0-9]{0,17}$/.test(id)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid event id" } });
	}
	next();
});

router.param("object_type", (_req, res, next, type) => {
	if (!Object.hasOwn(HOST_OBJECTS, type)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid host type" } });
	}
	next();
});

router.param("service", (_req, res, next, service) => {
	if (!SERVICE_NAME.test(service)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid service name" } });
	}
	next();
});

/**
 * GET /api/npmos/services
 */
router
	.route("/services")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalServices.list(res.locals.access)));

/**
 * GET /api/npmos/services/:service
 */
router
	.route("/services/:service")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalServices.get(res.locals.access, req.params.service)));

/**
 * GET /api/npmos/services/:service/logs?tail=200&since=<unix seconds>
 */
router
	.route("/services/:service/logs")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(
		handle((req, res) =>
			internalServices.logs(res.locals.access, req.params.service, {
				tail: Number.parseInt(req.query.tail, 10) || 200,
				since: Number.parseInt(req.query.since, 10) || 0,
			}),
		),
	);

/**
 * POST /api/npmos/services/:service/restart
 */
router
	.route("/services/:service/restart")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((req, res) => internalServices.restart(res.locals.access, req.params.service), 202));

const roleSchema = {
	type: "object",
	additionalProperties: false,
	required: ["name", "scope", "permissions"],
	properties: {
		name: { type: "string", minLength: 1, maxLength: 100 },
		description: { type: "string", maxLength: 500 },
		scope: { enum: ["all", "own"] },
		oidc_groups: { type: "array", maxItems: 50, items: { type: "string", maxLength: 200 } },
		permissions: { type: "array", maxItems: 200, items: { type: "string", pattern: "^[a-z_]+:[a-z_]+$" } },
	},
};

/**
 * GET /api/npmos/rbac/model — resources, actions and built-in roles
 * GET /api/npmos/rbac/me — permissions of the current user
 */
router
	.route("/rbac/model")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle(() => internalRbac.model()));

router
	.route("/rbac/me")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalRbac.me(res.locals.access)));

/**
 * GET  /api/npmos/rbac/roles
 * POST /api/npmos/rbac/roles — {name, description, scope, oidc_groups, permissions: ["resource:action"]}
 */
router
	.route("/rbac/roles")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalRbac.list(res.locals.access)))
	.post(
		handle(async (req, res) => internalRbac.create(res.locals.access, await validator(roleSchema, req.body)), 201),
	);

/**
 * GET/PUT/DELETE /api/npmos/rbac/roles/:role_id (built-in roles: only oidc_groups change)
 */
router
	.route("/rbac/roles/:role_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalRbac.get(res.locals.access, req.params.role_id)))
	.put(
		handle(async (req, res) =>
			internalRbac.update(res.locals.access, req.params.role_id, await validator(roleSchema, req.body)),
		),
	)
	.delete(handle((req, res) => internalRbac.delete(res.locals.access, req.params.role_id)));

/**
 * GET /api/npmos/rbac/users — {user id: [{id, name, builtin}]}
 * PUT /api/npmos/rbac/users/:user_id — {roles: [role ids]}
 */
router
	.route("/rbac/users")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalRbac.assignments(res.locals.access)));

router
	.route("/rbac/users/:user_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["roles"],
					properties: { roles: { type: "array", maxItems: 100, items: { type: "integer", minimum: 1 } } },
				},
				req.body,
			);
			return internalRbac.setUserRoles(res.locals.access, req.params.user_id, data.roles);
		}),
	);

/**
 * GET/PUT /api/npmos/rbac/oidc — {claim, requestScope}: OIDC groups → roles
 */
router
	.route("/rbac/oidc")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalRbac.getOidc(res.locals.access)))
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["claim", "requestScope"],
					properties: {
						claim: { type: "string", minLength: 1, maxLength: 100 },
						requestScope: { type: "boolean" },
					},
				},
				req.body,
			);
			return internalRbac.setOidc(res.locals.access, data);
		}),
	);

/**
 * GET /api/npmos/hosts/changes — the last change of every visible host (audit log)
 */
router
	.route("/hosts/changes")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalHosts.changes(res.locals.access)));

/**
 * GET /api/npmos/hosts/changes/:object_type/:host_id — changes of one host, newest first
 */
router
	.route("/hosts/changes/:object_type/:host_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalHosts.history(res.locals.access, req.params.object_type, req.params.host_id)));

/**
 * GET /api/npmos/hosts/upstreams — whether the upstreams of proxy hosts and TCP streams accept connections
 */
router
	.route("/hosts/upstreams")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalHosts.upstreams(res.locals.access)));

/**
 * GET /api/npmos/waf — {enabled, active, restartRequired}
 * PUT /api/npmos/waf — {enabled: boolean, apply?: boolean}
 */
router
	.route("/waf")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWaf.getStatus(res.locals.access)))
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					required: ["enabled"],
					additionalProperties: false,
					properties: { enabled: { type: "boolean" }, apply: { type: "boolean" } },
				},
				req.body,
			);
			return internalWaf.setEnabled(res.locals.access, data.enabled, data.apply ?? true);
		}),
	);

const wafSettings = {
	type: "object",
	required: ["enabled", "mode", "minimum_confidence"],
	properties: {
		enabled: { type: "boolean" },
		mode: { type: "string" },
		minimum_confidence: { type: "string" },
	},
};

/**
 * GET /api/npmos/waf/hosts — {<proxy host id>: {enabled, mode, minimum_confidence}}
 */
router
	.route("/waf/hosts")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWafHosts.list(res.locals.access)));

/**
 * GET /api/npmos/waf/hosts/:host_id
 * PUT /api/npmos/waf/hosts/:host_id — {enabled, mode, minimum_confidence, locations?: [{path, inherit, ...}]}
 */
router
	.route("/waf/hosts/:host_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalWafHosts.get(res.locals.access, req.params.host_id)))
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: wafSettings.required,
					properties: {
						...wafSettings.properties,
						locations: {
							type: "array",
							items: {
								type: "object",
								additionalProperties: false,
								required: ["path", "inherit"],
								properties: {
									path: { type: "string" },
									inherit: { type: "boolean" },
									...wafSettings.properties,
								},
							},
						},
					},
				},
				req.body,
			);
			return internalWafHosts.set(res.locals.access, req.params.host_id, data);
		}),
	);

/**
 * GET  /api/npmos/waf/policy — generated local_policy.yaml (text) and its state
 * POST /api/npmos/waf/policy/apply — regenerate and make the agent apply it now
 */
router
	.route("/waf/policy")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWaf.getPolicy(res.locals.access)));

router
	.route("/waf/policy/apply")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((_, res) => internalWaf.applyPolicy(res.locals.access)));

/**
 * GET /api/npmos/waf/agent — agent settings, restartRequired, advanced model
 * PUT /api/npmos/waf/agent — {crowdsec: {enabled, mode}, fail_open: {enabled, timeout_ms}, apply?: boolean}
 */
router
	.route("/waf/agent")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWafAgent.get(res.locals.access)))
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["crowdsec", "fail_open"],
					properties: {
						crowdsec: {
							type: "object",
							additionalProperties: false,
							required: ["enabled", "mode"],
							properties: { enabled: { type: "boolean" }, mode: { enum: ["prevent", "detect"] } },
						},
						fail_open: {
							type: "object",
							additionalProperties: false,
							required: ["enabled", "timeout_ms"],
							properties: {
								enabled: { type: "boolean" },
								timeout_ms: { type: "integer", minimum: 10, maximum: 10000 },
							},
						},
						apply: { type: "boolean" },
					},
				},
				req.body,
			);
			return internalWafAgent.set(res.locals.access, data, data.apply !== false);
		}),
	);

/**
 * PUT /api/npmos/waf/agent/model?apply=false — body: open-appsec-advanced-model.tgz (application/octet-stream)
 * nginx lets up to 1 GB through for this path only (npmplus.conf)
 */
router
	.route("/waf/agent/model")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(handle((req, res) => internalWafAgent.uploadModel(res.locals.access, req, req.query.apply !== "false")));

/**
 * GET /api/npmos/analytics?period=1h|24h|7d|30d&host=<domain> — KPI, timeline, top lists
 */
router
	.route("/analytics")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalAnalytics.get(res.locals.access, req.query)));

/**
 * GET /api/npmos/events — security events of the agent, newest first. Filters: from, to (ISO, default
 * the last 24 h), kind=security|system|all, important=true, host, ip, action, severity, type
 * (comma-separated), min_score, max_score, q (text); limit (≤ 500), before (cursor: next of a page)
 */
router
	.route("/events")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalEvents.list(res.locals.access, req.query)));

const CSV_COLUMNS = [
	"time",
	"severity",
	"action",
	"incident_type",
	"source_ip",
	"source_country",
	"host",
	"method",
	"uri",
	"query",
	"response_code",
	"location",
	"parameter",
	"sample",
	"indicators",
	"score",
	"rule",
	"name",
	"kind",
	"id",
];

const csvCell = (value) => {
	if (value === null || value === undefined) return "";
	let s = String(value);
	// a cell starting with = + - @ would be a formula in a spreadsheet
	if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
	return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
};

/**
 * GET /api/npmos/events/export?format=csv|json&<filters of /events> — up to 100 000 events
 */
router
	.route("/events/export")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const { rows, capped } = await internalEvents.export(res.locals.access, req.query);
			const name = `npmos-events-${new Date().toISOString().slice(0, 19).replaceAll(":", "-")}`;
			res.set("X-NPMOS-Export-Capped", String(capped));
			if (req.query.format === "json") {
				res.set("Content-Disposition", `attachment; filename="${name}.json"`);
				res.type("application/json").send(JSON.stringify(rows, null, 2));
				return;
			}
			const lines = [CSV_COLUMNS.join(","), ...rows.map((r) => CSV_COLUMNS.map((c) => csvCell(r[c])).join(","))];
			res.set("Content-Disposition", `attachment; filename="${name}.csv"`);
			res.type("text/csv").send(`\ufeff${lines.join("\r\n")}\r\n`);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			next(err);
		}
	});

/**
 * GET /api/npmos/events/settings — retention, storage, state of the ingest
 * PUT /api/npmos/events/settings — {days, aggregate_days}
 */
router
	.route("/events/settings")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalEvents.getSettings(res.locals.access)))
	.put(
		handle(async (req, res) =>
			internalEvents.setSettings(
				res.locals.access,
				await validator(
					{
						type: "object",
						additionalProperties: false,
						required: ["days", "aggregate_days"],
						properties: {
							days: { type: "integer", minimum: 1, maximum: 365 },
							aggregate_days: { type: "integer", minimum: 1, maximum: 1830 },
						},
					},
					req.body,
				),
			),
		),
	);

/**
 * GET /api/npmos/events/:event_id?time=<ISO> — one event with its raw JSON
 */
router
	.route("/events/:event_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalEvents.get(res.locals.access, req.params.event_id, req.query.time)));

/**
 * GET /api/npmos/waf/policy/custom — expert YAML fragment in force, its versions
 * PUT /api/npmos/waf/policy/custom — {content, comment?}: new version, applied at once
 */
const customPolicy = {
	type: "object",
	additionalProperties: false,
	required: ["content"],
	properties: {
		content: { type: "string", maxLength: 262144 },
		comment: { type: "string", maxLength: 255 },
	},
};

router
	.route("/waf/policy/custom")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWafExpert.get(res.locals.access)))
	.put(
		handle(async (req, res) => internalWafExpert.save(res.locals.access, await validator(customPolicy, req.body))),
	);

/**
 * POST /api/npmos/waf/policy/custom/check — {content}: validation and diff against the file in force
 */
router
	.route("/waf/policy/custom/check")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(customPolicy, req.body);
			return internalWafExpert.check(res.locals.access, data.content);
		}),
	);

/**
 * POST /api/npmos/waf/policy/custom/:version_id/rollback
 */
router
	.route("/waf/policy/custom/:version_id/rollback")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((req, res) => internalWafExpert.rollback(res.locals.access, req.params.version_id)));

/**
 * POST /api/npmos/nginx/regenerate
 */
router
	.route("/nginx/regenerate")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((_, res) => internalServices.regenerate(res.locals.access)));

/**
 * GET /api/npmos/diagnostics — zip archive
 */
router
	.route("/diagnostics")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			await res.locals.access.can("services:manage");
			res.attachment(`npmos-diagnostics-${new Date().toISOString().replace(/[:.]/g, "-")}.zip`);
			await internalServices.diagnostics(res.locals.access, res);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			if (res.headersSent) {
				res.destroy(err);
			} else {
				next(err);
			}
		}
	});

export default router;
