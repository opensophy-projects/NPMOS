// NPMOS API: /api/npmos/*
import express from "express";
import db from "../db.js";
import errs from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import validator from "../lib/validator/api.js";
import { debug, express as logger } from "../logger.js";
import internalAnalytics from "./events/analytics.js";
import internalEvents from "./events/index.js";
import internalHosts, { HOST_OBJECTS } from "./hosts.js";
import internalNotifications from "./notifications/index.js";
import internalPki from "./pki/index.js";
import internalMtls, { usage as mtlsUsage, usedBy as mtlsUsedBy } from "./pki/mtls.js";
import internalRbac from "./rbac/index.js";
import internalServices from "./services.js";
import internalSystem from "./system/index.js";
import internalWafAgent from "./waf/agent-settings.js";
import internalWafExpert from "./waf/expert.js";
import internalWafHosts from "./waf/hosts.js";
import internalWaf from "./waf/index.js";
import internalWafObjects from "./waf/objects/api.js";

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

router.param("object_id", (req, res, next, id) => {
	if (!/^[1-9][0-9]{0,9}$/.test(id)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid object id" } });
	}
	req.params.object_id = Number.parseInt(id, 10);
	next();
});

router.param("version_id", (req, res, next, id) => {
	if (!/^[1-9][0-9]{0,9}$/.test(id)) {
		return res.status(400).send({ error: { code: 400, message: "Invalid version id" } });
	}
	req.params.version_id = Number.parseInt(id, 10);
	next();
});

for (const name of ["role_id", "user_id", "channel_id", "rule_id", "ca_id", "cert_id", "link_id"]) {
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

const ids = { type: "array", maxItems: 100, items: { type: "integer", minimum: 1 } };
const id = { type: ["integer", "null"], minimum: 1 };
/** references of a rule to objects of the policy (WAF → Policy) */
const ruleRefs = {
	threatPreventionPractices: ids,
	accessControlPractices: ids,
	triggers: ids,
	exceptions: ids,
	customResponse: id,
	sourceIdentifiers: id,
	trustedSources: id,
};
const wafHostObjects = {
	type: ["object", "null"],
	additionalProperties: false,
	// also snake_case: the API client of the GUI converts the keys of the WAF settings of hosts
	properties: {
		template: { type: "string", maxLength: 50 },
		...ruleRefs,
		...Object.fromEntries(
			Object.entries(ruleRefs).map(([key, schema]) => [
				key.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`),
				schema,
			]),
		),
	},
};
const wafDefaultPolicy = {
	type: "object",
	additionalProperties: false,
	required: ["mode"],
	properties: { mode: { type: "string" }, ...ruleRefs },
};
const wafObject = {
	type: "object",
	additionalProperties: false,
	required: ["kind", "name", "spec"],
	properties: {
		kind: { type: "string", maxLength: 32 },
		name: { type: "string", maxLength: 100 },
		description: { type: "string", maxLength: 500 },
		spec: { type: "object" },
	},
};

/**
 * GET /api/npmos/waf/hosts — {<proxy host id>: {enabled, mode, minimum_confidence, template}}
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
						objects: wafHostObjects,
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

const language = { enum: ["ru", "en"] };
/** config of a channel by type (secrets: omitted or null keeps the stored one) */
const CHANNEL_CONFIG = {
	email: {
		type: "object",
		additionalProperties: false,
		required: ["host", "port", "security", "from", "to"],
		properties: {
			host: { type: "string", minLength: 1, maxLength: 255, pattern: "^[A-Za-z0-9.:\\[\\]_-]+$" },
			port: { type: "integer", minimum: 1, maximum: 65535 },
			security: { enum: ["none", "starttls", "tls"] },
			verify_tls: { type: "boolean" },
			username: { type: "string", maxLength: 255 },
			password: { type: ["string", "null"], maxLength: 1024 },
			from: { type: "string", minLength: 3, maxLength: 255 },
			to: {
				type: "array",
				minItems: 1,
				maxItems: 20,
				items: { type: "string", pattern: "^[^\\s@,]+@[^\\s@,]+$", maxLength: 255 },
			},
			language,
		},
	},
	webhook: {
		type: "object",
		additionalProperties: false,
		required: ["url"],
		properties: {
			url: { type: "string", pattern: "^https?://", maxLength: 2048 },
			secret: { type: ["string", "null"], maxLength: 1024 },
			language,
		},
	},
	telegram: {
		type: "object",
		additionalProperties: false,
		required: ["chat_id"],
		properties: {
			token: { type: ["string", "null"], pattern: "^[0-9]+:[A-Za-z0-9_-]+$", maxLength: 255 },
			chat_id: { type: "string", pattern: "^-?[0-9]+$|^@[A-Za-z0-9_]{4,}$", maxLength: 64 },
			api_url: { type: "string", pattern: "^(https?://.+)?$", maxLength: 2048 },
			language,
		},
	},
};

/** a channel body; `create`: type and config are required */
const channelBody = async (body, create, type) => {
	const data = await validator(
		{
			type: "object",
			additionalProperties: false,
			required: create ? ["name", "type", "config"] : [],
			properties: {
				name: { type: "string", minLength: 1, maxLength: 100 },
				type: { enum: Object.keys(CHANNEL_CONFIG) },
				enabled: { type: "boolean" },
				config: { type: "object" },
			},
		},
		body,
	);
	const channelType = data.type || type;
	if (data.config) {
		data.config = await validator(CHANNEL_CONFIG[channelType], data.config);
		if (create && channelType === "telegram" && !data.config.token) {
			throw new errs.ValidationError("The bot token is required");
		}
	}
	return data;
};

const ruleSchema = (create) => ({
	type: "object",
	additionalProperties: false,
	required: create ? ["name", "type", "channel_ids"] : [],
	properties: {
		name: { type: "string", minLength: 1, maxLength: 100 },
		type: { enum: ["attack_spike", "agent_down", "policy_error", "service_down", "cert_expiry", "host_problem"] },
		enabled: { type: "boolean" },
		params: { type: "object", maxProperties: 10 },
		channel_ids: { type: "array", maxItems: 20, items: { type: "integer", minimum: 1 } },
		repeat_minutes: { type: "integer", minimum: 0, maximum: 10080 },
		notify_resolved: { type: "boolean" },
	},
});

/**
 * GET /api/npmos/notifications — channels (no secrets), rules, last deliveries, types
 */
router
	.route("/notifications")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalNotifications.get(res.locals.access)));

/**
 * POST /api/npmos/notifications/channels — {name, type: email|webhook|telegram, enabled?, config}
 * PUT/DELETE /api/npmos/notifications/channels/:channel_id; POST .../test — a test message now
 */
router
	.route("/notifications/channels")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(
			async (req, res) =>
				internalNotifications.createChannel(res.locals.access, await channelBody(req.body, true)),
			201,
		),
	);

router
	.route("/notifications/channels/:channel_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(
		handle(async (req, res) => {
			await res.locals.access.can("notifications:manage");
			const channel = await db()("npmos_notification_channel").where("id", req.params.channel_id).first();
			if (!channel) throw new errs.ItemNotFoundError(req.params.channel_id);
			return internalNotifications.updateChannel(
				res.locals.access,
				req.params.channel_id,
				await channelBody(req.body, false, channel.type),
			);
		}),
	)
	.delete(handle((req, res) => internalNotifications.deleteChannel(res.locals.access, req.params.channel_id)));

router
	.route("/notifications/channels/:channel_id/test")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((req, res) => internalNotifications.testChannel(res.locals.access, req.params.channel_id)));

/**
 * POST /api/npmos/notifications/rules — {name, type, params?, channel_ids, repeat_minutes?, notify_resolved?}
 * PUT/DELETE /api/npmos/notifications/rules/:rule_id
 */
router
	.route("/notifications/rules")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(
			async (req, res) =>
				internalNotifications.createRule(res.locals.access, await validator(ruleSchema(true), req.body)),
			201,
		),
	);

router
	.route("/notifications/rules/:rule_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(
		handle(async (req, res) =>
			internalNotifications.updateRule(
				res.locals.access,
				req.params.rule_id,
				await validator(ruleSchema(false), req.body),
			),
		),
	)
	.delete(handle((req, res) => internalNotifications.deleteRule(res.locals.access, req.params.rule_id)));

/**
 * GET /api/npmos/system/settings — env settings of NPMplus: value saved, value running
 * PUT /api/npmos/system/settings — {values: [{env, value}], apply?}: apply restarts npmos
 * POST /api/npmos/system/settings/apply — restart npmos with what was saved
 */
router
	.route("/system/settings")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalSystem.getSettings(res.locals.access)))
	.put(
		handle(async (req, res) =>
			internalSystem.setSettings(
				res.locals.access,
				await validator(
					{
						type: "object",
						additionalProperties: false,
						required: ["values"],
						properties: {
							values: {
								type: "array",
								maxItems: 50,
								items: {
									type: "object",
									additionalProperties: false,
									required: ["env", "value"],
									properties: {
										env: { type: "string", pattern: "^[A-Z0-9_]{1,64}$" },
										value: { type: ["boolean", "integer", "string"] },
									},
								},
							},
							apply: { type: "boolean" },
						},
					},
					req.body,
				),
			),
		),
	);

router
	.route("/system/settings/apply")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((_, res) => internalSystem.apply(res.locals.access), 202));

/**
 * GET /api/npmos/analytics?period=1h|24h|7d|30d&host=<domain> — KPI, timeline, top lists
 */
router
	.route("/analytics")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalAnalytics.get(res.locals.access, req.query)));

/**
 * GET /api/npmos/analytics/hosts — attacks per host and hour of the last 24 h
 */
router
	.route("/analytics/hosts")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalAnalytics.hosts(res.locals.access)));

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
 * WAF → Policy (ADR-0008)
 * GET  /api/npmos/waf/policy/objects — objects, default policy, templates, state of the file
 * POST /api/npmos/waf/policy/objects — {kind, name, description?, spec}
 */
router
	.route("/waf/policy/objects")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWafObjects.get(res.locals.access)))
	.post(
		handle(
			async (req, res) => internalWafObjects.create(res.locals.access, await validator(wafObject, req.body)),
			201,
		),
	);

/**
 * PUT    /api/npmos/waf/policy/objects/:object_id — {kind, name, description?, spec}
 * DELETE /api/npmos/waf/policy/objects/:object_id
 */
router
	.route("/waf/policy/objects/:object_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(
		handle(async (req, res) =>
			internalWafObjects.update(res.locals.access, req.params.object_id, await validator(wafObject, req.body)),
		),
	)
	.delete(handle((req, res) => internalWafObjects.delete(res.locals.access, req.params.object_id)));

/**
 * PUT /api/npmos/waf/policy/default — {mode, threatPreventionPractices?: [id], ..., customResponse?: id}
 */
router
	.route("/waf/policy/default")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(
		handle(async (req, res) =>
			internalWafObjects.setPolicy(res.locals.access, await validator(wafDefaultPolicy, req.body)),
		),
	);

/**
 * POST /api/npmos/waf/policy/preview — one change, nothing saved: validation, diff of local_policy.yaml,
 * format and warnings. {object, id?} | {delete: id} | {policy} | {host: {id, objects}}
 */
router
	.route("/waf/policy/preview")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const change = await validator(
				{
					type: "object",
					additionalProperties: false,
					minProperties: 1,
					properties: {
						object: wafObject,
						id: { type: "integer", minimum: 1 },
						delete: { type: "integer", minimum: 1 },
						policy: wafDefaultPolicy,
						host: {
							type: "object",
							additionalProperties: false,
							required: ["id", "objects"],
							properties: { id: { type: "integer", minimum: 1 }, objects: wafHostObjects },
						},
					},
				},
				req.body,
			);
			return internalWafObjects.preview(res.locals.access, change);
		}),
	);

/**
 * GET  /api/npmos/waf/policy/versions
 * POST /api/npmos/waf/policy/versions/:version_id/rollback
 */
router
	.route("/waf/policy/versions")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalWafObjects.versions(res.locals.access)));

router
	.route("/waf/policy/versions/:version_id/rollback")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(handle((req, res) => internalWafObjects.rollback(res.locals.access, req.params.version_id)));

/**
 * GET  /api/npmos/waf/policy/export?format=v1beta2|v1beta1 — YAML of the objects and the default policy
 * POST /api/npmos/waf/policy/import?dry_run=true — {content}: objects and default policy of a local_policy.yaml
 */
router
	.route("/waf/policy/export")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const format = req.query.format === "v1beta1" ? "v1beta1" : "v1beta2";
			const content = await internalWafObjects.export(res.locals.access, format);
			res.attachment(`npmos-waf-policy-${format}.yaml`);
			res.type("application/yaml").send(content);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.originalUrl}: ${err}`);
			next(err);
		}
	});

router
	.route("/waf/policy/import")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["content"],
					properties: { content: { type: "string", maxLength: 1048576 } },
				},
				req.body,
			);
			return internalWafObjects.import(res.locals.access, data.content, req.query.dry_run === "true");
		}),
	);

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

// ---------------------------------------------------------------------------------------------
// PKI and mTLS (phase 6)

router.param("host_type", (_req, res, next, value) => {
	if (!["proxy_host", "stream"].includes(value)) {
		return res.status(400).send({ error: { code: 400, message: "host_type: proxy_host or stream" } });
	}
	next();
});

/** a file as JSON (the GUI saves it): {filename, content_type, data_base64} */
const fileJson = ({ filename, type, data }) => ({
	filename,
	content_type: type,
	data_base64: Buffer.from(data).toString("base64"),
});

const subjectSchema = {
	type: "object",
	additionalProperties: false,
	properties: Object.fromEntries(
		["common_name", "organization", "organizational_unit", "country", "state", "locality", "email"].map((k) => [
			k,
			{ type: "string", maxLength: 128 },
		]),
	),
};

const sansSchema = {
	type: "object",
	additionalProperties: false,
	properties: Object.fromEntries(
		["dns", "ip", "email"].map((k) => [
			k,
			{ type: "array", maxItems: 100, items: { type: "string", maxLength: 253 } },
		]),
	),
};

const p12Properties = {
	password: { type: "string", maxLength: 128 },
	compatible: { type: "boolean" },
};

/**
 * GET /api/npmos/pki — CAs, certificates, settings; hosts of CAs (mTLS) and of server certificates
 */
router
	.route("/pki")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(
		handle(async (_, res) => {
			const overview = await internalPki.overview(res.locals.access);
			const used = await mtlsUsage();
			for (const ca of overview.cas) ca.hosts = used.cas[ca.id] || [];
			for (const cert of overview.certificates) {
				cert.hosts = cert.certificate_id ? used.certificates[cert.certificate_id] || [] : [];
			}
			return overview;
		}),
	);

/**
 * PUT /api/npmos/pki/settings — {public_url, crl_days, client_days, server_days, key_type, p12_compatible, templates}
 */
router
	.route("/pki/settings")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: [
						"public_url",
						"crl_days",
						"client_days",
						"server_days",
						"key_type",
						"p12_compatible",
						"templates",
					],
					properties: {
						public_url: { type: "string", maxLength: 255 },
						crl_days: { type: "integer" },
						client_days: { type: "integer" },
						server_days: { type: "integer" },
						key_type: { type: "string" },
						p12_compatible: { type: "boolean" },
						templates: {
							type: "array",
							maxItems: 100,
							items: {
								type: "object",
								additionalProperties: false,
								required: ["id", "name", "profile", "ca_id", "days", "key_type"],
								properties: {
									id: { type: "string" },
									name: { type: "string" },
									profile: { type: "string" },
									ca_id: { anyOf: [{ type: "integer" }, { type: "null" }] },
									days: { type: "integer" },
									key_type: { type: "string" },
									subject: subjectSchema,
								},
							},
						},
					},
				},
				req.body,
			);
			return internalPki.setSettings(res.locals.access, data);
		}),
	);

/**
 * POST /api/npmos/pki/cas — new CA: {kind: root|intermediate, name, parent_id?, subject, key_type?, days?}
 */
router
	.route("/pki/cas")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["kind", "name", "subject"],
					properties: {
						kind: { type: "string", enum: ["root", "intermediate"] },
						name: { type: "string", maxLength: 100 },
						parent_id: { type: "integer" },
						subject: subjectSchema,
						key_type: { type: "string" },
						days: { type: "integer" },
					},
				},
				req.body,
			);
			return internalPki.createCa(res.locals.access, data);
		}, 201),
	);

/**
 * POST /api/npmos/pki/cas/import — {kind: root|external, name, cert_pem, key_pem?, key_password?, crl_pem?}
 */
router
	.route("/pki/cas/import")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["kind", "name", "cert_pem"],
					properties: {
						kind: { type: "string", enum: ["root", "external"] },
						name: { type: "string", maxLength: 100 },
						cert_pem: { type: "string", maxLength: 1000000 },
						key_pem: { type: "string", maxLength: 100000 },
						key_password: { type: "string", maxLength: 1024 },
						crl_pem: { type: "string", maxLength: 10000000 },
					},
				},
				req.body,
			);
			return internalPki.importCa(res.locals.access, data);
		}, 201),
	);

/**
 * GET    /api/npmos/pki/cas/:ca_id
 * PUT    /api/npmos/pki/cas/:ca_id — {name?, crl_pem? (external CAs)}
 * DELETE /api/npmos/pki/cas/:ca_id
 */
router
	.route("/pki/cas/:ca_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalPki.getCa(res.locals.access, req.params.ca_id)))
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					properties: {
						name: { type: "string", maxLength: 100 },
						crl_pem: { type: "string", maxLength: 10000000 },
					},
				},
				req.body,
			);
			return internalPki.updateCa(res.locals.access, req.params.ca_id, data);
		}),
	)
	.delete(handle((req, res) => internalPki.deleteCa(res.locals.access, req.params.ca_id, mtlsUsedBy)));

/**
 * POST /api/npmos/pki/cas/:ca_id/export — {format: cert|chain|crl|key, password? (key)}
 */
router
	.route("/pki/cas/:ca_id/export")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["format"],
					properties: { format: { type: "string" }, password: { type: "string", maxLength: 128 } },
				},
				req.body,
			);
			return fileJson(
				await internalPki.exportCa(res.locals.access, req.params.ca_id, data.format, data.password),
			);
		}),
	);

const issueProperties = {
	ca_id: { type: "integer" },
	profile: { type: "string", enum: ["client", "server"] },
	subject: subjectSchema,
	sans: sansSchema,
	days: { type: "integer" },
	key_type: { type: "string" },
	csr_pem: { type: "string", maxLength: 100000 },
	template: { type: "string", maxLength: 100 },
	notes: { type: "string", maxLength: 500 },
	store_key: { type: "boolean" },
	include_key_pem: { type: "boolean" },
	link_hours: { type: "integer" },
	install: { type: "boolean" },
	...p12Properties,
};

/**
 * POST /api/npmos/pki/certs — issue: {ca_id, profile, subject | csr_pem, sans?, days?, key_type?, template?,
 *   notes?, store_key?, password?, compatible?, include_key_pem?, link_hours?, install?}
 *   → {certificate, files: {cert_pem, chain_pem, p12_base64?, password?, key_pem?}, link?}
 */
router
	.route("/pki/certs")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["ca_id", "profile"],
					properties: issueProperties,
				},
				req.body,
			);
			return internalPki.issue(res.locals.access, data);
		}, 201),
	);

/**
 * POST /api/npmos/pki/certs/revoke — {ids, reason}
 */
router
	.route("/pki/certs/revoke")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["ids", "reason"],
					properties: {
						ids: { type: "array", minItems: 1, maxItems: 1000, items: { type: "integer", minimum: 1 } },
						reason: { type: "string" },
					},
				},
				req.body,
			);
			return internalPki.revoke(res.locals.access, data.ids, data.reason);
		}),
	);

/**
 * POST /api/npmos/pki/certs/:cert_id/renew — {days?, key_type?, csr_pem?, revoke_old?, password?, ...}
 */
router
	.route("/pki/certs/:cert_id/renew")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					properties: {
						days: issueProperties.days,
						key_type: issueProperties.key_type,
						csr_pem: issueProperties.csr_pem,
						store_key: issueProperties.store_key,
						include_key_pem: issueProperties.include_key_pem,
						link_hours: issueProperties.link_hours,
						revoke_old: { type: "boolean" },
						...p12Properties,
					},
				},
				req.body,
			);
			return internalPki.renew(res.locals.access, req.params.cert_id, data);
		}, 201),
	);

/**
 * POST /api/npmos/pki/certs/:cert_id/download — {format: cert|chain|key|p12, password?, compatible?}
 */
router
	.route("/pki/certs/:cert_id/download")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["format"],
					properties: { format: { type: "string" }, ...p12Properties },
				},
				req.body,
			);
			return fileJson(await internalPki.download(res.locals.access, req.params.cert_id, data.format, data));
		}),
	);

/**
 * GET  /api/npmos/pki/certs/:cert_id/links — one-time links of a certificate
 * POST /api/npmos/pki/certs/:cert_id/links — {hours, password?, compatible?} (kept key)
 */
router
	.route("/pki/certs/:cert_id/links")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalPki.links(res.locals.access, req.params.cert_id)))
	.post(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["hours"],
					properties: { hours: { type: "integer" }, ...p12Properties },
				},
				req.body,
			);
			return internalPki.createLink(res.locals.access, req.params.cert_id, data);
		}, 201),
	);

/**
 * DELETE /api/npmos/pki/links/:link_id
 */
router
	.route("/pki/links/:link_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.delete(handle((req, res) => internalPki.deleteLink(res.locals.access, req.params.link_id)));

/**
 * GET /api/npmos/pki/public/crl/:ca_id.crl — CRL (DER), without login: the distribution point of
 * certificates
 */
router.get("/pki/public/crl/:file", async (req, res, next) => {
	try {
		const match = /^([1-9][0-9]{0,9})\.crl$/.exec(req.params.file);
		const der = match ? await internalPki.publicCrl(Number.parseInt(match[1], 10)) : null;
		if (!der) return res.status(404).send({ error: { code: 404, message: "No such CRL" } });
		res.set("Content-Type", "application/pkix-crl");
		res.set("Cache-Control", "max-age=300");
		res.send(der);
	} catch (err) {
		next(err);
	}
});

/**
 * GET /api/npmos/pki/public/download/:token — one-time link, without login
 */
router.get("/pki/public/download/:token", async (req, res, next) => {
	try {
		const file = await internalPki.takeLink(req.params.token);
		res.set("Cache-Control", "no-store");
		if (!file) {
			return res.status(410).send({ error: { code: 410, message: "The link was used or has expired" } });
		}
		res.set("Content-Type", "application/x-pkcs12");
		res.attachment(file.filename);
		res.send(file.data);
	} catch (err) {
		next(err);
	}
});

/**
 * GET /api/npmos/mtls — mTLS of hosts and streams: {proxy_host: {<id>: {...}}, stream: {...}}
 */
router
	.route("/mtls")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((_, res) => internalMtls.list(res.locals.access)));

/**
 * GET /api/npmos/mtls/:host_type/:host_id
 * PUT /api/npmos/mtls/:host_type/:host_id — {enabled, ca_ids, mode, depth, send_ca_names, rules, required_paths, headers}
 */
router
	.route("/mtls/:host_type/:host_id")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(handle((req, res) => internalMtls.get(res.locals.access, req.params.host_type, req.params.host_id)))
	.put(
		handle(async (req, res) => {
			const data = await validator(
				{
					type: "object",
					additionalProperties: false,
					required: ["enabled", "ca_ids"],
					properties: {
						enabled: { type: "boolean" },
						ca_ids: { type: "array", maxItems: 50, items: { type: "integer", minimum: 1 } },
						mode: { type: "string" },
						depth: { type: "integer" },
						send_ca_names: { type: "boolean" },
						rules: {
							type: "array",
							maxItems: 20,
							items: {
								type: "object",
								additionalProperties: false,
								required: ["field", "op", "values"],
								properties: {
									field: { type: "string" },
									op: { type: "string" },
									values: { type: "array", maxItems: 50, items: { type: "string", maxLength: 200 } },
								},
							},
						},
						required_paths: { type: "array", maxItems: 200, items: { type: "string" } },
						headers: { type: "boolean" },
					},
				},
				req.body,
			);
			return internalMtls.set(res.locals.access, req.params.host_type, req.params.host_id, data);
		}),
	);

export default router;
