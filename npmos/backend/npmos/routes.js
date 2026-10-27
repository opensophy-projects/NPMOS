// NPMOS API: /api/npmos/*
import express from "express";
import jwtdecode from "../lib/express/jwt-decode.js";
import validator from "../lib/validator/index.js";
import { debug, express as logger } from "../logger.js";
import internalServices from "./services.js";
import internalWafAgent from "./waf/agent-settings.js";
import internalWafEvents from "./waf/events.js";
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
 * GET /api/npmos/waf/events?view=important|all&host=<domain>&query=<text>&limit=200 — newest first
 */
router
	.route("/waf/events")
	.options((_, res) => res.sendStatus(204))
	.all(jwtdecode())
	.get(
		handle((req, res) =>
			internalWafEvents.list(res.locals.access, {
				view: String(req.query.view || "important"),
				host: String(req.query.host || ""),
				query: String(req.query.query || "").slice(0, 200),
				limit: Number.parseInt(req.query.limit, 10) || 200,
			}),
		),
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
			await res.locals.access.can("npmos_services:manage");
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
