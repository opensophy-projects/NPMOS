// NPMOS API: /api/npmos/*
import express from "express";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";
import internalServices from "./services.js";

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

export default router;
