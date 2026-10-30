// Backend client of the npmos-control service (see ./server.js).
import { readFile } from "node:fs/promises";
import errs from "../../lib/error.js";

const CONTROL_URL = process.env.NPMOS_CONTROL_URL || "http://npmos-control:7080";
const TOKEN_FILE = process.env.NPMOS_CONTROL_TOKEN_FILE || "/run/npmos-secrets/control_token";
const TIMEOUT_MS = 20000;

let token = null;
const getToken = async () => {
	if (!token) {
		try {
			token = (await readFile(TOKEN_FILE, "utf8")).trim();
		} catch (err) {
			throw new errs.ConfigurationError(`npmos-control token is missing (${TOKEN_FILE})`, err);
		}
	}
	return token;
};

/**
 * @param   {string} method
 * @param   {string} path
 * @param   {number} [actor]  id of the user on whose behalf the call is made (for the control audit log)
 * @returns {Promise<any>}
 */
const call = async (method, path, actor) => {
	const headers = { Authorization: `Bearer ${await getToken()}` };
	if (actor) {
		headers["X-NPMOS-Actor"] = `user:${actor}`;
	}

	let response;
	try {
		response = await fetch(`${CONTROL_URL}${path}`, { method, headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
	} catch (err) {
		throw new errs.ConfigurationError(`npmos-control is unreachable: ${err.cause?.code || err.message}`, err);
	}
	const body = await response.json().catch(() => ({}));
	if (response.status === 404) {
		throw new errs.ItemNotFoundError(body.error || path);
	}
	if (!response.ok) {
		throw new errs.ConfigurationError(`npmos-control: ${body.error || response.status}`);
	}
	return body;
};

const control = {
	listServices: () => call("GET", "/v1/services"),
	getService: (service) => call("GET", `/v1/services/${encodeURIComponent(service)}`),
	/**
	 * @param {string} service
	 * @param {{tail?: number, since?: number}} [options]
	 */
	getLogs: (service, { tail = 200, since = 0 } = {}) =>
		call("GET", `/v1/services/${encodeURIComponent(service)}/logs?tail=${tail}&since=${since}`),
	restartService: (service, actor) => call("POST", `/v1/services/${encodeURIComponent(service)}/restart`, actor),
	/** SIGHUP: the service rereads its configuration (CrowdSec only) */
	reloadService: (service, actor) => call("POST", `/v1/services/${encodeURIComponent(service)}/reload`, actor),
};

export default control;
