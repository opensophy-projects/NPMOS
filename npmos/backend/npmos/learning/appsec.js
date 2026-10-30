// Clients of the local services of open-appsec that learning uses: the shared storage (files of learning,
// tuning/decisions.data that the agent reads) and the tuning service (statistics, readiness, tuning
// suggestions). Both are in the internal network of the stack; nothing leaves the machine.
import { randomUUID } from "node:crypto";

export const STORAGE_URL = process.env.NPMOS_APPSEC_STORAGE_URL || "http://appsec-shared-storage";
export const TUNING_URL = process.env.NPMOS_APPSEC_TUNING_URL || "http://appsec-tuning-svc";
const TIMEOUT_MS = 8000;

export class AppsecError extends Error {
	constructor(message, status = 0) {
		super(message);
		this.status = status;
	}
}

const request = async (method, url, tenant, body) => {
	let response;
	try {
		response = await fetch(url, {
			method,
			headers: {
				// both services refuse a request without a tenant and a trace id
				"X-Tenant-Id": tenant,
				"X-Trace-Id": randomUUID(),
				"X-Correlation-Id": randomUUID(),
				"X-Calling-Service": "npmos",
				...(body === undefined ? {} : { "Content-Type": "application/json" }),
			},
			body: body === undefined ? undefined : JSON.stringify(body),
			signal: AbortSignal.timeout(TIMEOUT_MS),
		});
	} catch (err) {
		throw new AppsecError(`${new URL(url).host} is unreachable: ${err.cause?.code || err.message}`);
	}
	const text = await response.text();
	if (response.status === 404) return null;
	if (!response.ok)
		throw new AppsecError(`${new URL(url).host}: ${response.status} ${text.slice(0, 200)}`, response.status);
	if (!text) return {};
	try {
		return JSON.parse(text);
	} catch {
		throw new AppsecError(`${new URL(url).host}: not JSON`);
	}
};

/** path of decisions.data as the agent reads it: <tenant>/<asset>/tuning/decisions.data (TuningDecision.cc) */
const decisionsPath = (tenant, asset) =>
	`${STORAGE_URL}/api/${tenant}/${asset}/tuning/decisions.data`.replace(/([^:])\/\/+/g, "$1/");

/** @returns {Promise<{decisions: object[]}|null>}  null: no file yet */
export const getDecisions = (tenant, asset) => request("GET", decisionsPath(tenant, asset), tenant);

export const putDecisions = (tenant, asset, data) => request("PUT", decisionsPath(tenant, asset), tenant, data);

/** tenants that have files in the shared storage (S3-like listing: <ListBucketResult><Contents><Key>) */
export const listTenants = async () => {
	let response;
	try {
		response = await fetch(`${STORAGE_URL}/api/?prefix=`, {
			headers: { "X-Tenant-Id": "npmos", "X-Trace-Id": randomUUID() },
			signal: AbortSignal.timeout(TIMEOUT_MS),
		});
	} catch (err) {
		throw new AppsecError(`shared storage is unreachable: ${err.cause?.code || err.message}`);
	}
	if (!response.ok) return [];
	const text = await response.text();
	return [...new Set([...text.matchAll(/<Key>([^</]+)\//g)].map((m) => m[1]))];
};

const asset = (name) => encodeURIComponent(name);

/** @returns {Promise<object|null>} {statistics: {...}} */
export const getStatistics = (tenant, name) =>
	request("GET", `${TUNING_URL}/api/v2/assets/${asset(name)}/statistics`, tenant);

/** @returns {Promise<object[]>} undecided tuning suggestions */
export const getSuggestions = async (tenant, name) =>
	(await request("GET", `${TUNING_URL}/api/v2/assets/${asset(name)}/tuning`, tenant))?.tuningEvents ?? [];

/**
 * Decides suggestions of the tuning service (it writes decisions.data itself); decision "undecided" undoes.
 * @param {Array<{id, decision, eventType, eventTitle}>} events
 */
export const postSuggestions = (tenant, name, events) =>
	request("POST", `${TUNING_URL}/api/v2/assets/${asset(name)}/tuning`, tenant, events);
