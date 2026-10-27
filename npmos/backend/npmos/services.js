// System → Services: containers of the NPMOS stack, through npmos-control.
import { ZipArchive } from "archiver";
import internalAuditLog from "../internal/audit-log.js";
import utils from "../lib/utils.js";
import { express as logger } from "../logger.js";
import pjson from "../package.json" with { type: "json" };
import { regenerateAllHosts } from "../setup.js";
import control from "./control/client.js";

const MAX_LOG_LINES = 5000;
const DIAGNOSTICS_LOG_LINES = 2000;

const internalServices = {
	/**
	 * @param {Access} access
	 */
	list: async (access) => {
		await access.can("npmos_services:list");
		const services = await control.listServices();
		return services.sort((a, b) => a.service.localeCompare(b.service));
	},

	/**
	 * @param {Access} access
	 * @param {string} service
	 */
	get: async (access, service) => {
		await access.can("npmos_services:list");
		return control.getService(service);
	},

	/**
	 * @param {Access} access
	 * @param {string} service
	 * @param {{tail?: number, since?: number}} options
	 */
	logs: async (access, service, { tail, since }) => {
		await access.can("npmos_services:list");
		return control.getLogs(service, { tail: Math.min(tail || 200, MAX_LOG_LINES), since });
	},

	/**
	 * @param {Access} access
	 * @param {string} service
	 */
	restart: async (access, service) => {
		await access.can("npmos_services:manage");
		const audit = () =>
			internalAuditLog.add(access, { action: "restarted", object_type: "service", meta: { name: service } });
		// the audit log lives in postgres: log before taking it down
		if (service === "postgres") {
			await audit();
		}
		// npmos-control answers before restarting npmos itself, so this process is still here to log it
		const result = await control.restartService(service, access.token.getUserId(1));
		if (service !== "postgres") {
			await audit();
		}
		return result;
	},

	/**
	 * Rewrites the nginx configs of all enabled hosts from the database and reloads nginx
	 * (replaces the REGENERATE_ALL env of upstream).
	 * @param {Access} access
	 */
	regenerate: async (access) => {
		await access.can("npmos_services:manage");
		await regenerateAllHosts(true);
		await internalAuditLog.add(access, { action: "regenerated", object_type: "service", meta: { name: "nginx" } });
		return { regenerated: true };
	},

	/**
	 * Diagnostic archive for bug reports: versions, service states, recent logs, `nginx -T`.
	 * Contains no secrets from the secrets volume, but logs and nginx configs are the admin's
	 * to review before sharing.
	 * @param {Access} access
	 * @param {import("node:stream").Writable} output
	 */
	diagnostics: async (access, output) => {
		await access.can("npmos_services:manage");
		const archive = new ZipArchive({ zlib: { level: 9 } });
		archive.on("warning", (err) => logger.warn(`diagnostics: ${err.message}`));
		archive.pipe(output);

		const add = (name, content) => archive.append(content, { name });
		const attempt = async (fn) => {
			try {
				return await fn();
			} catch (err) {
				return `unavailable: ${err.message}`;
			}
		};

		add("npmos.json", JSON.stringify({ version: pjson.version, created: new Date().toISOString() }, null, 2));
		const services = await attempt(() => control.listServices());
		add("services.json", typeof services === "string" ? services : JSON.stringify(services, null, 2));
		if (Array.isArray(services)) {
			for (const { service } of services) {
				const lines = await attempt(() => control.getLogs(service, { tail: DIAGNOSTICS_LOG_LINES }));
				const text = Array.isArray(lines) ? lines.map((l) => `${l.stream} ${l.line}`).join("\n") : lines;
				add(`logs/${service}.log`, `${text}\n`);
			}
		}
		add("nginx-T.txt", await attempt(() => utils.execFile("nginx", ["-T"])));

		await archive.finalize();
		await internalAuditLog.add(access, {
			action: "exported",
			object_type: "service",
			meta: { name: "diagnostics" },
		});
	},
};

export default internalServices;
