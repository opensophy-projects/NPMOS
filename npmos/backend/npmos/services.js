// System → Services: containers of the NPMOS stack, through npmos-control.
import internalAuditLog from "../internal/audit-log.js";
import control from "./control/client.js";

const MAX_LOG_LINES = 5000;

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
};

export default internalServices;
