// Trial mode of a host (docs/ROADMAP.md, phase 12; docs/WAF-POLICY.md, section 7): blocking is tried for some hours on
// the log only. The host keeps its mode: nothing is blocked. At the end NginxionS keeps the report of what blocking
// would have done with the WAF events of those hours (the dry run of objects/simulate.js), tells it (notification
// rule waf_trial) and offers to switch. RBAC: who switches the WAF mode of the host (waf/hosts.js) starts and closes
// a trial; who sees the host and the policy sees it.
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import internalWafHosts from "./hosts.js";
import { hostSimulation } from "./objects/api.js";

export const TRIAL_TABLE = "nginxions_waf_trial";
export const TRIAL_MODE = "prevent-learn";
export const MAX_HOURS = 7 * 24;
const CHECK_MS = 60 * 1000;

const parse = (value) => (typeof value === "string" ? JSON.parse(value || "null") : value) ?? null;

/** the state of a trial at a time: running before its end, finished after it, closed once decided */
export const trialState = (row, now = new Date()) =>
	row.outcome ? "closed" : new Date(row.ends_on) > now ? "running" : "finished";

const toApi = (row, now = new Date()) => ({
	id: row.id,
	hostId: row.proxy_host_id,
	mode: row.mode,
	startedOn: new Date(row.started_on).toISOString(),
	endsOn: new Date(row.ends_on).toISOString(),
	state: trialState(row, now),
	outcome: row.outcome || null,
});

/** the open trial of a host (running or finished, not decided) */
const openTrial = (hostId) =>
	db()(TRIAL_TABLE).where({ proxy_host_id: hostId, outcome: "" }).orderBy("id", "desc").first();

/** the open trials of all hosts: {hostId: trial} (Learning → hosts) */
export const openTrials = async (now = new Date()) => {
	const rows = await db()(TRIAL_TABLE).where({ outcome: "" }).orderBy("id");
	return new Map(rows.map((r) => [r.proxy_host_id, toApi(r, now)]));
};

/** the report of the hours of a trial so far (running) or the kept one (finished) */
const reportOf = async (row, now = new Date()) => {
	const kept = parse(row.report);
	if (kept) return kept;
	const until = new Date(Math.min(now.getTime(), new Date(row.ends_on).getTime()));
	return hostSimulation(row.proxy_host_id, row.mode, { since: new Date(row.started_on), until });
};

/** the right to change the WAF mode of the host (waf/hosts.js: set) */
const canSwitch = async (access, hostId) => {
	try {
		await access.can("proxy_hosts:update", hostId);
	} catch {
		await access.can("waf_policy:manage");
		await access.can("proxy_hosts:get", hostId);
	}
};

const audit = (access, hostId, meta) =>
	internalAuditLog.add(access, { action: "updated", object_type: "waf", object_id: hostId, meta });

// ------------------------------------------------------------------ the end of trials

/** finished trials get their report (once): the notification and the page read it */
export const finishTrials = async (now = new Date()) => {
	const rows = await db()(TRIAL_TABLE).where({ outcome: "" }).whereNull("finished_on").where("ends_on", "<=", now);
	for (const row of rows) {
		let report;
		try {
			report = await hostSimulation(row.proxy_host_id, row.mode, {
				since: new Date(row.started_on),
				until: new Date(row.ends_on),
			});
		} catch (err) {
			// the host was deleted: the trial is closed with it
			if (err instanceof errs.ItemNotFoundError) {
				await db()(TRIAL_TABLE).where({ id: row.id }).update({ outcome: "cancelled", closed_on: now });
				continue;
			}
			throw err;
		}
		await db()(TRIAL_TABLE)
			.where({ id: row.id })
			.update({ finished_on: now, report: JSON.stringify(report) });
	}
};

let timer = null;
/** the end of trials is checked every minute */
export const start = () => {
	if (timer) clearInterval(timer);
	const run = () => finishTrials().catch((err) => logger.warn(`WAF trial: ${err.message}`));
	timer = setInterval(run, CHECK_MS);
	timer.unref?.();
	run();
};

// ------------------------------------------------------------------ API

const internalWafTrial = {
	/**
	 * The open trial of a host with its report (null without one).
	 * @param {Access} access
	 * @param {number} hostId
	 */
	get: async (access, hostId) => {
		await access.can("proxy_hosts:get", hostId);
		await access.can("waf_policy:view");
		const row = await openTrial(hostId);
		if (!row) return { trial: null, report: null };
		const now = new Date();
		return { trial: toApi(row, now), report: await reportOf(row, now) };
	},

	/**
	 * Starts a trial: the host must have the WAF on and not block yet.
	 * @param {Access} access
	 * @param {number} hostId
	 * @param {{hours: number}} data
	 */
	start: async (access, hostId, { hours }) => {
		await canSwitch(access, hostId);
		if (!Number.isInteger(hours) || hours < 1 || hours > MAX_HOURS) {
			throw new errs.ValidationError(`hours: from 1 to ${MAX_HOURS}`);
		}
		const settings = await internalWafHosts.get(access, hostId);
		if (!settings.enabled) throw new errs.ValidationError("the WAF of the host is off");
		if (String(settings.mode).startsWith("prevent")) throw new errs.ValidationError("the host already blocks");
		if (await openTrial(hostId)) throw new errs.ValidationError("the host has a trial already");
		const now = new Date();
		await db()(TRIAL_TABLE).insert({
			proxy_host_id: hostId,
			started_on: now,
			ends_on: new Date(now.getTime() + hours * 3600e3),
			mode: TRIAL_MODE,
			user_id: access.token.getUserId(0),
			report: "",
		});
		await audit(access, hostId, { trial: "started", hours, mode: TRIAL_MODE });
		return internalWafTrial.get(access, hostId);
	},

	/**
	 * Closes the open trial: enable switches the host to the mode tried (with its minimum confidence), otherwise the
	 * host stays as it is (dismissed after the end, cancelled before it).
	 * @param {Access} access
	 * @param {number} hostId
	 * @param {{enable: boolean}} data
	 */
	finish: async (access, hostId, { enable }) => {
		await canSwitch(access, hostId);
		const row = await openTrial(hostId);
		if (!row) throw new errs.ItemNotFoundError(hostId);
		const now = new Date();
		const running = trialState(row, now) === "running";
		// a trial closed early keeps the report of its hours so far
		const report = parse(row.report) ?? (await reportOf(row, now));
		if (enable) {
			const settings = await internalWafHosts.get(access, hostId);
			await internalWafHosts.set(access, hostId, {
				enabled: true,
				mode: row.mode,
				minimum_confidence: settings.minimum_confidence,
			});
		}
		const outcome = enable ? "enabled" : running ? "cancelled" : "dismissed";
		await db()(TRIAL_TABLE)
			.where({ id: row.id })
			.update({
				outcome,
				closed_on: now,
				closed_by: access.token.getUserId(0),
				finished_on: row.finished_on ?? now,
				report: JSON.stringify(report),
			});
		await audit(access, hostId, { trial: outcome });
		return { trial: { ...toApi(row, now), state: "closed", outcome }, report };
	},
};

export default internalWafTrial;
