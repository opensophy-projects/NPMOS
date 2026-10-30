// Alerts of CrowdSec → npmos_security_event (kind "crowdsec"): one list of security events for
// Events, Analytics and Notifications. Read from the LAPI every 30 s; the position (last alert id)
// is a row of npmos_log_cursor, stored with the events in one transaction.
import { global as logger } from "../../logger.js";
import { emitEvents } from "../events/ingest.js";
import { loadCursors, oldestKeptDay, store } from "../events/store.js";
import { getSetting } from "../settings.js";
import { alerts } from "./lapi.js";

const CURSOR = "crowdsec:alerts";
const INTERVAL_MS = Number(process.env.NPMOS_CROWDSEC_ALERTS_INTERVAL_MS || 30000);
const FIRST_SINCE = "24h";
const LIMIT = 1000;
/** alerts NPMOS makes itself: decisions by hand and blocklists, logged in the audit log instead */
export const OWN_SCENARIO = /^npmos\/(manual|blocklist)/;

const str = (v, max = 255) => (v === undefined || v === null ? "" : String(v).slice(0, max));

/** value of a meta key of the alert (context) or of its first event */
const metaValue = (alert, key) => {
	for (const m of alert.meta || []) {
		if (m.key === key) {
			try {
				const v = JSON.parse(m.value);
				return Array.isArray(v) ? str(v[0]) : str(v);
			} catch {
				return str(m.value);
			}
		}
	}
	for (const e of alert.events || []) {
		for (const m of e.meta || []) if (m.key === key) return str(m.value);
	}
	return "";
};

/**
 * @param {object} alert  of the LAPI
 * @returns {object|null}  row of npmos_security_event
 */
export const toEvent = (alert, nodeId = "local") => {
	if (!alert?.id || OWN_SCENARIO.test(alert.scenario || "")) return null;
	const decision = (alert.decisions || [])[0];
	const raw = JSON.stringify({ ...alert, events: (alert.events || []).slice(0, 5) });
	return {
		node_id: nodeId,
		time: new Date(alert.stop_at || alert.created_at || alert.start_at || Date.now()),
		kind: "crowdsec",
		name: str(alert.scenario, 200),
		severity: decision ? "high" : "medium",
		priority: "",
		confidence: "",
		action: str(decision?.type || (alert.simulated ? "simulated" : "alert"), 32),
		incident_type: "",
		source_ip: str(alert.source?.ip || alert.source?.value, 64),
		source_port: null,
		proxy_ip: "",
		source_country: str(alert.source?.cn, 64),
		host: metaValue(alert, "target_fqdn").toLowerCase(),
		asset: "",
		method: str(metaValue(alert, "http_verb"), 16),
		uri: str(metaValue(alert, "http_path"), 2048),
		query: "",
		response_code: Number.parseInt(metaValue(alert, "http_status"), 10) || null,
		location: "",
		parameter: "",
		sample: str(alert.message, 2048),
		indicators: "",
		score: null,
		rule: str(alert.scenario),
		practice: "",
		override: "",
		service: "crowdsec",
		raw:
			raw.length > 64 * 1024
				? JSON.stringify({ npmosTruncated: true, id: alert.id, scenario: alert.scenario })
				: raw,
	};
};

const state = { running: false, timer: null, lastRun: null, lastError: null, stored: 0 };

/** one round: new alerts since the last one stored */
export const pollOnce = async (now = new Date()) => {
	const cursors = await loadCursors();
	const cursor = cursors.get(CURSOR);
	const last = cursor ? cursor.offset : 0;
	const since = cursor
		? `${Math.max(60, Math.ceil((now.getTime() - new Date(cursor.head || 0).getTime()) / 1000) + 60)}s`
		: FIRST_SINCE;
	const list = await alerts({ since, limit: LIMIT });
	const fresh = list.filter((a) => Number(a.id) > last).sort((a, b) => Number(a.id) - Number(b.id));
	if (!fresh.length && cursor) return [];
	const retention = await getSetting("events.retention");
	const oldest = oldestKeptDay(retention.days, now);
	const events = fresh.map((a) => toEvent(a)).filter((e) => e && e.time >= oldest);
	const maxId = fresh.reduce((m, a) => Math.max(m, Number(a.id)), last);
	await store({
		events,
		telemetry: [],
		cursors: [{ key: CURSOR, file: "lapi", offset: maxId, head: now.toISOString(), head_length: 0 }],
	});
	state.stored += events.length;
	emitEvents(events);
	return events;
};

const round = async () => {
	try {
		await pollOnce();
		state.lastRun = new Date();
		state.lastError = null;
	} catch (err) {
		if (state.lastError !== err.message) logger.warn(`NPMOS CrowdSec alerts: ${err.message}`);
		state.lastError = err.message;
	} finally {
		if (state.running) {
			state.timer = setTimeout(round, INTERVAL_MS);
			state.timer.unref();
		}
	}
};

export const startAlerts = () => {
	if (state.running) return;
	state.running = true;
	state.timer = setTimeout(round, 5000);
	state.timer.unref();
};

export const alertsStatus = () => ({ ...state, timer: undefined });
