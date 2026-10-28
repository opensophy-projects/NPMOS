// Security log of the open-appsec agent → rows of npmos_security_event (docs/ROADMAP.md, phase 4).
// The agent writes one JSON object per line (cp-nano-*.log*): security events of the WAAP engine,
// service notices and periodic telemetry. Pure functions, no database.

/** periodic statistics: counters for the aggregates, never stored as events */
export const TELEMETRY = ["waap telemetry", "waap attack type telemetry", "waap traffic telemetry", "ips stats"];
/** "Important events" of open-appsec-npm */
export const IMPORTANT_SEVERITIES = ["critical", "high"];

const MAX_TEXT = 2048;
const MAX_RAW = 64 * 1024;
// Postgres takes no NUL in text and jsonb; attack samples may have one
const NUL = String.fromCharCode(0);
const noNul = (_key, value) => (typeof value === "string" ? value.replaceAll(NUL, "") : value);

const str = (value, max = 255) => {
	if (value === undefined || value === null) return "";
	const text = typeof value === "string" ? value : Array.isArray(value) ? value.join(", ") : String(value);
	const s = text.replaceAll(NUL, "");
	return s.length > max ? s.slice(0, max) : s;
};

const num = (value) => {
	const n = typeof value === "number" ? value : Number.parseFloat(value);
	return Number.isFinite(n) ? n : null;
};

const int = (value) => {
	const n = num(value);
	return n === null ? null : Math.trunc(n);
};

/** agent time is UTC without a zone: "2026-10-27T05:44:40.123" */
export const parseTime = (time) => {
	if (!time || typeof time !== "string") return null;
	const date = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(time) ? time : `${time}Z`);
	return Number.isNaN(date.getTime()) ? null : date;
};

/** the start of the UTC hour of a date */
export const hourOf = (date) => {
	const hour = new Date(date);
	hour.setUTCMinutes(0, 0, 0);
	return hour;
};

/** "2026-10-27" of a date (UTC) */
export const dayOf = (date) => date.toISOString().slice(0, 10);

/**
 * One line of the agent's log.
 * @param {object} raw
 * @param {string} [nodeId]
 * @returns {{type: "event", row: object} | {type: "telemetry", row: object} | null}  null: skipped
 */
export const classify = (raw, nodeId = "local") => {
	if (!raw || typeof raw !== "object") return null;
	const time = parseTime(raw.eventTime);
	if (!time) return null;
	const origin = raw.eventSource || {};
	const data = raw.eventData || {};
	// the orchestration's reminder (every 30 s) to define an agent profile in the Check Point cloud
	if (origin.source === "fog_communication") return null;
	const name = str(raw.eventName, 200);
	const pick = (key) => data[key] ?? origin[key];

	if (TELEMETRY.includes(name.toLowerCase())) {
		if (name.toLowerCase() !== "waap telemetry") return null;
		// counters of the reporting period, per asset (components/include/telemetry.h)
		return {
			type: "telemetry",
			row: {
				node_id: nodeId,
				hour: hourOf(time),
				asset: str(pick("assetName")),
				requests: int(data.reservedNgenA) ?? 0,
				sources: int(data.reservedNgenB) ?? 0,
				blocked:
					(int(data.reservedNgenD) ?? 0) + (int(data.reservedNgenE) ?? 0) + (int(data.reservedNgenF) ?? 0),
				threat_low: int(data.reservedNgenH) ?? 0,
				threat_medium: int(data.reservedNgenI) ?? 0,
				threat_high: int(data.reservedNgenJ) ?? 0,
			},
		};
	}

	const action = str(data.securityAction, 32);
	let rawText = JSON.stringify(raw, noNul);
	if (rawText.length > MAX_RAW) {
		// request bodies and headers make an event big; the rest is kept
		const { httpRequestBody, httpRequestHeaders, httpResponseBody, ...rest } = data;
		rawText = JSON.stringify({ ...raw, eventData: { ...rest, npmosTruncated: true } }, noNul);
		if (rawText.length > MAX_RAW)
			rawText = JSON.stringify({ npmosTruncated: true, text: rawText.slice(0, MAX_RAW) });
	}
	return {
		type: "event",
		row: {
			node_id: nodeId,
			time,
			kind: action ? "security" : "system",
			name,
			severity: str(raw.eventSeverity, 32),
			priority: str(raw.eventPriority, 32),
			confidence: str(pick("eventConfidence"), 32),
			action,
			incident_type: str(data.waapIncidentType, 100),
			source_ip: str(data.sourceIP ?? data.sourceIp, 64),
			source_port: int(data.sourcePort),
			proxy_ip: str(data.proxyIP ?? data.proxyIp, 255),
			source_country: str(data.sourceCountryName, 64),
			host: str(data.httpHostName).toLowerCase(),
			asset: str(pick("assetName")),
			method: str(data.httpMethod, 16),
			uri: str(data.httpUriPath, MAX_TEXT),
			query: str(data.httpUriQuery, MAX_TEXT),
			response_code: int(data.httpResponseCode),
			location: str(data.matchedLocation, 64),
			parameter: str(data.matchedParameter, MAX_TEXT),
			sample: str(data.matchedSample, MAX_TEXT),
			indicators: str(data.waapFoundIndicators, MAX_TEXT),
			score: num(data.waapFinalScore),
			rule: str(pick("ruleName")),
			practice: str(pick("practiceName")),
			override: str(data.waapOverride, 32),
			service: str(origin.serviceName, 100),
			raw: rawText,
		},
	};
};

/**
 * Parses a chunk of a log file. Only complete lines count: the rest is read again next time.
 * @param {Buffer} buffer
 * @returns {{lines: object[], consumed: number}}  consumed: bytes up to the last newline
 */
export const parseChunk = (buffer) => {
	const end = buffer.lastIndexOf(0x0a);
	if (end < 0) return { lines: [], consumed: 0 };
	const lines = [];
	for (const line of buffer.subarray(0, end).toString("utf8").split("\n")) {
		if (!line.startsWith("{")) continue;
		try {
			lines.push(JSON.parse(line));
		} catch {
			// debug output in the log file
		}
	}
	return { lines, consumed: end + 1 };
};
