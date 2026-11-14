// Requests refused by mTLS → nginxions_security_event (kind "mtls"): nginx writes them to their own log
// (_nginxions_mtls.conf, format nginxions_mtls of conf.d/nginxions-mtls-log.conf), read here every few seconds.
// The position is the cursor "mtls:denied" in nginxions_log_cursor, stored with the rows.
import { pollJsonLog, startJsonLog } from "../events/jsonlog.js";

export const LOG_FILE = process.env.NGINXIONS_MTLS_LOG || "/data/nginx/logs/nginxions-mtls.log";
const CURSOR = "mtls:denied";

const str = (v, max = 255) => String(v ?? "").slice(0, max);

/**
 * @param {object} line  a line of the log (JSON)
 * @returns {object|null} row of nginxions_security_event
 */
export const toEvent = (line, nodeId = "local") => {
	if (!line?.time || !line.ip) return null;
	const time = new Date(line.time);
	if (Number.isNaN(time.getTime())) return null;
	const verify = str(line.verify, 255);
	const missing = verify === "NONE" || verify === "";
	const [uri, query = ""] = str(line.uri, 4096).split(/\?(.*)/s);
	return {
		node_id: nodeId,
		time,
		kind: "mtls",
		name: missing ? "mTLS: no client certificate" : "mTLS: client certificate not accepted",
		severity: "medium",
		priority: "",
		confidence: "",
		action: "denied",
		incident_type: missing ? "mTLS no certificate" : "mTLS certificate",
		source_ip: str(line.ip, 64),
		source_port: null,
		proxy_ip: "",
		source_country: "",
		host: str(line.host).toLowerCase(),
		asset: "",
		method: str(line.method, 16),
		uri: uri.slice(0, 2048),
		query: query.slice(0, 2048),
		// the answer the host chose (denied_page): 403, 404 or 444 (closed); older lines have none
		response_code: Number.parseInt(line.status, 10) || 403,
		location: "",
		parameter: "",
		// SUCCESS here: the certificate is valid, but its issuer or a rule of the host refused it
		sample: str(
			[line.s_dn && `subject: ${line.s_dn}`, line.serial && `serial: ${line.serial}`].filter(Boolean).join("; "),
			2048,
		),
		indicators: "",
		score: null,
		rule: verify,
		practice: "",
		override: "",
		service: "nginx",
		raw: JSON.stringify(line).slice(0, 64 * 1024),
	};
};

/** one round: new lines of the log → events */
export const pollOnce = ({ file = LOG_FILE, now = new Date() } = {}) =>
	pollJsonLog({ file, cursor: CURSOR, toEvent, now });

export const startDenials = () => startJsonLog({ name: "mTLS denials", file: LOG_FILE, cursor: CURSOR, toEvent });
