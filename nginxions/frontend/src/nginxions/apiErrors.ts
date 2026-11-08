// An answer of /api that is not JSON never comes from the backend of NginxionS: something in front of it answered
// instead. When the panel is opened through a proxy host, that is the protection of the host (open-appsec, the
// CrowdSec bouncer or AppSec, mTLS, an access list) or a page of nginx. Without this the interface showed
// "Unexpected token '<', "<!DOCTYPE "... is not valid JSON".
import { intl } from "src/locale";

/** the error for an answer that is not JSON: who answered and what to do */
export function notJsonError(response: Response): Error {
	const status = response.status;
	const values = { status, host: window.location.host };
	let id = "nginxions.api.not-json";
	if (status === 403 || status === 495 || status === 496) id = "nginxions.api.not-json.blocked";
	else if (status === 404) id = "nginxions.api.not-json.not-found";
	else if (status >= 500) id = "nginxions.api.not-json.unavailable";
	const error = new Error(intl.formatMessage({ id }, values));
	(error as any).status = status;
	return error;
}

/** true when the answer is not JSON (a page of nginx, the block page, the mTLS page…) */
export function isNotJson(response: Response): boolean {
	const type = response.headers.get("Content-Type") || "";
	return !type.includes("json");
}
