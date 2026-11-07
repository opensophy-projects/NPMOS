// Who made a request (Analytics → Visitors, the request log): a person in a browser, a bot that says so (search
// engines, link previews, monitoring, scripts) or a scanner (probes for leaked files and admin pages, tools of mass
// scanning, requests to the bare IP, requests a protection refused). Decided from the request alone when it is
// written, plus the addresses seen scanning: once an address scans, its other requests are a scanner's too
// (requests.js). No list is fetched: the rules are here and work offline.

/** tools of mass scanning and probing, by their User-Agent */
const SCANNER_AGENT =
	/zgrab|masscan|nmap|nuclei|sqlmap|nikto|censys|expanse|xpanse|shodan|internet-?measurement|l9scan|l9explore|leakix|httpx|fuzz|dirbuster|gobuster|ffuf|feroxbuster|wpscan|whatweb|netsystemsresearch|odin\.io|zmap|scaninfo|paloalto|cortex|hello,? world|research scan|project-?resonance|visionheight|keydrop|ivre-masscan|nessus|openvas|acunetix|burp|jaeles|dotdotpwn|struts|log4j|jndi/i;

/** files and pages that only scanners ask for on a site that is not built on them: any answer */
const PROBE_ALWAYS =
	/(^|\/)\.(env|git|svn|hg|aws|ssh|docker|kube|DS_Store|htpasswd|bash_history|npmrc|vscode|idea)(\/|$|\.)|\/vendor\/phpunit\/|eval-stdin\.php|\/cgi-bin\/|\/boaform\/|\/HNAP1|\/GponForm|\/setup\.cgi|\/shell\b|\/\.well-known\/(?!acme-challenge|security\.txt|openid|change-password|apple|assetlinks|host-meta|webfinger|nodeinfo|matrix|mta-sts|caldav|carddav)[^/]*\.php|\/(wp-config|config|settings|database|db|backup|dump)\.(php\.)?(bak|old|save|swp|sql|zip|tar|gz|txt|orig)$|\/\.?(sftp|ftp)-config\.json$|\/_ignition\/|\/actuator(\/|$)|\/server-status$|\/solr\/admin|\/owa\/auth|\/remote\/(login|fgt_lang)|\/(phpmyadmin|pma|myadmin|phpMyAdmin)\b|\/manager\/html|\/jmx-console|\/invoker\/|\/console\/login|\/xmlrpc\.php$|\/autodiscover\/autodiscover\.xml$/i;

/** pages of popular software: a scanner's probe when the site answers that it has no such page (404; a 401 or 403
 * is a page that exists and asks who you are) */
const PROBE_MISSING =
	/\/(wp-login\.php|wp-admin|wp-content|wp-includes|wp-json|administrator|admin\.php|login\.action|user\/login|api\/v1\/pods|containers\/json|telescope|debug|_profiler|graphql|swagger|v2\/api-docs|druid|nacos|geoserver|jenkins|webui|cgi|admin|login|install|setup|phpinfo)\b|\.(php|asp|aspx|jsp|cgi|pl|do|action)$/i;

/** an IPv4 or IPv6 address as the Host: nobody types it, scanners walk the address space */
const BARE_ADDRESS = /^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9a-f]*:[0-9a-f:]+\]?)(:\d+)?$/i;

export const CLIENTS = ["human", "bot", "scanner"];

/**
 * What only a scanner does: no User-Agent, a tool of scanning, the bare IP as the Host, a probe for a leaked file or
 * a missing admin page. An address that does it is a scanner for a while (requests.js spreadScanners).
 * @param {object} r  user_agent, host, path, status
 */
export const scans = (r) => {
	const ua = r.user_agent || "";
	const path = r.path || "";
	return (
		!ua ||
		SCANNER_AGENT.test(ua) ||
		!r.host ||
		r.host === "_" ||
		BARE_ADDRESS.test(r.host) ||
		PROBE_ALWAYS.test(path) ||
		(r.status === 404 && PROBE_MISSING.test(path))
	);
};

/**
 * @param {object} r  a parsed line of the request log (requests.js parseLine): user_agent, host, path, status,
 *   device, protocol, and acceptLanguage (undefined in lines written before it was logged)
 * @returns {"human"|"bot"|"scanner"}
 */
export const classifyClient = (r) => {
	if (scans(r)) return "scanner";
	// refused by the WAF or the bouncer, or dropped (444): this request only (a false positive of the WAF must not
	// make a person a scanner); not a limit (429) or a missing client certificate
	if (r.status === 403 || r.status === 444) return "scanner";
	if (r.device === "bot") return "bot";
	// a browser always says which languages it wants, and does not speak HTTP/1.0: a script that took the name of
	// a browser does not
	if (r.acceptLanguage === "" || r.protocol === "HTTP/1.0") return "bot";
	return "human";
};
