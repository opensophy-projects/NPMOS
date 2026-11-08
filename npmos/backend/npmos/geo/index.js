// Countries of a host (Hosts → a host → Countries): only some countries let in ("allow"), or some kept out
// ("deny"). nginx decides it before anything else of the host, with the module geoip2 and the GeoIP database of
// System → Settings → GeoIP (offline). Stored in the meta of the host (meta.npmos_geo), set with the host; the
// templates get it checked here (npmos_geo), never the raw meta. The ACME challenge and private addresses always
// pass; without a database nothing is blocked (the GUI says so).
import { readFile, rename, writeFile } from "node:fs/promises";
import { global as logger } from "../../logger.js";
import { databaseFile } from "../geoip/index.js";

export const HOST_TYPES = ["proxy_host", "redirection_host", "dead_host"];
export const MODES = ["allow", "deny"];
const ACTIONS = ["403", "444"];
const CODE = /^[A-Z]{2}$/;
const CONF = process.env.NPMOS_GEO_CONF || "/usr/local/nginx/conf/conf.d/npmos-geo.conf";

/**
 * The countries of a host from its meta, checked: null when off or empty.
 * @returns {{mode: "allow"|"deny", countries: string[], action: "403"|"444"}|null}
 */
export const geoOf = (meta) => {
	const g = meta?.npmos_geo;
	if (!g || !MODES.includes(g.mode)) return null;
	const countries = [...new Set((Array.isArray(g.countries) ? g.countries : []).map((c) => String(c).toUpperCase()))]
		.filter((c) => CODE.test(c))
		.sort();
	if (!countries.length) return null;
	return { mode: g.mode, countries, action: ACTIONS.includes(String(g.action)) ? String(g.action) : "403" };
};

/** npmos_geo of the templates (_common.conf): the mode, a pattern of the countries and the answer */
export const prepareHost = (hostType, host) => {
	if (!HOST_TYPES.includes(hostType)) return;
	const geo = geoOf(host?.meta);
	host.npmos_geo = geo ? { mode: geo.mode, pattern: geo.countries.join("|"), action: geo.action } : null;
};

/**
 * The http part of nginx: $npmos_country (ISO code of the client's country) from the database, $npmos_geo_ready
 * 1 when there is one (else the rules of the hosts let everything in), $npmos_geo_lan for private addresses.
 */
export const geoConf = (
	file,
) => `# NPMOS: countries of the clients for the countries of the hosts (npmos/geo). Written by the backend.
geo $npmos_geo_lan {
  default 0;
  127.0.0.0/8 1;
  10.0.0.0/8 1;
  172.16.0.0/12 1;
  192.168.0.0/16 1;
  100.64.0.0/10 1;
  169.254.0.0/16 1;
  ::1/128 1;
  fc00::/7 1;
  fe80::/10 1;
}
${
	file
		? `geoip2 ${file} {
  auto_reload 5m;
  $npmos_country country iso_code;
}
map "" $npmos_geo_ready { default 1; }`
		: `map "" $npmos_country { default ""; }
map "" $npmos_geo_ready { default 0; }`
}
`;

/** writes the http part for the database in use; reloads nginx when asked and it changed */
export const writeGeoConf = async ({ reload = true } = {}) => {
	const file = await databaseFile().catch(() => null);
	// a path nginx can read as one word
	const usable = file && /^[\w./-]+$/.test(file) ? file : null;
	const text = geoConf(usable);
	if ((await readFile(CONF, "utf8").catch(() => "")) === text) return false;
	await writeFile(`${CONF}.tmp`, text);
	await rename(`${CONF}.tmp`, CONF);
	if (reload) {
		try {
			// loaded here: internal/nginx.js reads the configuration of the app (and imports this module)
			const { default: internalNginx } = await import("../../internal/nginx.js");
			await internalNginx.reload();
		} catch (err) {
			logger.warn(`NPMOS geo: nginx reload: ${err.message}`);
		}
	}
	return true;
};

/** whether nginx can tell countries (a GeoIP database is there) */
export const geoAvailable = async () => !!(await databaseFile().catch(() => null));

/** at the start, before nginx is reloaded by the backend: never fails the start */
export const bootstrap = async () => {
	try {
		await writeGeoConf({ reload: false });
	} catch (err) {
		logger.warn(`NPMOS geo: ${err.message}`);
	}
};
