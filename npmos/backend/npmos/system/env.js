// Everyday env settings of NPMplus moved to the GUI (docs/ROADMAP.md, phase 4; docs/ENV-INVENTORY.md).
// They are read by the start scripts of the container (envs.sh/start.sh), so a change is saved in
// the database, written to /data/npmos/runtime.env and applied by a restart of npmos. envs.sh reads
// only these names with values of the same form (rootfs/usr/local/bin/envs.sh): a bad value can't
// stop the container.

export const LETS_ENCRYPT = "https://acme-v02.api.letsencrypt.org/directory";
// shown instead of a secret that is set; sent back unchanged it keeps the secret
export const SECRET_SET = "********";

const bool = (env, group, fallback, extra = {}) => ({ env, group, type: "bool", default: fallback, ...extra });
const int = (env, group, fallback, min, max) => ({ env, group, type: "int", default: fallback, min, max });

/** order = order in the GUI */
export const SYSTEM_ENV = [
	{ env: "TZ", group: "general", type: "tz", default: "UTC" },
	int("DEFAULT_CERT_ID", "general", 0, 0, 2147483647),
	bool("DISABLE_HTTP", "network", false),
	bool("DISABLE_H3_QUIC", "network", false),
	bool("LISTEN_PROXY_PROTOCOL_HTTP", "network", false),
	bool("LISTEN_PROXY_PROTOCOL_HTTPS", "network", false),
	bool("ENABLE_MPTCP", "network", false),
	bool("NGINX_QUIC_BPF", "network", false),
	// downloads the IP ranges of Cloudflare: needs internet
	bool("TRUST_CLOUDFLARE", "network", false, { internet: true }),
	{ env: "NGINX_WORKER_PROCESSES", group: "nginx", type: "workers", default: "auto", min: 1, max: 1024 },
	int("NGINX_WORKER_CONNECTIONS", "nginx", 512, 64, 1048576),
	bool("NGINX_LOG_NOT_FOUND", "nginx", false),
	bool("NGINX_LOAD_NJS_MODULE", "nginx", false),
	bool("NGINX_LOAD_GEOIP2_MODULE", "nginx", false),
	bool("NGINX_LOAD_LDAP_MODULE", "nginx", false),
	bool("NGINX_LOAD_NTLM_MODULE", "nginx", false),
	bool("NGINX_LOAD_VHOST_TRAFFIC_STATUS_MODULE", "nginx", false),
	bool("NGINX_DISABLE_TLS12", "tls", false),
	bool("NGINX_FORCE_X25519MLKEM768", "tls", false),
	bool("NGINX_TRUST_SECPR1", "tls", true),
	bool("NGINX_TRUST_RSA_PKCS1", "tls", false),
	int("LOGROTATIONS", "logs", 3, 1, 365),
	// ACME: where certificates of "Let's Encrypt / ACME" come from; the account is registered at the
	// first request (npmos/acme.js), EAB is what ZeroSSL, Google and others ask for
	{ env: "ACME_SERVER", group: "acme", type: "url", default: LETS_ENCRYPT, internet: true },
	{ env: "ACME_EMAIL", group: "acme", type: "email", default: "" },
	{ env: "ACME_EAB_KID", group: "acme", type: "token", default: "" },
	{ env: "ACME_EAB_HMAC_KEY", group: "acme", type: "secret", default: "" },
	bool("NPMOS_CHECK_VERSION", "external", false, { internet: true }),
];

const BY_ENV = new Map(SYSTEM_ENV.map((d) => [d.env, d]));

/** a timezone name of the IANA database (Intl knows the same names as /usr/share/zoneinfo) */
const validTimeZone = (value) => {
	if (typeof value !== "string" || !/^[A-Za-z0-9_+-]+(\/[A-Za-z0-9_+-]+){0,2}$/.test(value)) return false;
	try {
		new Intl.DateTimeFormat("en", { timeZone: value });
		return true;
	} catch {
		return false;
	}
};

/**
 * A value of a setting in its form, or undefined when it is not valid.
 * @returns {boolean|number|string|undefined}
 */
export const normalize = (env, value) => {
	const def = BY_ENV.get(env);
	if (!def) return undefined;
	switch (def.type) {
		case "bool":
			if (value === true || value === "true") return true;
			if (value === false || value === "false") return false;
			return undefined;
		case "int": {
			const n = typeof value === "number" ? value : /^\d+$/.test(String(value)) ? Number(value) : Number.NaN;
			return Number.isInteger(n) && n >= def.min && n <= def.max ? n : undefined;
		}
		case "workers": {
			if (value === "auto") return "auto";
			const n = typeof value === "number" ? value : /^\d+$/.test(String(value)) ? Number(value) : Number.NaN;
			return Number.isInteger(n) && n >= def.min && n <= def.max ? n : undefined;
		}
		case "tz":
			return validTimeZone(value) ? value : undefined;
		// the same forms envs.sh accepts from runtime.env (no spaces, quotes or "=")
		case "url":
			return typeof value === "string" &&
				value.length <= 512 &&
				/^https?:\/\/[A-Za-z0-9._~:/?&%+@-]+$/.test(value)
				? value
				: undefined;
		case "email":
			return typeof value === "string" &&
				(value === "" || /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}$/.test(value))
				? value
				: undefined;
		case "token":
		case "secret":
			return typeof value === "string" && /^[A-Za-z0-9_-]{0,512}$/.test(value) ? value : undefined;
		default:
			return undefined;
	}
};

/** the value the running container has (envs.sh exports every one of them) */
export const running = (env, processEnv = process.env) => {
	const def = BY_ENV.get(env);
	const value = normalize(env, processEnv[env]);
	return value === undefined ? def.default : value;
};

/**
 * Validates changes {env: value}; values envs.sh would change on its own are refused with the reason
 * (the GUI explains them instead).
 * @param {Record<string, any>} values  all saved values after the change
 * @returns {string[]} problems
 */
export const conflicts = (values) => {
	const v = (env) => values[env];
	const problems = [];
	if (v("LISTEN_PROXY_PROTOCOL_HTTPS") === true && v("DISABLE_H3_QUIC") === false) {
		problems.push("LISTEN_PROXY_PROTOCOL_HTTPS needs DISABLE_H3_QUIC");
	}
	if (v("NGINX_FORCE_X25519MLKEM768") === true && v("NGINX_DISABLE_TLS12") === false) {
		problems.push("NGINX_FORCE_X25519MLKEM768 needs NGINX_DISABLE_TLS12");
	}
	if (v("NGINX_FORCE_X25519MLKEM768") === true && v("NGINX_TRUST_SECPR1") === true) {
		problems.push("NGINX_FORCE_X25519MLKEM768 needs NGINX_TRUST_SECPR1 off");
	}
	if (!!v("ACME_EAB_KID") !== !!v("ACME_EAB_HMAC_KEY")) {
		problems.push("ACME_EAB_KID and ACME_EAB_HMAC_KEY go together");
	}
	if ((v("ACME_EAB_KID") || /acme\.zerossl\.com/.test(v("ACME_SERVER") ?? "")) && !v("ACME_EMAIL")) {
		problems.push("ACME_EMAIL is needed with EAB and ZeroSSL");
	}
	return problems;
};

/** lines of runtime.env for the saved values */
export const envLines = (values) =>
	SYSTEM_ENV.filter((d) => values[d.env] !== undefined).map((d) => `${d.env}=${values[d.env]}`);
