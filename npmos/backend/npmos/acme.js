// NPMOS: certbot for an ACME server of Settings -> ACME (npmos/acme/servers.js): the account is registered on first
// use, at the server of the certificate. Upstream registers the account in launch.sh at every start, which contacts
// the ACME server (and, for ZeroSSL, api.zerossl.com) even when no ACME certificate is ever requested, and blocks
// startup when offline. NPMOS registers right before the first certbot request instead.
import { mkdirSync, writeFileSync } from "node:fs";
import { readdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { certbot as logger } from "../logger.js";
import acmeServers from "./acme/servers.js";
import { readWithStatSync } from "./files.js";
import { knownSecrets, redact } from "./redact.js";

const ACCOUNTS_DIR = "/data/tls/certbot/accounts";
const ZEROSSL_HOST = "acme.zerossl.com";
const ZEROSSL_EAB_URL = "https://api.zerossl.com/acme/eab-credentials-email";
const HTTP_TIMEOUT_MS = 20000;
// the full log of the last failed request, for "Full log" in the interface
const FAILURE_LOG = "/data/npmos/acme/last-failure.log";
// logs-dir of certbot (rootfs/etc/certbot.ini)
const CERTBOT_LOG = "/data/npmos/acme/certbot-log/letsencrypt.log";
const CERTBOT_LOG_FRESH_MS = 5 * 60 * 1000;

const pending = new Map();

/** the server of a call, the default one of Settings -> ACME when none is given */
const serverOf = async (server) => server || (await acmeServers.default());
const serverHost = (server) => new URL(server.directory).host;

/** --server and what the server of the certificate asks for on the command line of certbot */
const certbotServerArgs = (server) => [
	"--server",
	server.directory,
	...(server.profile ? ["--preferred-profile", server.profile] : []),
	...(server.tls_verify ? [] : ["--no-verify-ssl"]),
];

const hasAccount = async (server) => {
	try {
		const entries = await readdir(`${ACCOUNTS_DIR}/${serverHost(server)}`, {
			recursive: true,
			withFileTypes: true,
		});
		return entries.some((entry) => entry.isFile());
	} catch {
		return false;
	}
};

/**
 * ZeroSSL issues EAB credentials for an email address when none are configured
 * @returns {Promise<{kid: string, hmacKey: string}>}
 */
const fetchZeroSslEab = async (email) => {
	let response;
	try {
		response = await fetch(ZEROSSL_EAB_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ email }),
			signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
		});
	} catch (err) {
		// fetch says only "fetch failed": name the host and the reason under it
		const reason = err?.cause?.code || err?.cause?.message || err?.message || "";
		throw new errs.ValidationError(
			`NPMOS could not reach ${new URL(ZEROSSL_EAB_URL).host} for the EAB keys of ZeroSSL (${reason}). Check DNS and HTTPS to it, or enter EAB keys in System -> Settings -> ACME.`,
		);
	}
	const data = await response.json();
	if (!response.ok || !data.eab_kid || !data.eab_hmac_key) {
		throw new errs.ValidationError(`ZeroSSL did not issue EAB credentials (status ${response.status})`);
	}
	return { kid: data.eab_kid, hmacKey: data.eab_hmac_key };
};

/** the EAB keys of a server; ZeroSSL issues them for the email when none are set */
const eabOf = async (server) => {
	let kid = server.eab_kid || "";
	let hmacKey = server.eab_hmac_key || "";
	if (serverHost(server) === ZEROSSL_HOST && !kid && !hmacKey) {
		if (!server.email) {
			throw new errs.ValidationError("An email is required to use ZeroSSL (Settings -> ACME)");
		}
		({ kid, hmacKey } = await fetchZeroSslEab(server.email));
	}
	return { kid, hmacKey };
};

const register = async (server) => {
	const email = server.email || "";
	const { kid, hmacKey } = await eabOf(server);

	// a profile is a matter of the order, not of the account
	const args = ["--config", "/etc/certbot.ini", "register", ...certbotServerArgs({ ...server, profile: "" })];
	if (!email) {
		args.push("--register-unsafely-without-email");
	} else {
		args.push("--email", email);
		if (kid && hmacKey) {
			args.push("--eab-kid", kid, "--eab-hmac-key", hmacKey);
		}
	}

	logger.info(`Registering ACME account at ${server.directory}`);
	await utils.execFile("certbot", args);
	logger.success("ACME account registered");
};

/**
 * Registers the ACME account at the server if there is none yet.
 * Concurrent callers share one registration.
 */
const ensureAcmeAccount = async (given) => {
	const server = await serverOf(given);
	if (await hasAccount(server)) {
		return;
	}
	const key = server.directory;
	if (!pending.has(key)) {
		pending.set(
			key,
			register(server).finally(() => {
				pending.delete(key);
			}),
		);
	}
	await pending.get(key);
};

// the ACME server does not know the account any more (a reset step-ca or Pebble, a deactivated account)
const ACCOUNT_GONE = /accountDoesNotExist|Account \S+ not found|account (does not exist|is deactivated)/i;

const accountIds = async (server) => {
	try {
		const entries = await readdir(`${ACCOUNTS_DIR}/${serverHost(server)}`, {
			recursive: true,
			withFileTypes: true,
		});
		return entries.filter((e) => e.isFile() && e.name === "regr.json").map((e) => basename(e.parentPath));
	} catch {
		return [];
	}
};

/** the renewal files point at the account by its id: the new one takes the place of the old */
const replaceAccountInRenewals = async (oldIds, newId) => {
	let files = [];
	try {
		files = (await readdir(RENEWAL_DIR)).filter((f) => f.endsWith(".conf"));
	} catch {
		return;
	}
	for (const file of files) {
		const path = `${RENEWAL_DIR}/${file}`;
		const conf = await readFile(path, "utf8");
		const next = conf.replace(/^(\s*account\s*=\s*)(\S+)\s*$/m, (line, key, id) =>
			oldIds.includes(id) ? `${key}${newId}` : line,
		);
		if (next !== conf) await writeFile(path, next);
	}
};

/** a new account at the server instead of the one it forgot */
const replaceAccount = async (server) => {
	const oldIds = await accountIds(server);
	await rm(`${ACCOUNTS_DIR}/${serverHost(server)}`, { recursive: true, force: true });
	await ensureAcmeAccount(server);
	const [newId] = await accountIds(server);
	if (newId) await replaceAccountInRenewals(oldIds, newId);
};

/**
 * certbot with the ACME account of the server. Before, an account the server had forgotten failed every request
 * until the files were removed by hand; now NPMOS registers a new one and asks once more.
 * @param {string[]} args
 * @param {{register?: boolean, server?: object}} [options]  register: false for "renew" by the timer, which must not
 *   reach the ACME server when there is nothing to renew (local-first: no account is registered at the start of
 *   NPMOS); server: the ACME server of the certificate (npmos/acme/servers.js), the default one when not given
 */
const certbotAcme = async (args, { register = true, server: given } = {}) => {
	const server = await serverOf(given);
	if (register) await ensureAcmeAccount(server);
	try {
		return await utils.execFile("certbot", args);
	} catch (err) {
		if (!ACCOUNT_GONE.test(`${err?.message || ""}\n${err?.stderr || ""}`)) throw err;
		logger.warn(`${serverHost(server)} does not know the ACME account of NPMOS any more: registering a new one`);
		await replaceAccount(server);
		return utils.execFile("certbot", args);
	}
};

/**
 * Certbot and ACME failures are the admin's to fix (DNS, ports, rate limits), but upstream returns
 * them as a non-public CommandError, so the GUI showed "Internal Error". Pass certbot's output on.
 * @param   {Error} err
 * @returns {Error}
 */
const acmeError = (err, server) => {
	const output = `${err?.message || err}`.trim();
	saveFailureLog(output, server, err?.npmosLog);
	if (err?.public) {
		return err;
	}
	let host = "";
	try {
		host = serverHost(server);
	} catch {}
	return new errs.ValidationError(
		`Certificate request to ${host || "the ACME server"} failed: ${clean(output) || "no output"}${timeoutHint(output, host)}\n\nThe full log of the request: Certificates -> Full log of the last request.`,
		err,
	);
};

// certbot was written for Let's Encrypt and sends there for help, whatever server it asked: those lines go
const clean = (output) =>
	output
		.split("\n")
		.filter(
			(line) =>
				!/community\.letsencrypt\.org|See the logfile|re-run Certbot with -v|Ask for help or search|InsecureRequestWarning|^\s*warnings\.warn\(/i.test(
					line,
				),
		)
		.join("\n")
		.replace(/\n{3,}/g, "\n\n")
		.trim();

const saveFailureLog = (output, server, clientLog) => {
	try {
		// the log of lego, or the debug log of certbot if certbot ran for this request (it fails before that
		// without an account)
		let debug = "(certbot did not run)";
		let source = CERTBOT_LOG;
		if (clientLog !== undefined) {
			debug = clientLog;
			source = "lego";
		} else {
			try {
				const fresh = readWithStatSync(CERTBOT_LOG, {
					encoding: "utf8",
					accept: (st) => Date.now() - st.mtimeMs < CERTBOT_LOG_FRESH_MS,
				});
				if (fresh.data !== null) debug = fresh.data;
			} catch {}
		}
		const text = [
			`time: ${new Date().toISOString()}`,
			`ACME server: ${server ? `${server.name} (${server.directory}), client ${server.client}` : ""}`,
			"",
			"== output",
			output,
			"",
			`== ${source}`,
			debug,
		].join("\n");
		mkdirSync("/data/npmos/acme", { recursive: true });
		writeFileSync(
			FAILURE_LOG,
			redact(text, [...knownSecrets(), ...(server?.eab_hmac_key ? [server.eab_hmac_key] : [])]),
			{
				mode: 0o600,
			},
		);
	} catch (e) {
		logger.warn(`The log of the failed request is not saved: ${e.message}`);
	}
};

/** the full log of the last failed ACME request, or null */
const lastFailureLog = () => {
	try {
		const { stat, data } = readWithStatSync(FAILURE_LOG, { encoding: "utf8" });
		return { log: data, time: stat.mtime.toISOString() };
	} catch {
		return null;
	}
};

/** certbot gives up after 45 s without an answer: say what to check instead of only the traceback */
const timeoutHint = (detail, host = "") => {
	if (
		!/ReadTimeout|ConnectTimeout|Read timed out|timed out|Max retries exceeded|NewConnectionError|i\/o timeout|deadline exceeded/i.test(
			detail,
		)
	) {
		return "";
	}
	return `\n\nThe ACME server ${host} did not answer in time. Check that NPMOS can reach it (DNS, HTTPS on port 443, firewall, proxy) and try again, or choose another ACME server in System -> Settings -> ACME.`;
};

const RENEWAL_DIR = "/data/tls/certbot/renewal";

const acmeRenewEnabled = () => !/^(false|0|no|off)$/i.test(process.env.ACME_RENEW || "true");

/**
 * The renewal window (days before the end) of Settings -> ACME, in the renewal file of every certificate:
 * certbot has no option for it on the command line. 0 takes the line out, certbot decides (a third of the term,
 * at most 30 days).
 */
const setRenewWindow = (conf, days) => {
	const lines = conf.split("\n").filter((line) => !/^\s*renew_before_expiry\s*=/.test(line));
	if (days > 0) {
		// a top-level key: before the first [section]
		const at = lines.findIndex((line) => /^\s*\[/.test(line));
		lines.splice(at < 0 ? lines.length : at, 0, `renew_before_expiry = ${days} days`);
	}
	return lines.join("\n");
};

/** @param {string} [value]  days, ACME_RENEW_DAYS by default */
const applyRenewWindow = async (value = process.env.ACME_RENEW_DAYS) => {
	const days = Number.parseInt(value || "0", 10) || 0;
	let files = [];
	try {
		files = (await readdir(RENEWAL_DIR)).filter((f) => f.endsWith(".conf"));
	} catch {
		return;
	}
	for (const file of files) {
		const path = `${RENEWAL_DIR}/${file}`;
		try {
			const conf = await readFile(path, "utf8");
			const next = setRenewWindow(conf, days);
			if (next !== conf) await writeFile(path, next);
		} catch (err) {
			logger.warn(`Renewal window not set in ${file}: ${err.message}`);
		}
	}
};

export {
	ACCOUNT_GONE,
	acmeError,
	acmeRenewEnabled,
	applyRenewWindow,
	certbotAcme,
	certbotServerArgs,
	clean,
	eabOf,
	ensureAcmeAccount,
	lastFailureLog,
	setRenewWindow,
};
