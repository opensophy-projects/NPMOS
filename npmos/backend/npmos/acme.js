// NPMOS: ACME account registration on first use.
// Upstream registers the account in launch.sh at every start, which contacts the ACME server
// (and, for ZeroSSL, api.zerossl.com) even when no ACME certificate is ever requested, and
// blocks startup when offline. NPMOS registers right before the first certbot request instead.
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { readdir, readFile, writeFile } from "node:fs/promises";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { certbot as logger } from "../logger.js";
import { knownSecrets, redact } from "./redact.js";

const ACCOUNTS_DIR = "/data/tls/certbot/accounts";
const ZEROSSL_HOST = "acme.zerossl.com";
const ZEROSSL_EAB_URL = "https://api.zerossl.com/acme/eab-credentials-email";
const HTTP_TIMEOUT_MS = 20000;
// the full log of the last failed request, for "Full log" in the interface
const FAILURE_LOG = "/data/npmos/acme/last-failure.log";
const CERTBOT_LOG = "/tmp/certbot-log/letsencrypt.log";
const CERTBOT_LOG_FRESH_MS = 5 * 60 * 1000;

let pending = null;

const serverHost = () => new URL(process.env.ACME_SERVER).host;

const hasAccount = async () => {
	try {
		const entries = await readdir(`${ACCOUNTS_DIR}/${serverHost()}`, { recursive: true, withFileTypes: true });
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

const register = async () => {
	const email = process.env.ACME_EMAIL || "";
	let kid = process.env.ACME_EAB_KID || "";
	let hmacKey = process.env.ACME_EAB_HMAC_KEY || "";

	if (serverHost() === ZEROSSL_HOST && !kid && !hmacKey) {
		if (!email) {
			throw new errs.ValidationError("ACME_EMAIL is required to use ZeroSSL");
		}
		({ kid, hmacKey } = await fetchZeroSslEab(email));
	}

	const args = ["--config", "/etc/certbot.ini", "register", "--server", process.env.ACME_SERVER];
	if (!email) {
		args.push("--register-unsafely-without-email");
	} else {
		args.push("--email", email);
		if (kid && hmacKey) {
			args.push("--eab-kid", kid, "--eab-hmac-key", hmacKey);
		}
	}

	logger.info(`Registering ACME account at ${process.env.ACME_SERVER}`);
	await utils.execFile("certbot", args);
	logger.success("ACME account registered");
};

/**
 * Registers the ACME account for ACME_SERVER if there is none yet.
 * Concurrent callers share one registration.
 */
const ensureAcmeAccount = async () => {
	if (await hasAccount()) {
		return;
	}
	if (!pending) {
		pending = register().finally(() => {
			pending = null;
		});
	}
	await pending;
};

/**
 * Certbot and ACME failures are the admin's to fix (DNS, ports, rate limits), but upstream returns
 * them as a non-public CommandError, so the GUI showed "Internal Error". Pass certbot's output on.
 * @param   {Error} err
 * @returns {Error}
 */
const acmeError = (err) => {
	const output = `${err?.message || err}`.trim();
	saveFailureLog(output);
	if (err?.public) {
		return err;
	}
	let host = "";
	try {
		host = serverHost();
	} catch {}
	return new errs.ValidationError(
		`Certificate request to ${host || "the ACME server"} failed: ${clean(output) || "no output"}${timeoutHint(output)}\n\nThe full log of the request: Certificates -> Full log of the last request.`,
		err,
	);
};

// certbot was written for Let's Encrypt and sends there for help, whatever server it asked: those lines go
const clean = (output) =>
	output
		.split("\n")
		.filter(
			(line) =>
				!/community\.letsencrypt\.org|See the logfile|re-run Certbot with -v|Ask for help or search/i.test(
					line,
				),
		)
		.join("\n")
		.replace(/\n{3,}/g, "\n\n")
		.trim();

const saveFailureLog = (output) => {
	try {
		// the debug log of certbot, if certbot ran for this request (it fails before that without an account)
		let debug = "(certbot did not run)";
		try {
			if (Date.now() - statSync(CERTBOT_LOG).mtimeMs < CERTBOT_LOG_FRESH_MS)
				debug = readFileSync(CERTBOT_LOG, "utf8");
		} catch {}
		const text = [
			`time: ${new Date().toISOString()}`,
			`ACME server: ${process.env.ACME_SERVER || ""}`,
			"",
			"== output",
			output,
			"",
			`== ${CERTBOT_LOG}`,
			debug,
		].join("\n");
		mkdirSync("/data/npmos/acme", { recursive: true });
		writeFileSync(FAILURE_LOG, redact(text, knownSecrets()), { mode: 0o600 });
	} catch (e) {
		logger.warn(`The log of the failed request is not saved: ${e.message}`);
	}
};

/** the full log of the last failed ACME request, or null */
const lastFailureLog = () => {
	try {
		return { log: readFileSync(FAILURE_LOG, "utf8"), time: statSync(FAILURE_LOG).mtime.toISOString() };
	} catch {
		return null;
	}
};

/** certbot gives up after 45 s without an answer: say what to check instead of only the traceback */
const timeoutHint = (detail) => {
	if (!/ReadTimeout|ConnectTimeout|Read timed out|timed out|Max retries exceeded|NewConnectionError/i.test(detail)) {
		return "";
	}
	let host = "";
	try {
		host = serverHost();
	} catch {}
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

export { acmeError, acmeRenewEnabled, applyRenewWindow, clean, ensureAcmeAccount, lastFailureLog, setRenewWindow };
