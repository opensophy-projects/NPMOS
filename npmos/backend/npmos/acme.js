// NPMOS: ACME account registration on first use.
// Upstream registers the account in launch.sh at every start, which contacts the ACME server
// (and, for ZeroSSL, api.zerossl.com) even when no ACME certificate is ever requested, and
// blocks startup when offline. NPMOS registers right before the first certbot request instead.
import { readdir } from "node:fs/promises";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { certbot as logger } from "../logger.js";

const ACCOUNTS_DIR = "/data/tls/certbot/accounts";
const ZEROSSL_HOST = "acme.zerossl.com";
const ZEROSSL_EAB_URL = "https://api.zerossl.com/acme/eab-credentials-email";
const HTTP_TIMEOUT_MS = 20000;

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
	const response = await fetch(ZEROSSL_EAB_URL, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ email }),
		signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
	});
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
	if (err?.public) {
		return err;
	}
	const detail = `${err?.message || err}`.trim() || "no output";
	return new errs.ValidationError(`Certificate request failed: ${detail}`, err);
};

export { acmeError, ensureAcmeAccount };
