// lego, the second ACME client of NPMOS (npmos/acme/servers.js: client "lego"). certbot registers with an RSA key
// (RS256) and sends a CSR without a subject; some CAs accept only ES256 account keys and need the name in the CN
// (the TLS CA of the Russian Federation, for one). lego does both, takes EAB, ACME profiles, your own CSR, a reason
// code of revocation, and solves DNS-01 with 150+ providers (credentials as KEY=VALUE, `lego dnshelp -c <code>`).
// The certificate goes to the place of a certbot one (/data/tls/certbot/live/npm-<id>), so hosts and nginx use it
// the same way; NPMOS renews it itself (the renewal point of cert-terms.js), like a certificate of your own CSR.
import { spawn } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { domainToASCII } from "node:url";
import errs from "../../lib/error.js";
import { certbot as logger } from "../../logger.js";
import { eabOf } from "../acme.js";

const LEGO = process.env.NPMOS_LEGO || "lego";
const LEGO_PATH = "/data/tls/lego";
const WEBROOT = "/data/tls/certbot/acme-challenge";
const LIVE_DIR = "/data/tls/certbot/live";
// lego waits for DNS propagation by itself; a request must still end
const TIMEOUT_MS = 10 * 60 * 1000;
// revocation reasons of RFC 5280 (some CAs accept only a few of them: 1, 4, 5)
export const REASON = { keyCompromise: 1, superseded: 4, cessationOfOperation: 5 };

const fileName = (id) => `npm-${id}`;
const liveDir = (id) => `${LIVE_DIR}/npm-${id}`;

/**
 * lego with the environment of a DNS provider; rejects like execFile (err.stdout, err.stderr) and keeps the
 * whole output for the full log (err.npmosLog)
 */
const runLego = (args, env = {}) =>
	new Promise((resolve, reject) => {
		const child = spawn(LEGO, args, {
			stdio: ["ignore", "pipe", "pipe"],
			env: { ...process.env, LEGO_DISABLE_CNAME_SUPPORT: "false", ...env },
		});
		const out = [];
		const timer = setTimeout(() => child.kill("SIGTERM"), TIMEOUT_MS);
		child.stdout.on("data", (d) => out.push(d));
		child.stderr.on("data", (d) => out.push(d));
		child.on("error", (err) => {
			clearTimeout(timer);
			reject(err.code === "ENOENT" ? new errs.ValidationError("lego is not installed in this image") : err);
		});
		child.on("close", (code, signal) => {
			clearTimeout(timer);
			const text = Buffer.concat(out).toString();
			if (code === 0) return resolve(text);
			// the lines that say what went wrong, not the whole log
			const problem = text
				.split("\n")
				.filter((l) => !/\[INFO\]/.test(l))
				.join("\n")
				.trim();
			reject(
				Object.assign(new Error(problem || text.trim() || `lego stopped (${signal || code})`), {
					stdout: text,
					stderr: "",
					code,
					npmosLog: text,
				}),
			);
		});
	});

/** the options of the account: server, email, EAB, TLS of the server */
const accountArgs = async (server) => {
	const { kid, hmacKey } = await eabOf(server);
	return [
		"--accept-tos",
		"--server",
		server.directory,
		"--path",
		LEGO_PATH,
		"--user-agent",
		"NPMOS",
		...(server.email ? ["--email", server.email] : []),
		...(kid && hmacKey ? ["--eab", "--kid", kid, "--hmac", hmacKey] : []),
		...(server.tls_verify ? [] : ["--tls-skip-verify"]),
	];
};

/** KEY=VALUE lines (comments and empty lines left out) → the environment of lego */
export const parseCredentials = (text = "") => {
	const env = {};
	for (const raw of String(text).split("\n")) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const at = line.indexOf("=");
		if (at < 1) throw new errs.ValidationError(`The DNS credentials are KEY=VALUE lines: "${line.slice(0, 40)}"`);
		const key = line.slice(0, at).trim();
		if (!/^[A-Z][A-Z0-9_]*$/.test(key)) throw new errs.ValidationError(`Not a variable name of lego: ${key}`);
		env[key] = line
			.slice(at + 1)
			.trim()
			.replace(/^(["'])(.*)\1$/, "$2");
	}
	return env;
};

/** the challenge of a certificate: HTTP-01 in the webroot nginx serves, or DNS-01 with a provider of lego */
export const challengeArgs = (meta = {}) => {
	if (!meta.dns_challenge) return { args: ["--http", "--http.webroot", WEBROOT], env: {} };
	const code = String(meta.dns_provider || "");
	if (!/^[a-z0-9.-]+$/.test(code)) throw new errs.ValidationError("Choose the DNS provider");
	const args = ["--dns", code];
	if (meta.propagation_seconds) args.push("--dns.propagation-wait", `${Number(meta.propagation_seconds)}s`);
	return { args, env: parseCredentials(meta.dns_provider_credentials) };
};

const pemBlocks = (pem) => pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];

/** the files of lego → cert.pem, chain.pem, fullchain.pem, privkey.pem of /data/tls/certbot/live/npm-<id> */
const install = async (id, keyFile) => {
	const crt = await readFile(`${LEGO_PATH}/certificates/${fileName(id)}.crt`, "utf8");
	const blocks = pemBlocks(crt);
	if (!blocks.length) throw new errs.ValidationError("lego returned no certificate");
	const live = liveDir(id);
	await mkdir(live, { recursive: true });
	const files = {
		"cert.pem": `${blocks[0]}\n`,
		"chain.pem": blocks.slice(1).join("\n") + (blocks.length > 1 ? "\n" : ""),
		"fullchain.pem": `${blocks.join("\n")}\n`,
		"privkey.pem": await readFile(keyFile || `${LEGO_PATH}/certificates/${fileName(id)}.key`, "utf8"),
	};
	// written next to the served files first, then each replaced in one step
	for (const [name, content] of Object.entries(files)) {
		await writeFile(`${live}/${name}.new`, content, { mode: name === "privkey.pem" ? 0o600 : 0o644 });
	}
	for (const name of Object.keys(files)) {
		await rm(`${live}/${name}`, { force: true });
		await copyFile(`${live}/${name}.new`, `${live}/${name}`);
		await rm(`${live}/${name}.new`, { force: true });
	}
};

/**
 * A certificate from the server: a new order each time (issue and renewal alike), lego keeps its account.
 * @param {{id, domain_names, meta}} cert
 * @param {object} server  internal form of npmos/acme/servers.js
 * @param {{csr?: string, key?: string}} [own]  the CSR file and its key (your own CSR)
 */
export const issue = async (cert, server, own = {}) => {
	const meta = cert.meta || {};
	const { args: challenge, env } = challengeArgs(meta);
	const names = (cert.domain_names || []).map((d) => d.replace(/^\[|\]$/g, ""));
	const args = [
		...(await accountArgs(server)),
		"--filename",
		fileName(cert.id),
		...(own.csr ? ["--csr", own.csr] : ["--key-type", meta.lego_key_type || "ec256"]),
		...(own.csr ? [] : names.flatMap((n) => ["--domains", n.includes(":") ? n : domainToASCII(n) || n])),
		...challenge,
		"run",
		...(server.profile ? ["--profile", server.profile] : []),
		...(own.key ? ["--private-key", own.key] : []),
	];
	await mkdir(LEGO_PATH, { recursive: true, mode: 0o700 });
	logger.info(
		`Requesting a certificate with lego from ${server.directory} for Cert #${cert.id}: ${names.join(", ")}`,
	);
	const output = await runLego(args, env);
	await install(cert.id, own.key);
	logger.info(`lego issued the certificate of Cert #${cert.id}`);
	return output;
};

/** revokes the certificate (reason: a code of REASON) and removes its files */
export const revoke = async (cert, server, reason = REASON.cessationOfOperation, throwErrors = false) => {
	try {
		// "revoke" finds the file by --domains, not by --filename: the file name is given as the "domain" (the
		// revocation sends the certificate itself); --keep: NPMOS removes the files below
		await runLego([
			...(await accountArgs(server)),
			"--domains",
			fileName(cert.id),
			"revoke",
			"--keep",
			"--reason",
			String(reason),
		]);
		logger.info(`lego revoked the certificate of Cert #${cert.id} (reason ${reason})`);
	} catch (err) {
		logger.error(`lego could not revoke the certificate of Cert #${cert.id}: ${err.message}`);
		if (throwErrors) throw err;
	} finally {
		for (const ext of ["crt", "key", "issuer.crt", "json", "pem"]) {
			await rm(`${LEGO_PATH}/certificates/${fileName(cert.id)}.${ext}`, { force: true });
		}
		await rm(liveDir(cert.id), { recursive: true, force: true });
	}
};

let providersCache = null;
/** the codes of the DNS providers of lego (`lego dnshelp`) */
export const dnsProviders = async () => {
	if (providersCache) return providersCache;
	const text = await runLego(["dnshelp"]);
	const at = text.indexOf("Supported DNS providers:");
	const list = at < 0 ? "" : text.slice(at + "Supported DNS providers:".length).split(/\n\s*\n/)[0];
	providersCache = list
		.split(/[,\s]+/)
		.map((c) => c.trim())
		.filter((c) => /^[a-z0-9.-]+$/.test(c));
	return providersCache;
};

/** what a provider needs (`lego dnshelp -c <code>`): its variables and their meaning */
export const dnsProviderHelp = async (code) => {
	if (!(await dnsProviders()).includes(code)) throw new errs.ItemNotFoundError(code);
	return runLego(["dnshelp", "-c", code]);
};

export default { issue, revoke, dnsProviders, dnsProviderHelp, REASON };
