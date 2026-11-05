// ACME with your own CSR: the administrator brings the request (and its key) made elsewhere — a key type, a subject
// or extensions NPMOS does not choose, a key kept outside — and the ACME server signs it. certbot takes a CSR only
// with "certonly --csr" and keeps no renewal configuration for it, so NPMOS renews such certificates itself (the
// same CSR again, from the renewal point of cert-terms.js) and revokes them by the file. The certificate is a
// "letsencrypt" row of NPMplus with meta.npmos_csr: hosts, nginx and the rest use it like any ACME certificate.
import { createPrivateKey, createPublicKey } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { domainToASCII } from "node:url";
import dayjs from "dayjs";
import dnsPlugins from "../certbot/dns-plugins.json" with { type: "json" };
import internalAuditLog from "../internal/audit-log.js";
import errs from "../lib/error.js";
import { installPlugin } from "../lib/certbot.js";
import utils from "../lib/utils.js";
import { certbot as logger } from "../logger.js";
import certificateModel from "../models/certificate.js";
import { acmeError, acmeRenewEnabled, ensureAcmeAccount } from "./acme.js";
import { termOf } from "./cert-terms.js";

const CSR_DIR = "/data/tls/certbot/csr";
const LIVE_DIR = "/data/tls/certbot/live";
const MAX_PEM = 64 * 1024;

const csrDir = (id) => `${CSR_DIR}/npm-${id}`;
const liveDir = (id) => `${LIVE_DIR}/npm-${id}`;

const pemBlock = (text, label) => {
	const m = String(text ?? "").match(new RegExp(`-----BEGIN ${label}-----[\\s\\S]+?-----END ${label}-----`));
	return m ? `${m[0]}\n` : null;
};

/** what openssl says about a CSR: its names, its public key, whether its signature holds */
const opensslCsr = async (csr) => {
	const dir = await mkdtemp("/tmp/npmos-csr-");
	try {
		const file = `${dir}/req.pem`;
		await writeFile(file, csr);
		const text = await utils.execFile("openssl", ["req", "-in", file, "-noout", "-text", "-verify"]);
		const pubkey = await utils.execFile("openssl", ["req", "-in", file, "-noout", "-pubkey"]);
		return { text, pubkey };
	} catch (err) {
		throw new errs.ValidationError(`The CSR is not valid: ${String(err.message || err).split("\n")[0]}`);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

/** names of the CSR: DNS and IP of subjectAltName (ACME and certbot take the names from there only) */
export const namesOf = (text) => {
	const san = text.match(/X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]+)/);
	if (!san) return [];
	return san[1]
		.split(",")
		.map((v) => v.trim())
		.filter((v) => /^(DNS|IP Address):/.test(v))
		.map((v) => v.replace(/^(DNS|IP Address):/, "").toLowerCase());
};

/** the key type of the CSR as openssl names it */
const keyTypeOf = (text) => {
	const algo = text.match(/Public Key Algorithm:\s*(\S+)/)?.[1] ?? "";
	const bits = text.match(/Public-Key:\s*\((\d+) bit\)/)?.[1];
	return bits ? `${algo} ${bits}` : algo;
};

/**
 * Checks a CSR and its key: the signature, the names, that the key is the one of the CSR.
 * @returns {Promise<{csr: string, key: string, names: string[], key_type: string, subject: string}>}
 */
export const checkCsr = async (csrText, keyText) => {
	const csr = pemBlock(csrText, "CERTIFICATE REQUEST") || pemBlock(csrText, "NEW CERTIFICATE REQUEST");
	if (!csr || csr.length > MAX_PEM)
		throw new errs.ValidationError("Paste the CSR in PEM (BEGIN CERTIFICATE REQUEST)");
	const { text, pubkey } = await opensslCsr(csr);
	if (!/verify OK|Certificate request self-signature verify OK/i.test(text)) {
		throw new errs.ValidationError("The signature of the CSR does not hold");
	}
	const names = namesOf(text);
	if (!names.length) {
		throw new errs.ValidationError(
			"The CSR has no subjectAltName with its domains: ACME servers take the names from there",
		);
	}
	const key = String(keyText ?? "").trim();
	if (!key)
		throw new errs.ValidationError("The private key of the CSR is needed: nginx serves the certificate with it");
	let same = false;
	try {
		const fromKey = createPublicKey(createPrivateKey(key)).export({ type: "spki", format: "der" });
		const fromCsr = createPublicKey(pubkey).export({ type: "spki", format: "der" });
		same = Buffer.compare(fromKey, fromCsr) === 0;
	} catch {
		throw new errs.ValidationError("The private key is not valid (PEM, not encrypted)");
	}
	if (!same) throw new errs.ValidationError("The private key does not belong to the CSR");
	const subject = text.match(/Subject:\s*([^\n]*)/)?.[1]?.trim() ?? "";
	return { csr, key: `${key}\n`, names, key_type: keyTypeOf(text), subject };
};

/** certbot certonly --csr into a fresh directory (certbot picks other names when the files exist) */
const requestFor = async (cert) => {
	const dir = csrDir(cert.id);
	const meta = cert.meta || {};
	const out = await mkdtemp("/tmp/npmos-csr-out-");
	let credentials = null;
	try {
		await ensureAcmeAccount();
		const challenge = [];
		if (meta.dns_challenge) {
			const plugin = dnsPlugins[meta.dns_provider];
			if (!plugin) throw new errs.ValidationError(`Unknown DNS provider '${meta.dns_provider}'`);
			await installPlugin(meta.dns_provider);
			credentials = `/tmp/certbot-credentials/credentials-csr-${cert.id}`;
			await mkdir("/tmp/certbot-credentials", { recursive: true });
			await writeFile(credentials, meta.dns_provider_credentials || "", { mode: 0o600 });
			challenge.push(
				"--authenticator",
				plugin.full_plugin_name,
				`--${plugin.full_plugin_name}-credentials`,
				credentials,
			);
			if (meta.propagation_seconds !== undefined && meta.propagation_seconds !== null) {
				challenge.push(`--${plugin.full_plugin_name}-propagation-seconds`, String(meta.propagation_seconds));
			}
		} else {
			challenge.push("--authenticator", "webroot");
		}
		logger.info(`Requesting a certificate for the CSR of Cert #${cert.id}: ${cert.domain_names.join(", ")}`);
		const result = await utils.execFile("certbot", [
			"--config",
			"/etc/certbot.ini",
			"certonly",
			"--server",
			process.env.ACME_SERVER,
			"--csr",
			`${dir}/csr.pem`,
			"--cert-path",
			`${out}/cert.pem`,
			"--fullchain-path",
			`${out}/fullchain.pem`,
			"--chain-path",
			`${out}/chain.pem`,
			...challenge,
		]);
		logger.info(result);
		const live = liveDir(cert.id);
		await mkdir(live, { recursive: true });
		for (const name of ["cert.pem", "chain.pem", "fullchain.pem"]) {
			await copyFile(`${out}/${name}`, `${live}/${name}.new`);
		}
		await copyFile(`${dir}/privkey.pem`, `${live}/privkey.pem`);
		// replace the served files in one step each
		for (const name of ["cert.pem", "chain.pem", "fullchain.pem"]) {
			await rm(`${live}/${name}`, { force: true });
			await copyFile(`${live}/${name}.new`, `${live}/${name}`);
			await rm(`${live}/${name}.new`, { force: true });
		}
		return result;
	} finally {
		await rm(out, { recursive: true, force: true });
		if (credentials) await rm(credentials, { force: true });
	}
};

const expiresOf = async (id) => {
	const pem = await readFile(`${liveDir(id)}/fullchain.pem`, "utf8");
	const { X509Certificate } = await import("node:crypto");
	const x509 = new X509Certificate(pemBlock(pem, "CERTIFICATE"));
	return dayjs(new Date(x509.validTo)).format("YYYY-MM-DD HH:mm:ss");
};

const internalAcmeCsr = {
	/** the names, key type and subject of a CSR, before it is sent */
	check: async (access, data) => {
		await access.can("certificates:create");
		const { names, key_type, subject } = await checkCsr(data.csr, data.key);
		return { names, key_type, subject };
	},

	/**
	 * A certificate for the CSR: {csr, key, meta: {dns_challenge?, dns_provider?, dns_provider_credentials?,
	 * propagation_seconds?}}
	 */
	create: async (access, data) => {
		await access.can("certificates:create");
		const { csr, key, names, key_type, subject } = await checkCsr(data.csr, data.key);
		const input = data.meta || {};
		const meta = { npmos_csr: true, npmos_csr_key_type: key_type, npmos_csr_subject: subject };
		if (input.dns_challenge) {
			if (!dnsPlugins[input.dns_provider]) throw new errs.ValidationError("Choose the DNS provider");
			Object.assign(meta, {
				dns_challenge: true,
				dns_provider: input.dns_provider,
				dns_provider_credentials: input.dns_provider_credentials || "",
				...(input.propagation_seconds ? { propagation_seconds: Number(input.propagation_seconds) } : {}),
			});
		}
		const row = await certificateModel.query().insertAndFetch({
			owner_user_id: access.token.getUserId(1),
			provider: "letsencrypt",
			nice_name: names.join(", "),
			domain_names: names.map((n) => (n.includes(":") ? n : domainToASCII(n) || n)),
			meta,
		});
		try {
			await mkdir(csrDir(row.id), { recursive: true, mode: 0o700 });
			await writeFile(`${csrDir(row.id)}/csr.pem`, csr);
			await writeFile(`${csrDir(row.id)}/privkey.pem`, key, { mode: 0o600 });
			await requestFor(row);
			const saved = await certificateModel
				.query()
				.patchAndFetchById(row.id, { expires_on: await expiresOf(row.id) });
			await internalAuditLog.add(access, {
				action: "created",
				object_type: "certificate",
				object_id: row.id,
				meta: { nice_name: saved.nice_name, domain_names: names, provider: "letsencrypt", csr: true, key_type },
			});
			const { dns_provider_credentials: _, ...publicMeta } = saved.meta || {};
			return { ...saved, meta: publicMeta };
		} catch (err) {
			await certificateModel.query().deleteById(row.id);
			await rm(csrDir(row.id), { recursive: true, force: true });
			await rm(liveDir(row.id), { recursive: true, force: true });
			throw err instanceof errs.ValidationError ? err : acmeError(err);
		}
	},

	/** "Renew" of a certificate of a CSR: the same CSR again */
	renew: async (cert) => {
		await requestFor(cert);
		return expiresOf(cert.id);
	},

	/** revoke by the certificate file (no certbot lineage) and remove the files */
	revoke: async (cert, throwErrors) => {
		try {
			const result = await utils.execFile("certbot", [
				"--config",
				"/etc/certbot.ini",
				"revoke",
				"--server",
				process.env.ACME_SERVER,
				"--cert-path",
				`${liveDir(cert.id)}/cert.pem`,
				"--key-path",
				`${csrDir(cert.id)}/privkey.pem`,
				"--reason",
				"unspecified",
				"--no-delete-after-revoke",
			]);
			logger.info(result);
		} catch (err) {
			logger.error(err.message);
			if (throwErrors) throw err;
		} finally {
			await rm(liveDir(cert.id), { recursive: true, force: true });
			await rm(csrDir(cert.id), { recursive: true, force: true });
		}
	},

	/** the timer of NPMplus: certificates of a CSR past their renewal point are requested again */
	renewDue: async () => {
		if (!acmeRenewEnabled()) return;
		const rows = await certificateModel.query().where("is_deleted", 0).andWhere("provider", "letsencrypt");
		for (const cert of rows) {
			if (!cert.meta?.npmos_csr) continue;
			const term = await termOf(cert);
			if (!term.renew_from || Date.now() < new Date(term.renew_from).getTime()) continue;
			try {
				const expires = await internalAcmeCsr.renew(cert);
				await certificateModel.query().patchAndFetchById(cert.id, { expires_on: expires });
				logger.info(`Renewed the certificate of the CSR of Cert #${cert.id}`);
			} catch (err) {
				logger.warn(`Renewal of the certificate of the CSR of Cert #${cert.id} failed: ${err.message}`);
			}
		}
	},
};

export default internalAcmeCsr;
