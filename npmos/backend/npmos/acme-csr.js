// ACME with your own CSR: the administrator brings the request (and its key) made elsewhere — a key type, a subject
// or extensions NPMOS does not choose, a key kept outside — and the ACME server signs it. certbot takes a CSR only
// with "certonly --csr" and keeps no renewal configuration for it, so NPMOS renews such certificates itself (the
// same CSR again, from the renewal point of cert-terms.js) and revokes them by the file. The certificate is a
// "letsencrypt" row of NPMplus with meta.npmos_csr: hosts, nginx and the rest use it like any ACME certificate.
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
import { checkCsr, pemBlock } from "./acme-csr-check.js";
import { acmeError, acmeRenewEnabled, certbotAcme, certbotServerArgs } from "./acme.js";
import { clientOf, withServer } from "./acme/certs.js";
import lego, { REASON } from "./acme/lego.js";
import acmeServers from "./acme/servers.js";
import { termOf } from "./cert-terms.js";

const CSR_DIR = "/data/tls/certbot/csr";
const LIVE_DIR = "/data/tls/certbot/live";

const csrDir = (id) => `${CSR_DIR}/npm-${id}`;
const liveDir = (id) => `${LIVE_DIR}/npm-${id}`;

/**
 * The certificate for the CSR from the ACME server of the certificate: lego with --csr, or certbot certonly --csr
 * into a fresh directory (certbot picks other names when the files exist)
 */
const requestFor = async (cert) => {
	const dir = csrDir(cert.id);
	const meta = cert.meta || {};
	const server = await acmeServers.of(meta);
	if (clientOf(cert) === "lego") {
		return lego.issue(cert, server, { csr: `${dir}/csr.pem`, key: `${dir}/privkey.pem` });
	}
	const out = await mkdtemp("/tmp/npmos-csr-out-");
	let credentials = null;
	try {
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
		const result = await certbotAcme(
			[
				"--config",
				"/etc/certbot.ini",
				"certonly",
				...certbotServerArgs(server),
				"--csr",
				`${dir}/csr.pem`,
				"--cert-path",
				`${out}/cert.pem`,
				"--fullchain-path",
				`${out}/fullchain.pem`,
				"--chain-path",
				`${out}/chain.pem`,
				...challenge,
			],
			{ server },
		);
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
		// the ACME server of Settings -> ACME it is sent to, and its client
		const { server } = await withServer({ acme_server_id: input.acme_server_id });
		const meta = {
			npmos_csr: true,
			npmos_csr_key_type: key_type,
			npmos_csr_subject: subject,
			acme_server_id: server.id,
			acme_client: server.client,
		};
		if (input.dns_challenge) {
			// certbot: one of its plugins; lego: a code of `lego dnshelp`
			const known =
				server.client === "lego"
					? (await lego.dnsProviders()).includes(input.dns_provider)
					: !!dnsPlugins[input.dns_provider];
			if (!known) throw new errs.ValidationError("Choose the DNS provider");
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
			throw err instanceof errs.ValidationError ? err : acmeError(err, server);
		}
	},

	/** "Renew" of a certificate of a CSR: the same CSR again */
	renew: async (cert) => {
		await requestFor(cert);
		return expiresOf(cert.id);
	},

	/** revoke by the certificate file (no certbot lineage) and remove the files */
	revoke: async (cert, throwErrors) => {
		const server = await acmeServers.of(cert.meta).catch(() => null);
		if (server && clientOf(cert) === "lego") {
			await lego.revoke(cert, server, REASON.cessationOfOperation, throwErrors);
			await rm(csrDir(cert.id), { recursive: true, force: true });
			return;
		}
		try {
			if (!server) throw new Error("its ACME server was removed");
			const result = await utils.execFile("certbot", [
				"--config",
				"/etc/certbot.ini",
				"revoke",
				...certbotServerArgs({ ...server, profile: "" }),
				"--cert-path",
				`${liveDir(cert.id)}/cert.pem`,
				"--key-path",
				`${csrDir(cert.id)}/privkey.pem`,
				// a reason every CA accepts (some refuse "unspecified")
				"--reason",
				"cessationofoperation",
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
