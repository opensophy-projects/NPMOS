// The ACME certificates of NPMplus ("letsencrypt" rows) with a server of Settings -> ACME: meta.acme_server_id is
// the server, meta.acme_client the client it was issued with (kept, so that a later change of the server does not
// strand its certificates). certbot certificates keep their certbot lineage (internal/certificate.js); lego
// certificates are requested, renewed and revoked here.

import { X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import dayjs from "dayjs";
import errs from "../../lib/error.js";
import { certbot as logger } from "../../logger.js";
import certificateModel from "../../models/certificate.js";
import { acmeRenewEnabled } from "../acme.js";
import { termOf } from "../cert-terms.js";
import { firstPemCertificate } from "../pem.js";
import lego, { REASON } from "./lego.js";
import acmeServers from "./servers.js";

/** the client of an ACME certificate */
export const clientOf = (cert) => (cert?.meta?.acme_client === "lego" ? "lego" : "certbot");

/**
 * The meta of a new ACME certificate with its server and client (the default server when none is chosen).
 * @param {object} meta  from the API (certificate form, host form)
 */
export const withServer = async (meta = {}) => {
	const server = await acmeServers.of(meta);
	const out = { ...meta, acme_server_id: server.id, acme_client: server.client };
	if (server.client === "lego") delete out.reuse_key;
	return { meta: out, server };
};

const expiresOf = async (id) => {
	const pem = await readFile(`/data/tls/certbot/live/npm-${id}/fullchain.pem`, "utf8");
	const first = firstPemCertificate(pem);
	if (!first) throw new errs.ValidationError("No certificate in the files of lego");
	return dayjs(new Date(new X509Certificate(first).validTo)).format("YYYY-MM-DD HH:mm:ss");
};

const legoCerts = {
	/** issues a new lego certificate (the row exists already) */
	request: async (cert) => {
		const server = await acmeServers.of(cert.meta);
		return lego.issue(cert, server);
	},

	/** "Renew": a new certificate for the same names (the old one is left to expire, not revoked) */
	renew: async (cert) => {
		const server = await acmeServers.of(cert.meta);
		await lego.issue(cert, server);
		return expiresOf(cert.id);
	},

	/** removal of the certificate: revoked with cessationOfOperation, a reason every CA takes */
	revoke: async (cert, throwErrors) => {
		const server = await acmeServers.of(cert.meta).catch(() => null);
		if (!server) {
			logger.warn(`Cert #${cert.id}: its ACME server was removed, the certificate is not revoked`);
			return;
		}
		return lego.revoke(cert, server, REASON.cessationOfOperation, throwErrors);
	},

	/** the timer of NPMplus: lego certificates past their renewal point get a new certificate */
	renewDue: async () => {
		if (!acmeRenewEnabled()) return;
		const rows = await certificateModel.query().where("is_deleted", 0).andWhere("provider", "letsencrypt");
		for (const cert of rows) {
			if (clientOf(cert) !== "lego" || cert.meta?.npmos_csr) continue;
			const term = await termOf(cert);
			if (!term.renew_from || Date.now() < new Date(term.renew_from).getTime()) continue;
			try {
				const expires = await legoCerts.renew(cert);
				await certificateModel.query().patchAndFetchById(cert.id, { expires_on: expires });
				logger.info(`Renewed the lego certificate of Cert #${cert.id}`);
			} catch (err) {
				logger.warn(`Renewal of the lego certificate of Cert #${cert.id} failed: ${err.message}`);
			}
		}
	},
};

export default legoCerts;
