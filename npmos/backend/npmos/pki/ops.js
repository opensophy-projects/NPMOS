// X.509 operations of the PKI with openssl: self-signed roots, signing of requests, CRLs, PKCS#12.
// No database: the callers pass PEM texts (keys decrypted in memory) and store the results.
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import { openssl, withTmp } from "./openssl.js";
import { crlConfig, extConfig, indexTxt, ocspIndex, PkiError, parseCert, subjectArg } from "./x509.js";

const isRsa = (keyPem) => createPrivateKey(keyPem).asymmetricKeyType === "rsa";

/** RFC 2253 names of a certificate, as nginx prints $ssl_client_s_dn / $ssl_client_i_dn */
export const names = async (certPem) =>
	withTmp(async (tmp) => {
		const file = await tmp.write("cert.pem", certPem);
		const out = (
			await openssl(["x509", "-in", file, "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"])
		).toString();
		const field = (name) => out.match(new RegExp(`^${name}=\\s*(.*)$`, "m"))?.[1]?.trim() ?? "";
		return { subject: field("subject"), issuer: field("issuer") };
	});

/** whether a private key belongs to a certificate */
export const keyMatches = (keyPem, certPem) => {
	try {
		const fromKey = createPublicKey(createPrivateKey(keyPem)).export({ type: "spki", format: "der" });
		const fromCert = createPublicKey(certPem).export({ type: "spki", format: "der" });
		return fromKey.equals(fromCert);
	} catch {
		return false;
	}
};

/** a private key in PEM (PKCS#8), also from an encrypted PEM with its password */
export const readKey = (keyPem, passphrase) => {
	try {
		return createPrivateKey({ key: keyPem, passphrase: passphrase || undefined }).export({
			type: "pkcs8",
			format: "pem",
		});
	} catch (err) {
		throw new PkiError(`Cannot read the private key: ${err.message}`);
	}
};

/**
 * Self-signed root CA.
 * @param {{keyPem: string, subject: object, days: number, serial: string}} p
 */
export const selfSign = async ({ keyPem, subject, days, serial }) =>
	withTmp(async (tmp) => {
		const key = await tmp.write("key.pem", keyPem);
		const cfg = await tmp.write("ext.cnf", extConfig("root"));
		return (
			await openssl([
				"req",
				"-x509",
				"-new",
				"-utf8",
				"-key",
				key,
				"-config",
				cfg,
				"-extensions",
				"ext",
				"-subj",
				subjectArg(subject),
				"-days",
				String(days),
				"-sha256",
				"-set_serial",
				`0x${serial}`,
			])
		).toString();
	});

/** certificate request of a key (the subject is set again when it is signed) */
export const makeCsr = async ({ keyPem, subject }) =>
	withTmp(async (tmp) => {
		const key = await tmp.write("key.pem", keyPem);
		const cfg = await tmp.write("req.cnf", extConfig("client"));
		return (
			await openssl([
				"req",
				"-new",
				"-utf8",
				"-key",
				key,
				"-config",
				cfg,
				"-subj",
				subjectArg(subject),
				"-sha256",
			])
		).toString();
	});

/**
 * A request given by a client: checked signature, its subject and key type.
 * @param {string} csrPem
 */
export const readCsr = async (csrPem) =>
	withTmp(async (tmp) => {
		if (!/-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(csrPem)) {
			throw new PkiError("Not a certificate request (PEM)");
		}
		const file = await tmp.write("req.csr", csrPem);
		let pub;
		try {
			await openssl(["req", "-in", file, "-noout", "-verify"]);
			pub = (await openssl(["req", "-in", file, "-noout", "-pubkey"])).toString();
		} catch (err) {
			throw new PkiError(`Invalid certificate request: ${err.message}`);
		}
		const key = createPublicKey(pub);
		const details = key.asymmetricKeyDetails || {};
		if (key.asymmetricKeyType === "rsa" && details.modulusLength < 2048) {
			throw new PkiError("RSA keys shorter than 2048 bits are not accepted");
		}
		if (!["rsa", "ec"].includes(key.asymmetricKeyType)) {
			throw new PkiError(`Key type ${key.asymmetricKeyType} is not supported`);
		}
		let keyType = key.asymmetricKeyType;
		if (keyType === "ec")
			keyType = `ec-${{ prime256v1: "p256", secp384r1: "p384" }[details.namedCurve] || details.namedCurve}`;
		if (keyType === "rsa") keyType = `rsa-${details.modulusLength}`;
		return { keyType, rsa: key.asymmetricKeyType === "rsa" };
	});

/**
 * Signs a request with a CA. The subject is the one of the request (x509 -subj of openssl 3.0
 * mangles UTF-8), extensions are only ours (none is copied from the request).
 * @param {{csrPem: string, caCertPem: string, caKeyPem: string, profile: "intermediate"|"client"|"server",
 *   sans?: object, days: number, serial: string, crlUrl?: string, rsa?: boolean}} p
 */
export const sign = async ({ csrPem, caCertPem, caKeyPem, profile, sans, days, serial, crlUrl, ocspUrl, rsa }) =>
	withTmp(async (tmp) => {
		const csr = await tmp.write("req.csr", csrPem);
		const caCert = await tmp.write("ca.pem", caCertPem);
		const caKey = await tmp.write("ca.key", caKeyPem);
		const cfg = await tmp.write("ext.cnf", extConfig(profile, { sans, crlUrl, ocspUrl, rsa }));
		const pem = (
			await openssl([
				"x509",
				"-req",
				"-in",
				csr,
				"-CA",
				caCert,
				"-CAkey",
				caKey,
				"-extfile",
				cfg,
				"-extensions",
				"ext",
				"-set_serial",
				`0x${serial}`,
				"-days",
				String(days),
				"-sha256",
			])
		).toString();
		return pem;
	});

/**
 * CRL of a CA.
 * @param {{caCertPem: string, caKeyPem: string, revoked: Array, crlNumber: number, days: number}} p
 * @returns {Promise<string>} PEM
 */
export const makeCrl = async ({ caCertPem, caKeyPem, revoked, crlNumber, days }) =>
	withTmp(async (tmp) => {
		const dir = tmp.path("");
		await tmp.write("index.txt", indexTxt(revoked));
		await tmp.write("crlnumber", `${crlNumber.toString(16).toUpperCase().padStart(2, "0")}\n`);
		const cfg = await tmp.write("ca.cnf", crlConfig(dir.replace(/\/$/, "")));
		const caCert = await tmp.write("ca.pem", caCertPem);
		const caKey = await tmp.write("ca.key", caKeyPem);
		return (
			await openssl([
				"ca",
				"-gencrl",
				"-config",
				cfg,
				"-cert",
				caCert,
				"-keyfile",
				caKey,
				"-crldays",
				String(days),
			])
		).toString();
	});

/**
 * OCSP response (DER) to a request (DER), signed by the CA itself; valid for `hours`.
 * @param {{caCertPem: string, caKeyPem: string, certs: Array, requestDer: Buffer, hours?: number}} p
 */
export const ocspRespond = async ({ caCertPem, caKeyPem, certs, requestDer, hours = 1 }) =>
	withTmp(async (tmp) => {
		const index = await tmp.write("index.txt", ocspIndex(certs));
		// subjects in the index are placeholders: they repeat
		await tmp.write("index.txt.attr", "unique_subject = no\n");
		const caCert = await tmp.write("ca.pem", caCertPem);
		const caKey = await tmp.write("ca.key", caKeyPem);
		const req = await tmp.write("req.der", requestDer);
		const out = tmp.path("resp.der");
		await openssl([
			"ocsp",
			"-index",
			index,
			"-CA",
			caCert,
			"-rsigner",
			caCert,
			"-rkey",
			caKey,
			"-reqin",
			req,
			"-respout",
			out,
			"-nmin",
			String(hours * 60),
		]);
		return readFile(out);
	});

/** CRL in DER (for publication) */
export const crlToDer = async (crlPem) =>
	withTmp(async (tmp) => {
		const file = await tmp.write("crl.pem", crlPem);
		return openssl(["crl", "-in", file, "-outform", "DER"]);
	});

/**
 * Checks an uploaded CRL against the certificates of a CA: {nextUpdate}
 * @param {string} crlPem
 * @param {string} caPem  certificates of the CA
 */
export const checkCrl = async (crlPem, caPem) =>
	withTmp(async (tmp) => {
		const crl = await tmp.write("crl.pem", crlPem);
		const ca = await tmp.write("ca.pem", caPem);
		let out;
		try {
			out = (await openssl(["crl", "-in", crl, "-CAfile", ca, "-noout", "-nextupdate"])).toString();
		} catch (err) {
			throw new PkiError(`Invalid CRL: ${err.message}`);
		}
		const next = out.match(/nextUpdate=(.*)/)?.[1]?.trim();
		return { nextUpdate: next && next !== "NONE" ? new Date(next) : null };
	});

/**
 * PKCS#12 with the certificate, its key and the chain.
 * compatible: 3DES and SHA-1 MAC, which every system imports (older macOS, iOS, Android and
 * Windows do not read AES-256 containers); otherwise the openssl 3 defaults (AES-256, SHA-256).
 * @param {{certPem: string, keyPem: string, chainPem: string, password: string, name: string, compatible?: boolean}} p
 * @returns {Promise<Buffer>}
 */
export const pkcs12 = async ({ certPem, keyPem, chainPem, password, name, compatible = true }) =>
	withTmp(async (tmp) => {
		const cert = await tmp.write("cert.pem", certPem);
		const key = await tmp.write("key.pem", keyPem);
		const chain = await tmp.write("chain.pem", chainPem);
		const args = ["pkcs12", "-export", "-in", cert, "-inkey", key, "-certfile", chain, "-passout", "env:NPMOS_P12"];
		args.push("-name", name.replace(/[^\p{L}\p{N} _.@:'()&-]/gu, "_").slice(0, 64));
		if (compatible) {
			args.push("-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1");
		}
		return openssl(args, { env: { NPMOS_P12: password } });
	});

/** key in PEM encrypted with a password (AES-256, PKCS#8) */
export const encryptKey = (keyPem, password) =>
	createPrivateKey(keyPem).export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: password });

export { isRsa, parseCert };
