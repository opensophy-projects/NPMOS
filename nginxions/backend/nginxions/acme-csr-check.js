// Checks of your own CSR for ACME (nginxions/acme-csr.js): no database, testable on its own.
import { execFile } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import errs from "../lib/error.js";

const MAX_PEM = 64 * 1024;
const run = promisify(execFile);

export const pemBlock = (text, label) => {
	const m = String(text ?? "").match(new RegExp(`-----BEGIN ${label}-----[\\s\\S]+?-----END ${label}-----`));
	return m ? `${m[0]}\n` : null;
};

/** what openssl says about a CSR: its names, its public key, whether its signature holds */
const opensslCsr = async (csr) => {
	const dir = await mkdtemp(path.join(tmpdir(), "nginxions-csr-"));
	try {
		const file = path.join(dir, "req.pem");
		await writeFile(file, csr);
		const out = await run("openssl", ["req", "-in", file, "-noout", "-text", "-verify"]);
		const pub = await run("openssl", ["req", "-in", file, "-noout", "-pubkey"]);
		return { text: `${out.stdout}${out.stderr}`, pubkey: pub.stdout };
	} catch (err) {
		throw new errs.ValidationError(`The CSR is not valid: ${String(err.message || err).split("\n")[0]}`);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

/** names of the CSR: DNS and IP of subjectAltName (ACME and certbot take the names from there only) */
const namesOf = (text) => {
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
