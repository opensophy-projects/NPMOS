// NPMOS: an uploaded certificate and its key must belong together. Upstream checked each file on its own, so a key of
// another certificate was accepted and nginx then failed on every host using it ("key values mismatch").
import { createPrivateKey, X509Certificate } from "node:crypto";
import errs from "../lib/error.js";

/** throws when the key is not the one of the certificate (the first certificate of a chain) */
export const assertKeyMatches = (certificatePem, keyPem) => {
	const first = String(certificatePem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
	if (!first) return;
	let matches = false;
	try {
		matches = new X509Certificate(first[0]).checkPrivateKey(createPrivateKey(keyPem));
	} catch {
		matches = false;
	}
	if (!matches) {
		throw new errs.ValidationError(
			"The key does not match the certificate: upload the key the certificate was issued for",
		);
	}
};
