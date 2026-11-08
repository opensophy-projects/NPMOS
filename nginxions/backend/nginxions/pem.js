// Certificates of a PEM text, found by their markers in one pass: a regular expression over an uploaded file
// (-----BEGIN ...[\s\S]+?-----END...) takes quadratic time on a text of many BEGIN markers without an END.
const BEGIN = "-----BEGIN CERTIFICATE-----";
const END = "-----END CERTIFICATE-----";

/** every certificate block of a PEM text, markers included */
export const pemCertificates = (text) => {
	const pem = String(text ?? "");
	const out = [];
	let from = 0;
	for (;;) {
		const start = pem.indexOf(BEGIN, from);
		if (start < 0) break;
		const end = pem.indexOf(END, start + BEGIN.length);
		if (end < 0) break;
		out.push(pem.slice(start, end + END.length));
		from = end + END.length;
	}
	return out;
};

/** the first certificate block of a PEM text, or null */
export const firstPemCertificate = (text) => pemCertificates(text)[0] ?? null;
