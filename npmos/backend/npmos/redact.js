// Masks secrets in text that leaves NPMOS for someone else to read (the diagnostic archive): logs of the
// services and `nginx -T` may hold passwords of connection strings, tokens, keys.
import { readFileSync } from "node:fs";

export const MASK = "***";

const PATTERNS = [
	// postgres://user:password@host, https://user:password@host
	[/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:)[^\s@/"']+@/gi, `$1${MASK}@`],
	// Authorization: Bearer|Basic|Token <value>
	[/\b(authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token)\s+)[^\s"',;]+/gi, `$1${MASK}`],
	[/\b(bearer\s+)[a-z0-9._~+/-]{8,}=*/gi, `$1${MASK}`],
	// password=…, "token": "…", api_key: …, secret …
	[
		/\b((?:[a-z0-9]+[_-])*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[=:]\s*["']?)(?!\*\*\*)[^\s"'&,;}]+/gi,
		`$1${MASK}`,
	],
	// JSON Web Tokens
	[/\beyJ[a-z0-9_-]{5,}\.[a-z0-9_-]{5,}\.[a-z0-9_-]+/gi, MASK],
	// private keys in PEM
	[
		/-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----/g,
		`-----BEGIN $1PRIVATE KEY-----${MASK}-----END $1PRIVATE KEY-----`,
	],
];

const SECRET_NAME = /(PASS|SECRET|TOKEN|KEY)/i;
const MIN_LITERAL = 6;

/**
 * Values of the secrets this process knows (env and the *_FILE files it was given), masked wherever they
 * appear, whatever the format around them.
 * @param {NodeJS.ProcessEnv} env
 * @returns {string[]}
 */
export const knownSecrets = (env = process.env) => {
	const values = new Set();
	for (const [name, value] of Object.entries(env)) {
		if (!value || !SECRET_NAME.test(name)) continue;
		if (name.endsWith("_FILE")) {
			try {
				values.add(readFileSync(value, "utf8").trim());
			} catch {
				// not readable here: the patterns still apply
			}
		} else {
			values.add(value.trim());
		}
	}
	return [...values].filter((value) => value.length >= MIN_LITERAL && !value.includes("\n"));
};

/**
 * @param {string} text
 * @param {string[]} [literals]  exact values to mask (knownSecrets())
 * @returns {string}
 */
export const redact = (text, literals = []) => {
	let out = String(text);
	for (const literal of literals) {
		out = out.split(literal).join(MASK);
	}
	for (const [pattern, replacement] of PATTERNS) {
		out = out.replace(pattern, replacement);
	}
	return out;
};
