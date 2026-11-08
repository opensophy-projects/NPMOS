// Secrets that NginxionS keeps in its database (SMTP passwords, webhook keys, bot tokens) are encrypted
// with AES-256-GCM. The key is generated on first use in the data volume, apart from the database:
// a database dump alone does not reveal them.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const KEY_FILE = process.env.NGINXIONS_SECRET_KEY_FILE || "/data/nginxions/secret.key";
const PREFIX = "enc:v1:";

let key = null;

const getKey = () => {
	if (key) return key;
	try {
		key = Buffer.from(readFileSync(KEY_FILE, "utf8").trim(), "base64");
	} catch {
		key = randomBytes(32);
		mkdirSync(path.dirname(KEY_FILE), { recursive: true });
		writeFileSync(KEY_FILE, key.toString("base64"), { mode: 0o600, flag: "wx" });
	}
	if (key.length !== 32) throw new Error(`Invalid key in ${KEY_FILE}`);
	return key;
};

const TAG_BYTES = 16;

/** @param {string} text */
export const encrypt = (text) => {
	if (!text) return "";
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", getKey(), iv, { authTagLength: TAG_BYTES });
	const data = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
	return PREFIX + Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64");
};

/** @param {string} value  encrypted (or empty) */
export const decrypt = (value) => {
	if (!value) return "";
	if (!value.startsWith(PREFIX)) return value;
	const raw = Buffer.from(value.slice(PREFIX.length), "base64");
	// the tag length is fixed: a shortened tag would make a forged value easier to accept
	const decipher = createDecipheriv("aes-256-gcm", getKey(), raw.subarray(0, 12), { authTagLength: TAG_BYTES });
	decipher.setAuthTag(raw.subarray(12, 12 + TAG_BYTES));
	return Buffer.concat([decipher.update(raw.subarray(12 + TAG_BYTES)), decipher.final()]).toString("utf8");
};
