// The system openssl (in the image of NPMOS) does the X.509 work of the PKI: certificates, CRLs,
// PKCS#12. Keys reach it through a private temporary directory in memory (/dev/shm when there is
// one) that is removed right after the call; they are never written to the data volume unencrypted.
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const OPENSSL = process.env.NPMOS_OPENSSL || "openssl";

const tmpRoot = async () => {
	try {
		const dir = await mkdtemp("/dev/shm/npmos-pki-");
		return dir;
	} catch {
		return mkdtemp(path.join(os.tmpdir(), "npmos-pki-"));
	}
};

/**
 * Runs a function with a private temporary directory; files are written with mode 600.
 * @template T
 * @param {(tmp: {path: (name: string) => string, write: (name: string, data: string|Buffer) => Promise<string>}) => Promise<T>} fn
 * @returns {Promise<T>}
 */
export const withTmp = async (fn) => {
	const dir = await tmpRoot();
	try {
		return await fn({
			path: (name) => path.join(dir, name),
			write: async (name, data) => {
				const file = path.join(dir, name);
				await writeFile(file, data, { mode: 0o600 });
				return file;
			},
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
};

/**
 * Runs openssl; resolves with stdout (Buffer), rejects with its stderr.
 * @param {string[]} args
 * @param {{env?: Record<string, string>}} [options]
 * @returns {Promise<Buffer>}
 */
export const openssl = (args, { env = {} } = {}) =>
	new Promise((resolve, reject) => {
		execFile(
			OPENSSL,
			args,
			{ encoding: "buffer", maxBuffer: 16 * 1024 * 1024, timeout: 60000, env: { ...process.env, ...env } },
			(err, stdout, stderr) => {
				if (err) {
					const message = stderr?.toString().trim().split("\n").slice(0, 3).join("; ") || err.message;
					reject(new Error(`openssl ${args[0]}: ${message}`));
					return;
				}
				resolve(stdout);
			},
		);
	});
