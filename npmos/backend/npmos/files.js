// A file read together with its stat through one open handle: a stat, then a read by the name, could read another
// file that replaced the first in between (time of check, time of use).
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { open } from "node:fs/promises";

/**
 * @param {string} file
 * @param {{encoding?: BufferEncoding, accept?: (stat: import("node:fs").Stats) => boolean}} [options]
 *   accept: decides from the stat whether the content is read (a size limit, an unchanged mtime); when it says no,
 *   data is null
 * @returns {Promise<{stat: import("node:fs").Stats, data: string|Buffer|null}>}
 */
export const readWithStat = async (file, { encoding, accept } = {}) => {
	const handle = await open(file, "r");
	try {
		const stat = await handle.stat();
		const data = accept && !accept(stat) ? null : await handle.readFile(encoding ? { encoding } : {});
		return { stat, data };
	} finally {
		await handle.close();
	}
};

/** the same, synchronous */
export const readWithStatSync = (file, { encoding, accept } = {}) => {
	const fd = openSync(file, "r");
	try {
		const stat = fstatSync(fd);
		const data = accept && !accept(stat) ? null : readFileSync(fd, encoding ? { encoding } : {});
		return { stat, data };
	} finally {
		closeSync(fd);
	}
};
