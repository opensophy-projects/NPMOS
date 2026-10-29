// Lists of IPs and CIDRs (blocklists, exports for other nodes). Pure functions.
import { normalizeIpOrCidr } from "./config.js";

export const MAX_ENTRIES = 200000;

const inCidr = (ip, cidr) => {
	const [base, bitsText] = cidr.split("/");
	const v4 = (a) => a.split(".").reduce((n, x) => n * 256n + BigInt(Number(x)), 0n);
	const v6 = (a) => {
		const [head, tail = ""] = a.split("::");
		const h = head ? head.split(":") : [];
		const t = tail ? tail.split(":") : [];
		const parts = a.includes("::") ? [...h, ...Array(8 - h.length - t.length).fill("0"), ...t] : h;
		return parts.reduce((n, x) => n * 65536n + BigInt(Number.parseInt(x || "0", 16)), 0n);
	};
	const isV4 = !base.includes(":");
	if (isV4 !== !ip.includes(":") || ip.includes(".") === ip.includes(":")) return false;
	const width = isV4 ? 32n : 128n;
	const shift = width - BigInt(bitsText ?? (isV4 ? 32 : 128));
	const toInt = isV4 ? v4 : v6;
	return toInt(ip) >> shift === toInt(base) >> shift;
};

/** whether an IP or CIDR is covered by the allowlist (exact IPs and CIDRs of the allowlist) */
export const allowed = (entry, allowlist) => {
	const ip = entry.split("/")[0];
	return allowlist.some((a) => (a.includes("/") ? inCidr(ip, a) : a === entry));
};

/**
 * One IP or CIDR per line; comments (#, ;) and empty lines are skipped, also "ip,comment" and
 * "ip comment" (common list formats).
 * @returns {{entries: string[], invalid: number}}
 */
export const parseList = (text, allowlist = []) => {
	const entries = new Set();
	let invalid = 0;
	for (const line of String(text).split(/\r?\n/)) {
		const value = line
			.replace(/[#;].*$/, "")
			.trim()
			.split(/[\s,]/)[0];
		if (!value) continue;
		const n = normalizeIpOrCidr(value);
		if (!n) {
			invalid++;
			continue;
		}
		if (allowed(n, allowlist)) continue;
		entries.add(n);
		if (entries.size > MAX_ENTRIES) throw new Error(`More than ${MAX_ENTRIES} entries`);
	}
	return { entries: [...entries], invalid };
};

/** decisions of this node (not imported from lists) as a list for other nodes */
export const exportText = (decisions) => {
	const values = new Set();
	for (const d of decisions) {
		if (d.origin === "lists" || String(d.scenario || "").startsWith("npmos/blocklist/")) continue;
		if (d.type !== "ban" || !["Ip", "Range"].includes(d.scope)) continue;
		values.add(d.value);
	}
	return `# NPMOS decisions export, ${new Date().toISOString()}\n${[...values].join("\n")}\n`;
};
