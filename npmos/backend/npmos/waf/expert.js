// WAF -> Policy (expert): edit, check (diff against the file in force), save and roll back the
// YAML fragments merged over the generated policy (see custom.js). Every save is a new version.
import internalAuditLog from "../../internal/audit-log.js";
import db from "../../db.js";
import errs from "../../lib/error.js";
import { parseCustom } from "./custom.js";
import { buildPolicy, getPolicyState, readPolicyFile, regenerateNow, render } from "./policy.js";

const VERSIONS_SHOWN = 50;
const DIFF_MAX_LINES = 2000;

/**
 * Line diff: common head and tail, then the longest common subsequence of the changed middle.
 * @returns {Array<{op: " "|"+"|"-", line: string}>}
 */
const diffLines = (before, after) => {
	const a = before.split("\n");
	const b = after.split("\n");
	let head = 0;
	while (head < a.length && head < b.length && a[head] === b[head]) head++;
	let tail = 0;
	while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail]) {
		tail++;
	}
	const ma = a.slice(head, a.length - tail);
	const mb = b.slice(head, b.length - tail);
	const result = a.slice(0, head).map((line) => ({ op: " ", line }));
	if (ma.length > DIFF_MAX_LINES || mb.length > DIFF_MAX_LINES) {
		result.push(...ma.map((line) => ({ op: "-", line })), ...mb.map((line) => ({ op: "+", line })));
	} else {
		const lcs = Array.from({ length: ma.length + 1 }, () => new Uint16Array(mb.length + 1));
		for (let i = ma.length - 1; i >= 0; i--) {
			for (let j = mb.length - 1; j >= 0; j--) {
				lcs[i][j] = ma[i] === mb[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
			}
		}
		let i = 0;
		let j = 0;
		while (i < ma.length && j < mb.length) {
			if (ma[i] === mb[j]) {
				result.push({ op: " ", line: ma[i++] });
				j++;
			} else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
				result.push({ op: "-", line: ma[i++] });
			} else {
				result.push({ op: "+", line: mb[j++] });
			}
		}
		while (i < ma.length) result.push({ op: "-", line: ma[i++] });
		while (j < mb.length) result.push({ op: "+", line: mb[j++] });
	}
	result.push(...a.slice(a.length - tail).map((line) => ({ op: " ", line })));
	return result;
};

const versions = async () => {
	const rows = await db()("npmos_waf_custom_policy as p")
		.leftJoin("user as u", "u.id", "p.user_id")
		.select("p.id", "p.comment", "p.created_on", "u.name as user_name", db().raw("length(p.content) as size"))
		.orderBy("p.id", "desc")
		.limit(VERSIONS_SHOWN);
	return rows.map((r) => ({
		id: r.id,
		comment: r.comment,
		created_on: r.created_on,
		user: r.user_name || null,
		size: Number(r.size),
	}));
};

const save = async (access, content, comment) => {
	parseCustom(content);
	const [row] = await db()("npmos_waf_custom_policy")
		.insert({
			content,
			comment: (comment || "").slice(0, 255),
			user_id: access.token.getUserId(1),
			created_on: new Date(),
		})
		.returning("id");
	const id = typeof row === "object" ? row.id : row;
	const result = await regenerateNow({ force: true });
	return { id, ...result };
};

const internalWafExpert = {
	/**
	 * @param {Access} access
	 */
	get: async (access) => {
		await access.can("npmos_services:list");
		const current = await db()("npmos_waf_custom_policy").orderBy("id", "desc").first();
		return {
			id: current?.id ?? null,
			content: current?.content ?? "",
			versions: await versions(),
			policy: getPolicyState(),
		};
	},

	/**
	 * Validates a fragment and shows what local_policy.yaml would become (nothing is saved).
	 * @param {Access} access
	 * @param {string} content
	 */
	check: async (access, content) => {
		await access.can("npmos_services:list");
		let custom;
		try {
			custom = parseCustom(content);
		} catch (err) {
			if (err instanceof errs.ValidationError) {
				return { valid: false, error: err.message };
			}
			throw err;
		}
		const { policy } = await buildPolicy({ custom });
		const next = render(policy, Object.keys(custom).length > 0);
		const current = (await readPolicyFile()) ?? "";
		const diff = diffLines(current, next);
		return {
			valid: true,
			changed: diff.some((d) => d.op !== " "),
			diff,
		};
	},

	/**
	 * Saves a new version and applies the policy.
	 * @param {Access} access
	 * @param {{content: string, comment?: string}} data
	 */
	save: async (access, data) => {
		await access.can("npmos_services:manage");
		const result = await save(access, data.content, data.comment);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "waf",
			object_id: result.id,
			meta: { name: "local_policy.yaml (expert)", comment: data.comment || "" },
		});
		return { ...(await internalWafExpert.get(access)), ...result };
	},

	/**
	 * Makes an older version the current one (as a new version, the history is kept).
	 * @param {Access} access
	 * @param {number} id
	 */
	rollback: async (access, id) => {
		await access.can("npmos_services:manage");
		const old = await db()("npmos_waf_custom_policy").where({ id }).first();
		if (!old) {
			throw new errs.ItemNotFoundError(id);
		}
		const result = await save(access, old.content, `rollback to version ${id}`);
		await internalAuditLog.add(access, {
			action: "updated",
			object_type: "waf",
			object_id: result.id,
			meta: { name: "local_policy.yaml (expert)", comment: `rollback to version ${id}` },
		});
		return { ...(await internalWafExpert.get(access)), ...result };
	},
};

export default internalWafExpert;
