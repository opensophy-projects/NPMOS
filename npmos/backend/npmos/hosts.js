// Hosts table (docs/ROADMAP.md, phase 2): who changed a host and when (audit log), whether the
// upstreams of proxy hosts and streams answer. Only hosts the user can see are reported
// (upstream <type>:list permissions, including ownership).
import net from "node:net";
import db from "../db.js";
import errs from "../lib/error.js";

/** audit log object type → table and permission of upstream */
export const HOST_OBJECTS = {
	"proxy-host": { table: "proxy_host", permission: "proxy_hosts" },
	"redirection-host": { table: "redirection_host", permission: "redirection_hosts" },
	"dead-host": { table: "dead_host", permission: "dead_hosts" },
	stream: { table: "stream", permission: "streams" },
};

const HISTORY_LIMIT = 50;
const PROBE_TIMEOUT_MS = 2000;
const PROBE_CONCURRENCY = 16;
const PROBE_CACHE_MS = 30000;
const DEFAULT_PORT = { http: 80, https: 443 };

const parseJson = (value) => (typeof value === "string" ? JSON.parse(value) : value) || {};

/**
 * Ids of the hosts of one type the user can see; null when the type is not allowed at all.
 * @param {Access} access
 * @param {string} type
 * @param {string[]} [columns]
 */
const visibleHosts = async (access, type, columns = ["id"]) => {
	const { table, permission } = HOST_OBJECTS[type];
	let accessData;
	try {
		accessData = await access.can(`${permission}:list`);
	} catch (err) {
		if (err instanceof errs.PermissionError) return null;
		throw err;
	}
	const query = db()(table).select(columns).where("is_deleted", 0);
	if (accessData.permission_visibility !== "all") {
		query.where("owner_user_id", access.token.getUserId(1));
	}
	return query;
};

const userOf = (row) =>
	row.user_id ? { id: row.user_id, name: row.user_name || row.user_nickname || null, avatar: row.user_avatar } : null;

/** keys that change with every save or are state, not settings */
const VOLATILE = new Set(["id", "created_on", "modified_on", "is_deleted", "owner", "certificate", "access_list"]);
const VOLATILE_META = new Set(["nginx_online", "nginx_err"]);

/**
 * Settings that differ between two snapshots of a host (upstream logs the whole row on
 * create, update, enable and disable), as "field" or "meta.field".
 */
export const changedFields = (current, previous, partial = false) => {
	const a = parseJson(current);
	const b = parseJson(previous);
	// a partial snapshot (the create request) has no word on the fields it leaves out
	const known = (object, key) => !partial || Object.hasOwn(object, key);
	// the create entry is the request: booleans and numeric strings where the row has numbers
	const norm = (value) =>
		JSON.stringify(value ?? null, (_, v) =>
			typeof v === "boolean" ? Number(v) : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v,
		);
	const same = (x, y) => norm(x) === norm(y);
	const fields = [];
	for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
		if (VOLATILE.has(key)) continue;
		if (key === "meta") {
			const am = parseJson(a.meta);
			const bm = parseJson(b.meta);
			for (const metaKey of new Set([...Object.keys(am), ...Object.keys(bm)])) {
				if (!VOLATILE_META.has(metaKey) && known(bm, metaKey) && !same(am[metaKey], bm[metaKey])) {
					fields.push(`meta.${metaKey}`);
				}
			}
		} else if (known(b, key) && !same(a[key], b[key])) {
			fields.push(key);
		}
	}
	return fields;
};

const pickWaf = ({ enabled, mode }) => ({ enabled: !!enabled, mode: mode || null });

const entry = (row) => ({
	id: row.id,
	// WAF settings of a proxy host are logged as their own object
	action: row.object_type === "waf" ? "updated-waf" : row.action,
	created_on: row.created_on,
	user: userOf(row),
	fields: [],
	// the WAF entry keeps the settings that were saved
	...(row.object_type === "waf" ? { waf: pickWaf(parseJson(row.meta)) } : {}),
});

const auditQuery = () =>
	db()("audit_log")
		.leftJoin("user", "user.id", "audit_log.user_id")
		.select(
			"audit_log.id",
			"audit_log.object_type",
			"audit_log.object_id",
			"audit_log.action",
			"audit_log.created_on",
			"audit_log.user_id",
			"audit_log.meta",
			"user.name as user_name",
			"user.nickname as user_nickname",
			"user.avatar as user_avatar",
		);

/** WAF changes of proxy hosts count as changes of the host */
const auditTypes = (type) => (type === "proxy-host" ? ["proxy-host", "waf"] : [type]);

/** @type {Map<string, {at: number, result: Promise<object>}>} */
const probeCache = new Map();

/**
 * Opens a TCP connection and closes it at once.
 * @returns {Promise<{ok: boolean, ms?: number, error?: string}>}
 */
const probe = (host, port) => {
	const key = `${host}:${port}`;
	const cached = probeCache.get(key);
	if (cached && Date.now() - cached.at < PROBE_CACHE_MS) return cached.result;
	const started = Date.now();
	const result = new Promise((resolve) => {
		const socket = net.connect({ host, port, timeout: PROBE_TIMEOUT_MS });
		const done = (value) => {
			socket.destroy();
			resolve(value);
		};
		socket.once("connect", () => done({ ok: true, ms: Date.now() - started }));
		socket.once("timeout", () => done({ ok: false, error: "timeout" }));
		socket.once("error", (err) => done({ ok: false, error: err.code || err.message }));
	});
	probeCache.set(key, { at: Date.now(), result });
	return result;
};

/** runs the jobs with a limit of parallel ones */
const limited = async (jobs, limit) => {
	const results = new Array(jobs.length);
	let next = 0;
	const worker = async () => {
		while (next < jobs.length) {
			const index = next++;
			results[index] = await jobs[index]();
		}
	};
	await Promise.all(Array.from({ length: Math.min(limit, jobs.length) }, worker));
	return results;
};

/** host names nginx resolves itself or that are not a plain address (variables, sockets) are not probed */
const probeable = (host) => typeof host === "string" && /^[A-Za-z0-9.:[\]_-]+$/.test(host) && !host.startsWith("unix:");

const internalHosts = {
	/**
	 * The last change of every host the user can see.
	 * @param {Access} access
	 * @returns {Promise<Array<{type, object_id, action, created_on, user}>>}
	 */
	changes: async (access) => {
		const result = [];
		for (const type of Object.keys(HOST_OBJECTS)) {
			const hosts = await visibleHosts(access, type);
			if (!hosts?.length) continue;
			const ids = hosts.map((h) => h.id);
			const latest = db()("audit_log")
				.max("id as id")
				.whereIn("object_type", auditTypes(type))
				.whereIn("object_id", ids)
				.groupBy("object_id");
			const rows = await auditQuery().whereIn("audit_log.id", latest);
			for (const row of rows) {
				result.push({ type, object_id: row.object_id, ...entry(row) });
			}
		}
		return result;
	},

	/**
	 * Changes of one host, newest first.
	 * @param {Access} access
	 * @param {string} type  audit object type
	 * @param {number} id
	 */
	history: async (access, type, id) => {
		const object = HOST_OBJECTS[type];
		if (!object) {
			throw new errs.ValidationError(`Unknown host type: ${type}`);
		}
		await access.can(`${object.permission}:get`, id);
		const host = await db()(object.table).select("created_on").where({ id }).first();
		if (!host) {
			throw new errs.ItemNotFoundError(id);
		}
		// one more row than shown: the snapshot the oldest shown update is compared with
		const rows = await auditQuery()
			.whereIn("audit_log.object_type", auditTypes(type))
			.where("audit_log.object_id", id)
			// entries of an older object with the same id (a restored database) are not this host's
			.where("audit_log.created_on", ">=", host.created_on)
			.orderBy("audit_log.created_on", "desc")
			.orderBy("audit_log.id", "desc")
			.limit(HISTORY_LIMIT + 1);
		return rows.slice(0, HISTORY_LIMIT).map((row, index) => {
			const result = entry(row);
			if (row.action === "updated" && row.object_type !== "waf") {
				const previous = rows.slice(index + 1).find((r) => r.object_type !== "waf" && r.action !== "deleted");
				if (previous) result.fields = changedFields(row.meta, previous.meta, previous.action === "created");
			}
			return result;
		});
	},

	/**
	 * Whether the upstreams of enabled proxy hosts (and their locations) and TCP streams accept
	 * connections. Connections go only to the addresses the hosts forward to, with a timeout.
	 * @param {Access} access
	 * @returns {Promise<Array<{type, object_id, host, port, ok, ms?, error?}>>}
	 */
	upstreams: async (access) => {
		const targets = [];
		const proxies = await visibleHosts(access, "proxy-host", [
			"id",
			"enabled",
			"forward_scheme",
			"forward_host",
			"forward_port",
			"locations",
		]);
		for (const host of proxies ?? []) {
			if (!host.enabled) continue;
			const add = (scheme, address, port) => {
				const target = Number(port) || DEFAULT_PORT[scheme];
				if (probeable(address) && target) {
					targets.push({ type: "proxy-host", object_id: host.id, host: address, port: target });
				}
			};
			add(host.forward_scheme, host.forward_host, host.forward_port);
			const locations = parseJson(host.locations);
			for (const location of Array.isArray(locations) ? locations : []) {
				add(location.forward_scheme, location.forward_host, location.forward_port);
			}
		}
		const streams = await visibleHosts(access, "stream", [
			"id",
			"enabled",
			"forwarding_host",
			"forwarding_port",
			"tcp_forwarding",
		]);
		for (const stream of streams ?? []) {
			// UDP has no handshake to check
			if (stream.enabled && stream.tcp_forwarding && probeable(stream.forwarding_host)) {
				targets.push({
					type: "stream",
					object_id: stream.id,
					host: stream.forwarding_host,
					port: Number(stream.forwarding_port),
				});
			}
		}
		const unique = targets.filter(
			(t, i) =>
				targets.findIndex(
					(o) => o.type === t.type && o.object_id === t.object_id && o.host === t.host && o.port === t.port,
				) === i,
		);
		const results = await limited(
			unique.map((target) => () => probe(target.host.replace(/^\[|\]$/g, ""), target.port)),
			PROBE_CONCURRENCY,
		);
		return unique.map((target, i) => ({ ...target, ...results[i] }));
	},
};

export default internalHosts;
