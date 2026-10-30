// Certificates → registry: every certificate the system has in one list, with pages from the server.
// Sources: TLS certificates of the hosts (NPMplus), CAs and issued certificates of the PKI, and certificate
// files on disk that no record describes (left by a migration, an old host, a manual copy). RBAC: TLS rows
// with certificates:view, PKI rows with pki:view, files with either.
import { X509Certificate } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import db from "../db.js";
import errs from "../lib/error.js";

const DAY = 86400000;
/** "expiring": less than this many days left */
export const EXPIRING_DAYS = 30;
const MAX_LIMIT = 200;
export const SOURCES = ["tls", "ca", "pki", "file"];
export const STATUSES = ["valid", "expiring", "expired", "revoked"];
const SORTS = ["expires", "-expires", "name", "-created"];
const HOST_TABLES = ["proxy_host", "redirection_host", "dead_host", "stream"];
/** directories with certificate files of nginx, certbot, NPMplus and the PKI */
const SCAN_DIRS = ["/data/tls", "/data/npmos/pki/nginx"];
const SCAN_DEPTH = 4;
const DUMMY_CERT = "/data/tls/dummycert.pem";
const SCAN_MAX_FILES = 2000;
/** private keys, account data and ACME challenges are not certificates */
const SKIP_DIRS = new Set(["accounts", "acme-challenge", "renewal", "renewal-hooks", "ech"]);

const parse = (value) => {
	if (typeof value !== "string") return value;
	try {
		return JSON.parse(value);
	} catch {
		return null;
	}
};

const list = (value) =>
	String(value ?? "")
		.split(",")
		.map((v) => v.trim())
		.filter(Boolean);

const may = (access, permission) =>
	access.can(permission).then(
		() => true,
		() => false,
	);

const iso = (value) => (value ? new Date(value).toISOString() : null);

const statusOf = (notAfter, revoked, now) => {
	if (revoked) return "revoked";
	if (!notAfter) return "valid";
	const left = new Date(notAfter).getTime() - now.getTime();
	if (left <= 0) return "expired";
	return left < EXPIRING_DAYS * DAY ? "expiring" : "valid";
};

const hostName = (table, host) =>
	table === "stream" ? `:${host.incoming_port}` : (parse(host.domain_names) || []).join(", ");

/** hosts by the certificate they serve, and by the uploaded mTLS CA they trust (NPMplus) */
const hostUsage = async () => {
	const byCert = {};
	const byMtlsCa = {};
	for (const table of HOST_TABLES) {
		for (const host of await db()(table).where({ is_deleted: 0 })) {
			const entry = { type: table, id: host.id, name: hostName(table, host) };
			if (host.certificate_id > 0) {
				byCert[host.certificate_id] = [...(byCert[host.certificate_id] || []), entry];
			}
			const mtls = Number(parse(host.meta)?.npmplus_mtls_certificate_id);
			if (mtls > 0) byMtlsCa[mtls] = [...(byMtlsCa[mtls] || []), entry];
		}
	}
	return { byCert, byMtlsCa };
};

/** hosts of NPMOS mTLS that trust each CA (loaded on use: the module reads the configuration of NPMplus) */
const caUsage = async () => (await (await import("./pki/mtls.js")).usage()).cas;

const firstCert = (pem) => {
	const m = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(pem);
	if (!m) return null;
	try {
		return new X509Certificate(m[0]);
	} catch {
		return null;
	}
};

const cn = (dn) => /(?:^|\n|,\s*)CN=([^\n,]+)/.exec(dn || "")?.[1] ?? "";

const sansOf = (x509) =>
	(x509.subjectAltName || "")
		.split(",")
		.map((s) => s.trim().replace(/^(DNS|IP Address|email):/, ""))
		.filter(Boolean);

/** certificate files under the scanned directories: {path, x509, fingerprint} */
const scanFiles = async () => {
	const found = [];
	const walk = async (dir, depth) => {
		if (depth > SCAN_DEPTH || found.length >= SCAN_MAX_FILES) return;
		const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
		for (const entry of entries) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) {
				if (!SKIP_DIRS.has(entry.name)) await walk(full, depth + 1);
				continue;
			}
			// certbot's live/ holds links to archive/: the archive files are listed once
			if (!/\.(pem|crt|cer)$/i.test(entry.name) || /key|privkey/i.test(entry.name)) continue;
			if (entry.isSymbolicLink() || !entry.isFile()) continue;
			const info = await stat(full).catch(() => null);
			if (!info || info.size > 1024 * 1024) continue;
			const x509 = firstCert(await readFile(full, "utf8").catch(() => ""));
			if (x509) found.push({ path: full, x509, fingerprint: x509.fingerprint256 });
			if (found.length >= SCAN_MAX_FILES) return;
		}
	};
	for (const dir of SCAN_DIRS) await walk(dir, 0);
	return found;
};

/** all rows of the registry the user may see, before filters */
const collect = async (access, now) => {
	const [canTls, canPki] = await Promise.all([may(access, "certificates:list"), may(access, "pki:view")]);
	if (!canTls && !canPki) throw new errs.PermissionError("Permission Denied");
	const rows = [];
	const known = new Set();
	const usage = await hostUsage();
	const cas = canPki ? await db()("npmos_pki_ca").orderBy("id") : [];
	const caName = Object.fromEntries(cas.map((c) => [c.id, c.name]));
	/** certificates of NPMplus issued by the PKI: one row, the TLS one, says where it came from */
	const pkiOf = {};

	const trusted = canPki ? await caUsage() : {};
	if (canPki) {
		for (const ca of cas) {
			if (ca.fingerprint) known.add(ca.fingerprint.toUpperCase());
			const usedBy = ca.upstream_certificate_id
				? usage.byMtlsCa[ca.upstream_certificate_id] || []
				: (trusted[ca.id] || []).map((name) => ({ type: "mtls", id: 0, name }));
			rows.push({
				key: `ca:${ca.id}`,
				source: "ca",
				id: ca.id,
				name: ca.name,
				subjects: [cn(ca.subject_dn)].filter(Boolean),
				kind: ca.kind,
				issuer: ca.parent_id ? caName[ca.parent_id] || "" : "",
				serial: ca.serial,
				not_before: iso(ca.not_before),
				not_after: iso(ca.not_after),
				created_on: iso(ca.created_on),
				status: statusOf(ca.not_after, false, now),
				used_by: usedBy,
				tls_id: ca.upstream_certificate_id || null,
			});
		}
		const certs = await db()("npmos_pki_cert").whereNull("deleted_on").orderBy("id", "desc");
		for (const cert of certs) {
			if (cert.fingerprint) known.add(cert.fingerprint.toUpperCase());
			const entry = {
				key: `pki:${cert.id}`,
				source: "pki",
				id: cert.id,
				name: cert.common_name,
				subjects: Object.values(parse(cert.sans) || {})
					.flat()
					.filter((v) => typeof v === "string"),
				kind: cert.profile,
				issuer: caName[cert.ca_id] || "",
				serial: cert.serial,
				not_before: iso(cert.not_before),
				not_after: iso(cert.not_after),
				created_on: iso(cert.created_on),
				status: statusOf(cert.not_after, !!cert.revoked_on, now),
				used_by:
					cert.profile === "client"
						? (trusted[cert.ca_id] || []).map((name) => ({ type: "mtls", id: 0, name }))
						: [],
				ca_id: cert.ca_id,
			};
			// a server certificate installed as a TLS certificate of NPMplus is listed once, as TLS
			if (cert.certificate_id && canTls) {
				pkiOf[cert.certificate_id] = entry;
				continue;
			}
			rows.push(entry);
		}
	}

	if (canTls) {
		const certs = await db()("certificate").where({ is_deleted: 0 }).whereNot("provider", "mtls").orderBy("id");
		for (const cert of certs) {
			const meta = parse(cert.meta) || {};
			const pki = pkiOf[cert.id];
			rows.push({
				key: `tls:${cert.id}`,
				source: "tls",
				id: cert.id,
				name: cert.nice_name || (parse(cert.domain_names) || []).join(", "),
				subjects: parse(cert.domain_names) || [],
				kind: cert.provider,
				dns_provider: meta.dns_challenge ? meta.dns_provider || null : null,
				issuer: pki ? pki.issuer : "",
				not_before: null,
				not_after: iso(cert.expires_on),
				created_on: iso(cert.created_on),
				status: statusOf(cert.expires_on, pki?.status === "revoked", now),
				used_by: usage.byCert[cert.id] || [],
				pki_id: pki?.id ?? null,
			});
		}
		// TLS certificates of NPMplus have no fingerprint in the database: their files are known by path
		for (const cert of certs) {
			for (const file of [
				`/data/tls/custom/npm-${cert.id}/fullchain.pem`,
				`/data/tls/certbot/live/npm-${cert.id}/fullchain.pem`,
			]) {
				const x509 = firstCert(await readFile(file, "utf8").catch(() => ""));
				if (x509) known.add(x509.fingerprint256.toUpperCase());
			}
		}
		for (const ca of await db()("certificate").where({ is_deleted: 0, provider: "mtls" })) {
			const x509 = firstCert(await readFile(`/data/tls/mtls/npm-${ca.id}.pem`, "utf8").catch(() => ""));
			if (x509) known.add(x509.fingerprint256.toUpperCase());
		}
	}

	for (const file of await scanFiles()) {
		const fp = file.fingerprint.toUpperCase();
		// the same certificate as a record above, or a copy of another file (bundles of the PKI for nginx)
		if (known.has(fp) || known.has(fp.replaceAll(":", ""))) continue;
		known.add(fp);
		const x509 = file.x509;
		// the self-signed placeholder of NPMplus: nginx serves it to requests for unknown names
		const dummy = file.path === DUMMY_CERT;
		rows.push({
			key: `file:${file.path}`,
			source: "file",
			id: file.path,
			name: cn(x509.subject) || path.basename(file.path),
			subjects: sansOf(x509),
			kind: dummy ? "dummy" : x509.ca ? "ca" : "file",
			issuer: cn(x509.issuer),
			serial: x509.serialNumber,
			not_before: iso(x509.validFrom),
			not_after: iso(x509.validTo),
			created_on: null,
			status: statusOf(x509.validTo, false, now),
			used_by: dummy ? [{ type: "default", id: 0, name: "" }] : [],
			path: file.path,
		});
	}
	return { rows, canTls, canPki };
};

/**
 * Filters from query parameters: source, status, kind: comma-separated; used=yes|no; q: text in the name,
 * domains, issuer, serial and path; sort=expires (soonest first, default) | -expires | name | -created.
 */
export const parseQuery = (query) => {
	const source = list(query.source).filter((s) => SOURCES.includes(s));
	const status = list(query.status).filter((s) => STATUSES.includes(s));
	return {
		source,
		status,
		kind: list(query.kind),
		used: ["yes", "no"].includes(query.used) ? query.used : "",
		q: String(query.q ?? "")
			.trim()
			.toLowerCase()
			.slice(0, 200),
		sort: SORTS.includes(query.sort) ? query.sort : "expires",
	};
};

export const filterRows = (rows, f) =>
	rows.filter(
		(r) =>
			(!f.source.length || f.source.includes(r.source)) &&
			(!f.status.length || f.status.includes(r.status)) &&
			(!f.kind.length || f.kind.includes(r.kind)) &&
			(!f.used || (f.used === "yes") === r.used_by.length > 0) &&
			(!f.q ||
				[r.name, ...r.subjects, r.issuer, r.serial, r.path, ...r.used_by.map((u) => u.name)]
					.filter(Boolean)
					.some((v) => String(v).toLowerCase().includes(f.q))),
	);

const time = (v, missing) => (v ? new Date(v).getTime() : missing);

export const sortRows = (rows, sort) => {
	const by = {
		expires: (a, b) => time(a.not_after, Number.POSITIVE_INFINITY) - time(b.not_after, Number.POSITIVE_INFINITY),
		"-expires": (a, b) => time(b.not_after, Number.NEGATIVE_INFINITY) - time(a.not_after, Number.NEGATIVE_INFINITY),
		name: (a, b) => a.name.localeCompare(b.name),
		"-created": (a, b) =>
			time(b.created_on, Number.NEGATIVE_INFINITY) - time(a.created_on, Number.NEGATIVE_INFINITY),
	}[sort];
	return [...rows].sort((a, b) => by(a, b) || a.key.localeCompare(b.key));
};

const count = (rows, field) => {
	const result = {};
	for (const r of rows) result[r[field]] = (result[r[field]] || 0) + 1;
	return result;
};

const internalCertificates = {
	/**
	 * A page of the registry with counts by source and status (of the rows before those two filters).
	 * @param {Access} access
	 * @param {object} query  parseQuery, limit, offset
	 */
	list: async (access, query = {}) => {
		const now = new Date();
		const f = parseQuery(query);
		const limit = Math.min(Math.max(Number.parseInt(query.limit, 10) || 25, 1), MAX_LIMIT);
		const offset = Math.max(Number.parseInt(query.offset, 10) || 0, 0);
		const { rows, canTls, canPki } = await collect(access, now);
		const matched = sortRows(filterRows(rows, f), f.sort);
		return {
			items: matched.slice(offset, offset + limit),
			total: matched.length,
			limit,
			offset,
			counts: {
				source: count(filterRows(rows, { ...f, source: [] }), "source"),
				status: count(filterRows(rows, { ...f, status: [] }), "status"),
			},
			kinds: [...new Set(rows.filter((r) => !f.source.length || f.source.includes(r.source)).map((r) => r.kind))]
				.filter(Boolean)
				.sort(),
			expiring_days: EXPIRING_DAYS,
			can: { tls: canTls, pki: canPki },
		};
	},
};

export default internalCertificates;
