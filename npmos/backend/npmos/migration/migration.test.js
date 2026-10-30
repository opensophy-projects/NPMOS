import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { gzipSync } from "node:zlib";
import bcrypt from "bcryptjs";
import { hashAccessPassword } from "./copy.js";
import { copyCertbot, rewriteRenewal } from "./files.js";
import { NPM_MIGRATIONS, openSqlite, upgrade } from "./schema.js";
import { accept, locate } from "./source.js";
import { cleanPath, extract, sniff } from "./tar.js";

let dir;
before(async () => {
	dir = await mkdtemp(path.join(tmpdir(), "npmos-migration-"));
});
after(async () => {
	await rm(dir, { recursive: true, force: true });
});

/** a tar header + body for one file, with any name (also unsafe ones) */
const entry = (name, body, type = "0") => {
	const header = Buffer.alloc(512);
	header.write(name, 0, 100, "utf8");
	header.write("0000644\0", 100);
	header.write("0000000\0", 108);
	header.write("0000000\0", 116);
	header.write(`${body.length.toString(8).padStart(11, "0")}\0`, 124);
	header.write("00000000000\0", 136);
	header.write(type, 156);
	header.write("ustar\0", 257);
	header.write("00", 263);
	header.fill(" ", 148, 156);
	let sum = 0;
	for (const b of header) sum += b;
	header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148);
	const pad = Buffer.alloc((512 - (body.length % 512)) % 512);
	return Buffer.concat([header, body, pad]);
};

test("sniff and cleanPath", () => {
	assert.equal(sniff(Buffer.from([0x1f, 0x8b, 8])), "gzip");
	assert.equal(sniff(Buffer.from("SQLite format 3\0rest")), "sqlite");
	assert.equal(sniff(Buffer.from("hello")), null);
	assert.equal(cleanPath("./data/x"), "data/x");
	assert.equal(cleanPath("/etc/passwd"), "etc/passwd");
	assert.equal(cleanPath("data/../../x"), null);
	assert.equal(cleanPath("."), null);
});

test("accept: only the parts that are migrated", () => {
	assert.ok(accept("data/database.sqlite"));
	assert.ok(accept("data/npmplus/database.sqlite-wal"));
	assert.ok(accept("letsencrypt/renewal/npm-1.conf"));
	assert.ok(accept("data/custom_ssl/npm-3/fullchain.pem"));
	assert.ok(accept("appsec-localconfig/local_policy.yaml"));
	assert.ok(!accept("data/logs/proxy-host-1_access.log"));
	assert.ok(!accept("data/nginx/proxy_host/1.conf"));
	assert.ok(!accept("data/keys.json"));
});

test("extract: unsafe entries are skipped, links are not made", async () => {
	const src = path.join(dir, "src");
	await mkdir(path.join(src, "data/nginx/custom"), { recursive: true });
	await mkdir(path.join(src, "data/logs"), { recursive: true });
	await mkdir(path.join(src, "letsencrypt/archive/npm-1"), { recursive: true });
	await mkdir(path.join(src, "letsencrypt/live/npm-1"), { recursive: true });
	await mkdir(path.join(src, "letsencrypt/renewal"), { recursive: true });
	await writeFile(path.join(src, "data/database.sqlite"), "SQLite format 3\0");
	await writeFile(path.join(src, "data/logs/a.log"), "x".repeat(1000));
	await writeFile(path.join(src, "data/nginx/custom/http.conf"), "# custom");
	await writeFile(path.join(src, "letsencrypt/archive/npm-1/cert1.pem"), "c1");
	await writeFile(path.join(src, "letsencrypt/archive/npm-1/cert2.pem"), "c2");
	await writeFile(path.join(src, "letsencrypt/renewal/npm-1.conf"), "archive_dir = /etc/letsencrypt/archive/npm-1\n");
	await symlink("../../archive/npm-1/cert2.pem", path.join(src, "letsencrypt/live/npm-1/cert.pem"));
	const archive = path.join(dir, "backup.tgz");
	execFileSync("tar", ["czf", archive, "-C", src, "data", "letsencrypt"]);

	const out = path.join(dir, "out");
	await mkdir(out);
	const result = await extract(archive, out, { gzip: true, accept, maxBytes: 1e6, maxEntries: 1000 });
	assert.ok(result.files >= 5);
	assert.equal(await readFile(path.join(out, "data/nginx/custom/http.conf"), "utf8"), "# custom");
	await assert.rejects(lstat(path.join(out, "data/logs/a.log")));
	await assert.rejects(lstat(path.join(out, "letsencrypt/live/npm-1/cert.pem")));

	// an archive with ".." and an absolute path: nothing lands outside
	const evil = path.join(dir, "evil.tar.gz");
	await writeFile(
		evil,
		gzipSync(
			Buffer.concat([
				entry("../escape/database.sqlite", Buffer.from("x")),
				entry("/abs/access/1", Buffer.from("y")),
				entry("data/access/link", Buffer.alloc(0), "2"),
				Buffer.alloc(1024),
			]),
		),
	);
	const out2 = path.join(dir, "out2");
	await mkdir(out2);
	await extract(evil, out2, { gzip: true, accept, maxBytes: 1e6, maxEntries: 1000 });
	await assert.rejects(lstat(path.join(dir, "escape")));
	assert.equal(await readFile(path.join(out2, "abs/access/1"), "utf8"), "y");
	await assert.rejects(lstat(path.join(out2, "data/access/link")));

	await assert.rejects(
		extract(archive, await mkdtemp(path.join(dir, "small-")), {
			gzip: true,
			accept,
			maxBytes: 3,
			maxEntries: 1000,
		}),
		/too large/,
	);

	// where things are, and certbot with live/ made again
	const places = await locate(out);
	assert.equal(places.database, path.join(out, "data/database.sqlite"));
	assert.equal(places.certbot, path.join(out, "letsencrypt"));
	assert.equal(places.customNginx, path.join(out, "data/nginx/custom"));
	const data = path.join(dir, "target");
	assert.equal(await copyCertbot(places.certbot, [1, 2], data), 1);
	const live = path.join(data, "tls/certbot/live/npm-1");
	assert.deepEqual(await readdir(live), ["cert.pem"]);
	assert.equal(await readFile(path.join(live, "cert.pem"), "utf8"), "c2");
	assert.match(
		await readFile(path.join(data, "tls/certbot/renewal/npm-1.conf"), "utf8"),
		/\/data\/tls\/certbot\/archive/,
	);
});

test("locate: NPMplus layout", async () => {
	const root = path.join(dir, "plus");
	await mkdir(path.join(root, "npmplus"), { recursive: true });
	await mkdir(path.join(root, "tls/certbot/renewal"), { recursive: true });
	await mkdir(path.join(root, "tls/custom/npm-2"), { recursive: true });
	await mkdir(path.join(root, "custom_nginx"), { recursive: true });
	await writeFile(path.join(root, "npmplus/database.sqlite"), "");
	const places = await locate(root);
	assert.equal(places.dataRoot, root);
	assert.equal(places.certbot, path.join(root, "tls/certbot"));
	assert.equal(places.customSsl, path.join(root, "tls/custom"));
	assert.equal(places.customNginx, path.join(root, "custom_nginx"));
});

test("rewriteRenewal and access list passwords", () => {
	assert.equal(
		rewriteRenewal("cert = /etc/letsencrypt/live/npm-1/cert.pem\nwebroot_path = /data/letsencrypt-acme-challenge,"),
		"cert = /data/tls/certbot/live/npm-1/cert.pem\nwebroot_path = /data/tls/certbot/acme-challenge,",
	);
	const hash = hashAccessPassword("secret");
	assert.ok(bcrypt.compareSync("secret", hash));
	assert.equal(hashAccessPassword(hash), hash);
	assert.equal(hashAccessPassword("$apr1$abc$def"), "$apr1$abc$def");
	assert.equal(hashAccessPassword(""), "");
});

test("schema: a database of NPM is upgraded to NPMplus", async () => {
	const file = path.join(dir, "npm.sqlite");
	const db = openSqlite(file);
	try {
		await upgrade(db, NPM_MIGRATIONS);
		assert.ok(!(await db.schema.hasTable("npmplus_proxy_host_access_list")));
		await db("user").insert({
			created_on: "2024-01-01 00:00:00",
			modified_on: "2024-01-01 00:00:00",
			email: "a@b.c",
			name: "a",
			nickname: "a",
			avatar: "",
			roles: "[]",
		});
		const ran = await upgrade(db);
		assert.ok(ran.length > 10);
		assert.ok(await db.schema.hasTable("npmplus_proxy_host_access_list"));
		assert.equal((await db("user").first()).email, "a@b.c");
		assert.deepEqual(await upgrade(db), []);
	} finally {
		await db.destroy();
	}
});
