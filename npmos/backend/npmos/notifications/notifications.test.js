import assert from "node:assert/strict";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

const dir = await fs.mkdtemp(path.join(os.tmpdir(), "npmos-secrets-"));
process.env.NPMOS_SECRET_KEY_FILE = path.join(dir, "secret.key");

const { decrypt, encrypt } = await import("../secrets.js");
const { channelConfig, deliver, sign } = await import("./channels.js");
const { normalizeParams, render } = await import("./rules.js");

let server;
let url;
const received = [];

before(async () => {
	server = http.createServer((req, res) => {
		let body = "";
		req.on("data", (c) => {
			body += c;
		});
		req.on("end", () => {
			received.push({ url: req.url, headers: req.headers, body });
			if (req.url.includes("/botbad")) {
				res.writeHead(401, { "Content-Type": "application/json" });
				res.end(JSON.stringify({ ok: false, description: "Unauthorized" }));
				return;
			}
			res.writeHead(req.url === "/fail" ? 500 : 200, { "Content-Type": "application/json" });
			res.end("{}");
		});
	});
	await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
	url = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
	server.close();
	await fs.rm(dir, { recursive: true });
});

test("secrets are encrypted with a key outside the database", async () => {
	const value = encrypt("s3cret");
	assert.match(value, /^enc:v1:/);
	assert.notEqual(value, encrypt("s3cret"));
	assert.equal(decrypt(value), "s3cret");
	assert.equal(decrypt(""), "");
	assert.equal((await fs.stat(process.env.NPMOS_SECRET_KEY_FILE)).mode & 0o777, 0o600);
	assert.throws(() => decrypt(`${value.slice(0, -4)}AAAA`));
});

test("channel config: secrets kept when not sent, replaced when sent", () => {
	const first = channelConfig("webhook", { url: "https://x", secret: "k1" });
	assert.equal(decrypt(first.secret), "k1");
	const kept = channelConfig("webhook", { url: "https://y" }, first);
	assert.equal(kept.secret, first.secret);
	const cleared = channelConfig("webhook", { url: "https://y", secret: "" }, first);
	assert.equal(cleared.secret, "");
	const email = channelConfig("email", { host: "smtp", port: 587, security: "starttls", from: "a@b", to: ["c@d"] });
	assert.deepEqual([email.verifyTls, email.language, email.password], [true, "ru", ""]);
});

test("webhook: JSON with an HMAC signature; errors on non-2xx", async () => {
	const message = { status: "firing", title: "T", text: "X", time: "2026-10-28T00:00:00Z" };
	await deliver({ type: "webhook", config: { url: `${url}/hook`, secret: "key" } }, message);
	const hit = received.at(-1);
	assert.equal(hit.url, "/hook");
	assert.equal(JSON.parse(hit.body).source, "npmos");
	const expected = sign("key", hit.headers["x-npmos-timestamp"], hit.body);
	assert.equal(hit.headers["x-npmos-signature"], `sha256=${expected}`);
	await assert.rejects(deliver({ type: "webhook", config: { url: `${url}/fail` } }, message), /HTTP 500/);
	const closed = http.createServer();
	await new Promise((resolve) => closed.listen(0, "127.0.0.1", resolve));
	const port = closed.address().port;
	await new Promise((resolve) => closed.close(resolve));
	await assert.rejects(
		deliver({ type: "webhook", config: { url: `http://127.0.0.1:${port}/` } }, message),
		/ECONNREFUSED/,
	);
});

test("telegram: sendMessage of the bot, the token never in an error", async () => {
	const message = { status: "firing", title: "T", text: "X", time: "t" };
	await deliver({ type: "telegram", config: { token: "123:abc", chatId: "-100", apiUrl: url } }, message);
	const hit = received.at(-1);
	assert.equal(hit.url, "/bot123:abc/sendMessage");
	assert.equal(JSON.parse(hit.body).chat_id, "-100");
	await assert.rejects(
		deliver({ type: "telegram", config: { token: "bad", chatId: "1", apiUrl: url } }, message),
		(err) => /Unauthorized/.test(err.message) && !err.message.includes("bad"),
	);
});

test("rules: defaults and texts in both languages", () => {
	assert.deepEqual(normalizeParams("attack_spike", { threshold: -1, window: 10, host: " App.Example.com " }), {
		threshold: 50,
		window: 10,
		host: "app.example.com",
	});
	assert.deepEqual(normalizeParams("cert_expiry", {}), { days: 14 });
	const values = { count: 120, window: 5, threshold: 50, host: "", top: "203.0.113.7" };
	assert.match(render("attack_spike", "firing", values, "ru").title, /^Всплеск атак: 120/);
	assert.match(render("attack_spike", "resolved", values, "en").title, /^Resolved: Attack spike/);
	assert.match(
		render("cert_expiry", "firing", { name: "a", domains: "a", expires: "x", days: -2 }, "en").title,
		/expired/,
	);
});
