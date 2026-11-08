import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.NGINXIONS_SECRET_KEY_FILE = path.join(mkdtempSync(path.join(tmpdir(), "nginxions-acme-")), "secret.key");
const { normalize, PRESETS, SECRET_SET } = await import("./servers.js");
const { challengeArgs, parseCredentials } = await import("./lego.js");
const { decrypt } = await import("../secrets.js");

test("a preset takes its directory and client; the TLS CA needs lego", () => {
	const le = normalize({ preset: "letsencrypt" });
	assert.equal(le.directory, "https://acme-v02.api.letsencrypt.org/directory");
	assert.equal(le.client, "certbot");
	assert.equal(le.name, "Let's Encrypt");
	const tlscc = normalize({ preset: "tlscc-stage" });
	assert.equal(tlscc.client, "lego");
	assert.throws(() => normalize({ preset: "tlscc-stage", client: "certbot" }), /only with lego/);
	assert.ok(PRESETS.every((p) => p.directory.startsWith("https://")));
});

test("a server of your own: its URL, name from the host, client of choice", () => {
	const s = normalize({
		directory: "https://ca.internal:9000/acme/acme/directory",
		client: "lego",
		tls_verify: false,
	});
	assert.equal(s.preset, "custom");
	assert.equal(s.name, "ca.internal:9000");
	assert.equal(s.client, "lego");
	assert.equal(s.tls_verify, false);
	assert.throws(() => normalize({ directory: "ftp://x" }), /https:\/\//);
	assert.throws(() => normalize({ directory: "https://x/dir", client: "acme.sh" }), /certbot or lego/);
});

test("EAB: both keys or none, required by Google, an email with ZeroSSL; the secret is kept when masked", () => {
	assert.throws(() => normalize({ preset: "google" }), /EAB keys/);
	assert.throws(() => normalize({ preset: "google", eab_kid: "kid", email: "a@b.c" }), /go together/);
	assert.throws(() => normalize({ preset: "zerossl" }), /email/);
	const g = normalize({ preset: "google", eab_kid: "kid1", eab_hmac_key: "hmacSecret_1", email: "a@b.c" });
	assert.equal(decrypt(g.eab_hmac_key_enc), "hmacSecret_1");
	const current = {
		preset: "google",
		directory: g.directory,
		eab_kid: "kid1",
		eab_hmac_key: "hmacSecret_1",
		email: "a@b.c",
	};
	const again = normalize({ eab_hmac_key: SECRET_SET, name: "Google (mine)" }, current);
	assert.equal(decrypt(again.eab_hmac_key_enc), "hmacSecret_1");
	assert.equal(again.name, "Google (mine)");
});

test("DNS credentials of lego are KEY=VALUE lines", () => {
	assert.deepEqual(parseCredentials("# token of Cloudflare\nCF_DNS_API_TOKEN=abc=def\n\nCF_ZONE_API_TOKEN = 'x y'"), {
		CF_DNS_API_TOKEN: "abc=def",
		CF_ZONE_API_TOKEN: "x y",
	});
	assert.throws(() => parseCredentials("just a token"), /KEY=VALUE/);
	assert.throws(() => parseCredentials("lower=1"), /variable name/);
});

test("the challenge of lego: the webroot of nginx, or a DNS provider with its wait", () => {
	assert.deepEqual(challengeArgs({}).args, ["--http", "--http.webroot", "/data/tls/certbot/acme-challenge"]);
	const dns = challengeArgs({
		dns_challenge: true,
		dns_provider: "rfc2136",
		dns_provider_credentials: "RFC2136_NAMESERVER=127.0.0.1",
		propagation_seconds: 30,
	});
	assert.deepEqual(dns.args, ["--dns", "rfc2136", "--dns.propagation-wait", "30s"]);
	assert.deepEqual(dns.env, { RFC2136_NAMESERVER: "127.0.0.1" });
	assert.throws(() => challengeArgs({ dns_challenge: true, dns_provider: "x; rm" }), /DNS provider/);
});
