import assert from "node:assert/strict";
import { test } from "node:test";
import { clean } from "./acme.js";

test("certbot output loses its Let's Encrypt help lines", () => {
	const out = [
		"Some challenges have failed.",
		"Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile /tmp/certbot-log/letsencrypt.log or re-run Certbot with -v for more details.",
		"",
		"",
		"",
		"Detail: 203.0.113.1: Fetching http://a.example/.well-known/acme-challenge/x: Timeout",
	].join("\n");
	const got = clean(out);
	assert.ok(!/letsencrypt/i.test(got));
	assert.match(got, /Some challenges have failed\.\n\nDetail:/);
});

test("the renewal window goes in as a top-level key of the renewal file", async () => {
	const { setRenewWindow } = await import("./acme.js");
	const conf = "version = 5.8.0\narchive_dir = /x\n\n[renewalparams]\nserver = https://a/\n";
	const set = setRenewWindow(conf, 10);
	assert.match(set, /archive_dir = \/x\n\nrenew_before_expiry = 10 days\n\[renewalparams\]/);
	assert.equal(setRenewWindow(setRenewWindow(set, 20), 0), conf);
	assert.equal(setRenewWindow(set, 20).match(/renew_before_expiry/g).length, 1);
});

test("an account the ACME server forgot is recognised in the output of certbot", async () => {
	const { ACCOUNT_GONE } = await import("./acme.js");
	assert.match(
		"acme.messages.Error: urn:ietf:params:acme:error:accountDoesNotExist :: The request specified an account that does not exist",
		ACCOUNT_GONE,
	);
	assert.match(
		"An unexpected error occurred:\nAccount https://pebble:14000/my-account/2013de not found.",
		ACCOUNT_GONE,
	);
	assert.doesNotMatch("Some challenges have failed.\nDetail: Timeout", ACCOUNT_GONE);
});

test("the urllib3 warnings of an ACME server with its own CA are not shown as the error", () => {
	const out = [
		"Requesting a certificate for a.example",
		"/usr/local/lib/python3.14/site-packages/urllib3/connectionpool.py:1129: InsecureRequestWarning: Unverified HTTPS request is being made to host 'pebble'.",
		"  warnings.warn(",
		"Some challenges have failed.",
	].join("\n");
	assert.equal(clean(out), "Requesting a certificate for a.example\nSome challenges have failed.");
});
