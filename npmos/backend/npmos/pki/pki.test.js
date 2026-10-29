import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Liquid } from "liquidjs";
import * as ops from "./ops.js";
import { ruleRegex, trustSet } from "./trust.js";
import {
	extConfig,
	generateKey,
	indexTxt,
	normalizeSans,
	normalizeSubject,
	PkiError,
	parseCert,
	randomSerial,
	splitPem,
	subjectArg,
} from "./x509.js";

const TEMPLATES = path.join(path.dirname(fileURLToPath(import.meta.url)), "../../templates");

test("subjects and alternative names are checked", () => {
	assert.deepEqual(normalizeSubject({ common_name: " Иван Петров ", organization: "", country: "RU" }), {
		common_name: "Иван Петров",
		country: "RU",
	});
	assert.throws(() => normalizeSubject({ organization: "x" }), PkiError);
	assert.throws(() => normalizeSubject({ common_name: "a/b" }), PkiError);
	assert.throws(() => normalizeSubject({ common_name: "a+b" }), PkiError);
	assert.throws(() => normalizeSubject({ common_name: "Иван" }, { ascii: true }), PkiError);
	assert.throws(() => normalizeSubject({ common_name: "x", country: "Russia" }), PkiError);
	assert.equal(subjectArg({ common_name: "x", organization: "O", country: "RU" }), "/C=RU/O=O/CN=x");
	assert.deepEqual(normalizeSans({ dns: ["A.example.com", "*.example.com", "a.example.com"], ip: ["10.0.0.1"] }), {
		dns: ["a.example.com", "*.example.com"],
		ip: ["10.0.0.1"],
		email: [],
	});
	assert.throws(() => normalizeSans({ dns: ["bad name"] }), PkiError);
	assert.throws(() => normalizeSans({ ip: ["300.1.1.1"] }), PkiError);
	assert.match(extConfig("client", { sans: normalizeSans({ email: ["a@b.c"] }) }), /extendedKeyUsage = clientAuth/);
	assert.throws(() => extConfig("client", { crlUrl: "http://x/$y" }), PkiError);
	const serial = randomSerial();
	assert.match(serial, /^[0-9A-F]{32}$/);
	assert.ok(Number.parseInt(serial.slice(0, 2), 16) >= 1 && Number.parseInt(serial.slice(0, 2), 16) <= 0x7f);
	assert.equal(
		indexTxt([
			{ serial: "AB", not_after: "2030-01-02T03:04:05Z", revoked_on: "2026-10-29T00:00:00Z", revoke_reason: "x" },
		]),
		"R\t300102030405Z\t261029000000Z,unspecified\tAB\tunknown\t/CN=revoked\n",
	);
});

// root → trust domain → client, as the PKI issues them; then a CRL and a PKCS#12
test("a chain of NPMOS verifies, revocation is in the CRL, the .p12 opens", async () => {
	const rootKey = generateKey("ec-p256");
	const root = await ops.selfSign({
		keyPem: rootKey,
		subject: { common_name: "Test Root", organization: "NPMOS" },
		days: 30,
		serial: randomSerial(),
	});
	assert.ok(parseCert(root).selfSigned);
	assert.ok(parseCert(root).isCa);
	const domainKey = generateKey("ec-p256");
	const domain = await ops.sign({
		csrPem: await ops.makeCsr({ keyPem: domainKey, subject: { common_name: "Office", organization: "NPMOS" } }),
		caCertPem: root,
		caKeyPem: rootKey,
		profile: "intermediate",
		days: 20,
		serial: randomSerial(),
		crlUrl: "http://pki.local/api/npmos/pki/public/crl/1.crl",
	});
	assert.deepEqual(await ops.names(domain), { subject: "CN=Office,O=NPMOS", issuer: "CN=Test Root,O=NPMOS" });

	const clientKey = generateKey("rsa-2048");
	const csr = await ops.makeCsr({
		keyPem: clientKey,
		subject: { common_name: "Иван Петров", email: "ivan@example.com" },
	});
	assert.deepEqual(await ops.readCsr(csr), { keyType: "rsa-2048", rsa: true });
	await assert.rejects(ops.readCsr("not a request"), PkiError);
	const client = await ops.sign({
		csrPem: csr,
		caCertPem: domain,
		caKeyPem: domainKey,
		profile: "client",
		sans: normalizeSans({ email: ["ivan@example.com"] }),
		days: 10,
		serial: randomSerial(),
		rsa: true,
	});
	const info = parseCert(client);
	assert.equal(info.subject.common_name, "Иван Петров");
	assert.equal(info.subject.email, "ivan@example.com");
	assert.deepEqual(info.sans.email, ["ivan@example.com"]);
	assert.equal(info.isCa, false);
	assert.ok(ops.keyMatches(clientKey, client));
	assert.ok(!ops.keyMatches(domainKey, client));
	// UTF-8 stays UTF-8 (nginx prints it escaped in RFC 2253)
	assert.match((await ops.names(client)).subject, /^emailAddress=ivan@example\.com,CN=\\D0\\98/);

	const dir = mkdtempSync(path.join(os.tmpdir(), "npmos-pki-test-"));
	try {
		writeFileSync(path.join(dir, "chain.pem"), domain + root);
		writeFileSync(path.join(dir, "client.pem"), client);
		const verify = (crl) =>
			execFileSync("openssl", [
				"verify",
				...(crl ? ["-crl_check_all", "-CRLfile", path.join(dir, "crl.pem")] : []),
				"-CAfile",
				path.join(dir, "chain.pem"),
				path.join(dir, "client.pem"),
			]).toString();
		assert.match(verify(false), /OK/);

		const empty = await ops.makeCrl({
			caCertPem: domain,
			caKeyPem: domainKey,
			revoked: [],
			crlNumber: 1,
			days: 30,
		});
		const rootCrl = await ops.makeCrl({ caCertPem: root, caKeyPem: rootKey, revoked: [], crlNumber: 1, days: 30 });
		writeFileSync(path.join(dir, "crl.pem"), empty + rootCrl);
		assert.match(verify(true), /OK/);
		const crl = await ops.makeCrl({
			caCertPem: domain,
			caKeyPem: domainKey,
			revoked: [
				{
					serial: info.serial,
					not_after: info.notAfter,
					revoked_on: new Date(),
					revoke_reason: "keyCompromise",
				},
			],
			crlNumber: 2,
			days: 30,
		});
		const { nextUpdate } = await ops.checkCrl(crl, domain);
		assert.ok(nextUpdate > new Date(Date.now() + 29 * 86400000));
		await assert.rejects(ops.checkCrl(crl, root), PkiError);
		writeFileSync(path.join(dir, "crl.pem"), crl + rootCrl);
		assert.throws(() => verify(true), /certificate revoked/);
		assert.ok((await ops.crlToDer(crl)).length > 100);

		const p12 = await ops.pkcs12({
			certPem: client,
			keyPem: clientKey,
			chainPem: domain + root,
			password: "test-pass",
			name: "Иван Петров",
		});
		writeFileSync(path.join(dir, "client.p12"), p12);
		const info12 = execFileSync(
			"openssl",
			["pkcs12", "-in", path.join(dir, "client.p12"), "-passin", "pass:test-pass", "-info", "-nokeys"],
			{ stdio: ["ignore", "pipe", "pipe"] },
		).toString();
		assert.equal(splitPem(info12).length, 3);
		const key = ops.encryptKey(rootKey, "long password");
		assert.match(key, /ENCRYPTED PRIVATE KEY/);
		assert.ok(ops.keyMatches(ops.readKey(key, "long password"), root));
		assert.throws(() => ops.readKey(key, "wrong"), PkiError);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

const CAS = [
	{ id: 1, kind: "root", parent_id: null, subject_dn: "CN=Root,O=NPMOS", cert_pem: "R\n", crl_pem: "RC" },
	{ id: 2, kind: "intermediate", parent_id: 1, subject_dn: "CN=Office,O=NPMOS", cert_pem: "O\n", crl_pem: "OC" },
	{
		id: 3,
		kind: "intermediate",
		parent_id: 1,
		subject_dn: "CN=Partners (EU),O=NPMOS",
		cert_pem: "P\n",
		crl_pem: "PC",
	},
	{ id: 4, kind: "external", parent_id: null, subject_dn: "CN=Ext", cert_pem: "E\n", crl_pem: null },
];

test("a trust domain trusts its root but accepts only its own certificates", () => {
	const pem = (s) => `-----BEGIN CERTIFICATE-----\n${s}\n-----END CERTIFICATE-----\n`;
	const cas = CAS.map((ca) => ({ ...ca, cert_pem: pem(ca.cert_pem.trim()) }));
	const office = trustSet([2], cas);
	assert.deepEqual(office.ids, [2, 1]);
	assert.deepEqual(office.issuers, ["CN=Office,O=NPMOS"]);
	assert.equal(office.crls, "OC\nRC\n");
	assert.equal(splitPem(office.certs).length, 2);
	const root = trustSet([1], cas);
	assert.deepEqual(root.ids.sort(), [1, 2, 3]);
	assert.deepEqual(root.issuers.sort(), ["CN=Office,O=NPMOS", "CN=Partners (EU),O=NPMOS", "CN=Root,O=NPMOS"]);
	// an external CA: no issuer check, and without its CRL revocation is not checked at all
	const mixed = trustSet([2, 4], cas);
	assert.equal(mixed.issuers, null);
	assert.equal(mixed.crls, null);
	assert.deepEqual(trustSet([99], cas).ids, []);
});

test("rules on client certificates become nginx regular expressions", () => {
	assert.deepEqual(ruleRegex({ field: "organizational_unit", op: "one_of", values: ["IT", "Sec.Ops"] }), {
		variable: "$ssl_client_s_dn",
		regex: "(^|,)OU=(?:IT|Sec\\.Ops)(,|$)",
	});
	assert.deepEqual(ruleRegex({ field: "serial", op: "one_of", values: ["0A1B"] }), {
		variable: "$ssl_client_serial",
		regex: "^(?:0A1B)$",
	});
	const { regex } = ruleRegex({ field: "common_name", op: "regex", values: ["admin-[0-9]+"] });
	const re = new RegExp(regex);
	assert.ok(re.test("CN=admin-12,O=NPMOS"));
	assert.ok(re.test("O=NPMOS,CN=admin-1"));
	assert.ok(!re.test("CN=xadmin-1,O=NPMOS"));
	assert.ok(!re.test("O=NPMOS,OU=CN=admin-1x"));
});

test("the mTLS templates render the nginx directives", async () => {
	const engine = new Liquid({ root: TEMPLATES });
	const template = readFileSync(path.join(TEMPLATES, "_npmos_mtls.conf"), "utf8");
	const npmos_mtls = {
		mode: "on",
		depth: 2,
		send_ca_names: false,
		ca_file: "/data/npmos/pki/nginx/proxy_host-1.ca.pem",
		crl_file: "/data/npmos/pki/nginx/proxy_host-1.crl.pem",
		issuers: "^(?:CN=Office,O=NPMOS)$",
		rules: [ruleRegex({ field: "organizational_unit", op: "one_of", values: ["IT"] })],
		headers: true,
	};
	const out = await engine.parseAndRender(template, { npmos_mtls, ssl_forced: true });
	assert.match(out, /ssl_verify_client on;/);
	assert.match(out, /ssl_trusted_certificate \/data\/npmos\/pki\/nginx\/proxy_host-1\.ca\.pem;/);
	assert.match(out, /ssl_crl \/data\/npmos\/pki\/nginx\/proxy_host-1\.crl\.pem;/);
	assert.match(out, /if \(\$ssl_client_i_dn !~ "\^\(\?:CN=Office,O=NPMOS\)\$"\) \{ set \$npmos_mtls 495; \}/);
	assert.match(out, /if \(\$ssl_client_s_dn !~ "\(\^\|,\)OU=\(\?:IT\)\(,\|\$\)"\)/);
	assert.match(out, /if \(\$scheme = "http"\) \{ set \$npmos_mtls 0; \}/);
	assert.match(out, /return 496;/);
	assert.match(out, /more_set_input_headers "X-Client-Verify: \$ssl_client_verify"/);
	const optional = await engine.parseAndRender(template, {
		npmos_mtls: { ...npmos_mtls, mode: "optional", crl_file: "", issuers: "", rules: [], headers: false },
	});
	assert.doesNotMatch(optional, /return 49/);
	assert.doesNotMatch(optional, /ssl_crl|ssl_client_i_dn|more_set_input_headers|scheme/);
});
