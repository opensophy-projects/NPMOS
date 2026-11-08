import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (file) => JSON.parse(readFileSync(new URL(`../schema/${file}`, import.meta.url), "utf8"));

test("names that go into the config of nginx refuse its syntax", () => {
	const domain = new RegExp(read("common.json").properties.domain_names.items.pattern, "u");
	const forwardHost = new RegExp(read("components/proxy-host-object.json").properties.forward_host.pattern, "u");
	const forwardDomain = new RegExp(
		read("components/redirection-host-object.json").properties.forward_domain_name.pattern,
	);
	for (const ok of ["example.com", "*.example.com", "пример.рф", "xn--e1afmkfd.xn--p1ai", "a_b.local", "example.*"]) {
		assert.ok(domain.test(ok), ok);
	}
	for (const bad of ["test.example.com AND 1=1 -- ", "x.com;return 418", "a.com{", "a.com#", "$host", "a b", "a'b"]) {
		assert.ok(!domain.test(bad), bad);
		assert.ok(!forwardHost.test(bad), bad);
		assert.ok(!forwardDomain.test(bad), bad);
	}
	for (const ok of ["127.0.0.1", "app", "[::1]", "backend.internal"]) assert.ok(forwardHost.test(ok), ok);
	assert.ok(!forwardHost.test("app/path"));
	assert.ok(forwardDomain.test("example.com/path"));
});
