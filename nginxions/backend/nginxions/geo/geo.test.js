import assert from "node:assert/strict";
import { test } from "node:test";
import { geoConf, geoOf, prepareHost } from "./index.js";

test("geo: the countries of a host are checked before they reach nginx", () => {
	assert.equal(geoOf(undefined), null);
	assert.equal(geoOf({ nginxions_geo: { mode: "off", countries: ["RU"] } }), null);
	assert.equal(geoOf({ nginxions_geo: { mode: "allow", countries: [] } }), null);
	assert.deepEqual(
		geoOf({ nginxions_geo: { mode: "allow", countries: ["ru", "BY", "RU", 'x"; evil', "RUS", ""] } }),
		{
			mode: "allow",
			countries: ["BY", "RU"],
			action: "403",
		},
	);
	assert.equal(geoOf({ nginxions_geo: { mode: "deny", countries: ["CN"], action: "444" } }).action, "444");
	assert.equal(geoOf({ nginxions_geo: { mode: "deny", countries: ["CN"], action: "200; evil" } }).action, "403");

	const host = { meta: { nginxions_geo: { mode: "allow", countries: ["RU", "BY"] } } };
	prepareHost("proxy_host", host);
	assert.deepEqual(host.nginxions_geo, { mode: "allow", pattern: "BY|RU", action: "403" });
	const off = { meta: {} };
	prepareHost("dead_host", off);
	assert.equal(off.nginxions_geo, null);
	// streams have no countries
	const stream = { meta: { nginxions_geo: { mode: "allow", countries: ["RU"] } } };
	prepareHost("stream", stream);
	assert.equal(stream.nginxions_geo, undefined);
});

test("geo: nginx knows the countries only with a database; without one the rules let everything in", () => {
	const withDb = geoConf("/data/nginxions/geoip/geoip.mmdb");
	assert.match(withDb, /geoip2 \/data\/nginxions\/geoip\/geoip\.mmdb \{/);
	assert.match(withDb, /\$nginxions_country country iso_code;/);
	assert.match(withDb, /map "" \$nginxions_geo_ready \{ default 1; \}/);
	const none = geoConf(null);
	assert.doesNotMatch(none, /geoip2/);
	assert.match(none, /map "" \$nginxions_country \{ default ""; \}/);
	assert.match(none, /map "" \$nginxions_geo_ready \{ default 0; \}/);
	for (const conf of [withDb, none]) assert.match(conf, /192\.168\.0\.0\/16 1;/);
});
