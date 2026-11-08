import { describe, expect, it } from "vitest";
import {
	exportData,
	type FilterRule,
	filtersFromParams,
	filtersToParams,
	matches,
	parseImport,
	recommendations,
	sortRows,
	toRows,
} from "./rows";

const NOW = Date.parse("2026-10-27T00:00:00Z");
const DAY = 24 * 60 * 60 * 1000;

const cert = (id: number, provider: string, days: number) =>
	({
		id,
		provider,
		niceName: `cert-${id}`,
		domainNames: [],
		expiresOn: new Date(NOW + days * DAY + 1000).toISOString(),
	}) as any;

const sources = {
	proxy: [
		{
			id: 1,
			enabled: true,
			domainNames: ["app.example.com", "www.app.example.com"],
			forwardScheme: "http",
			forwardHost: "10.0.0.5",
			forwardPort: 8080,
			npmplusAccessListType: "public",
			npmplusAccessListIds: [],
			certificate: cert(10, "letsencrypt", 60),
			accessListId: 0,
			locations: null,
			meta: { nginxOnline: true, npmplusMtlsCertificateId: 20, directory: "prod" },
			modifiedOn: "",
		},
		{
			id: 2,
			enabled: true,
			domainNames: ["admin.example.com"],
			forwardScheme: "https",
			forwardHost: "10.0.0.6",
			forwardPort: 443,
			npmplusAccessListType: "custom",
			npmplusAccessListIds: [7],
			certificate: cert(11, "other", 5),
			meta: {
				nginxOnline: false,
				nginxErr: "bad",
				npmplusMtlsCertificateId: 20,
				npmplusMtlsVerifyClientOptional: true,
			},
			modifiedOn: "",
		},
	],
	redirect: [
		{
			id: 3,
			enabled: true,
			domainNames: ["old.example.com"],
			forwardScheme: "$scheme",
			forwardDomainName: "new.example.com",
			forwardHttpCode: 301,
			meta: { nginxOnline: true },
			modifiedOn: "",
		},
	],
	stream: [
		{
			id: 4,
			enabled: false,
			incomingPort: 5432,
			forwardingHost: "db",
			forwardingPort: 5432,
			tcpForwarding: true,
			udpForwarding: false,
			meta: {},
			modifiedOn: "",
		},
	],
	dead: [{ id: 5, enabled: true, domainNames: ["junk.example.com"], meta: {}, modifiedOn: "" }],
	waf: { 1: { enabled: true, mode: "prevent-learn", minimumConfidence: "high" } },
} as any;

describe("hosts rows", () => {
	const rows = toRows(sources, NOW);
	const byId = (key: string) => {
		const row = rows.find((r) => r.key === key);
		if (!row) throw new Error(key);
		return row;
	};

	it("maps every host type", () => {
		expect(rows.map((r) => r.key)).toEqual(["proxy-1", "proxy-2", "redirect-3", "stream-4", "dead-5"]);
		expect(byId("redirect-3").target).toBe("301 → new.example.com");
		expect(byId("stream-4").names).toEqual([":5432"]);
		expect(byId("stream-4").protocols).toEqual(["tcp"]);
	});

	it("derives status, TLS, WAF, mTLS and access", () => {
		const a = byId("proxy-1");
		expect([a.status, a.tls, a.expiresInDays, a.waf, a.mtls, a.accessPublic, a.group]).toEqual([
			"online",
			"letsencrypt",
			60,
			"prevent",
			"required",
			true,
			"prod",
		]);
		const b = byId("proxy-2");
		expect([b.status, b.tls, b.waf, b.mtls, b.accessPublic]).toEqual(["error", "custom", "off", "optional", false]);
		expect(byId("stream-4").status).toBe("disabled");
		expect(byId("redirect-3").waf).toBeNull();
	});

	it("filters by search and rules", () => {
		const f = (q: string, rules: [string, string, string][] = []) =>
			rows
				.filter((r) =>
					matches(r, { q, rules: rules.map(([field, op, value]) => ({ field, op, value }) as FilterRule) }),
				)
				.map((r) => r.key);
		expect(f("10.0.0.6")).toEqual(["proxy-2"]);
		expect(f("5432")).toEqual(["stream-4"]);
		// "is" on one field: alternatives
		expect(
			f("", [
				["type", "is", "redirect"],
				["type", "is", "dead"],
			]),
		).toEqual(["redirect-3", "dead-5"]);
		expect(
			f("", [
				["type", "not", "proxy"],
				["type", "not", "stream"],
			]),
		).toEqual(["redirect-3", "dead-5"]);
		expect(f("", [["tls", "is", "expiring"]])).toEqual(["proxy-2"]);
		expect(f("", [["tls", "is", "none"]])).toEqual(["redirect-3", "stream-4", "dead-5"]);
		expect(f("", [["waf", "is", "off"]])).toEqual(["proxy-2"]);
		expect(f("", [["access", "is", "7"]])).toEqual(["proxy-2"]);
		expect(
			f("", [
				["status", "is", "error"],
				["status", "is", "disabled"],
			]),
		).toEqual(["proxy-2", "stream-4"]);
		expect(f("", [["group", "is", "prod"]])).toEqual(["proxy-1"]);
		expect(f("", [["name", "has", "admin"]])).toEqual(["proxy-2"]);
		expect(f("", [["name", "nothas", "example"]])).toEqual(["stream-4"]);
		expect(f("", [["target", "has", "new.example"]])).toEqual(["redirect-3"]);
		// rules on different fields: all must hold
		expect(
			f("", [
				["type", "is", "proxy"],
				["waf", "is", "prevent"],
			]),
		).toEqual(["proxy-1"]);
	});

	it("keeps filters in the URL", () => {
		const filters = {
			q: "app",
			rules: [
				{ field: "type", op: "is", value: "proxy" },
				{ field: "target", op: "has", value: "http://10.0.0.5:8080" },
			] as FilterRule[],
		};
		const params = filtersToParams(filters, new URLSearchParams("sort=tls"));
		expect(params.getAll("f")).toEqual(["type:is:proxy", "target:has:http://10.0.0.5:8080"]);
		expect(params.get("sort")).toBe("tls");
		expect(filtersFromParams(params)).toEqual(filters);
		// unknown fields, wrong operators and empty values are dropped
		expect(
			filtersFromParams(new URLSearchParams("f=bogus:is:x&f=type:has:proxy&f=waf:is:&f=waf:not:off")).rules,
		).toEqual([{ field: "waf", op: "not", value: "off" }]);
		// old links: ?type=proxy
		expect(filtersFromParams(new URLSearchParams("type=proxy&type=bogus")).rules).toEqual([
			{ field: "type", op: "is", value: "proxy" },
		]);
		expect(filtersToParams(filters, new URLSearchParams("type=dead")).has("type")).toBe(false);
	});

	it("sorts", () => {
		expect(sortRows(rows, { key: "tls", desc: false }).map((r) => r.key)[0]).toBe("proxy-2");
		expect(sortRows(rows, { key: "name", desc: false }).map((r) => r.key)).toEqual([
			"proxy-2",
			"proxy-1",
			"dead-5",
			"redirect-3",
			"stream-4",
		]);
	});

	it("recommends", () => {
		const recs = Object.fromEntries(recommendations(rows, false).map((r) => [r.id, r.rows.map((x) => x.key)]));
		expect(recs).toEqual({
			"nginx-error": ["proxy-2"],
			expiring: ["proxy-2"],
			"no-tls": ["redirect-3", "dead-5"],
			"waf-global-off": ["proxy-1"],
		});
	});

	it("exports without state and imports with unknown references dropped", () => {
		const file = exportData(rows);
		const proxy = file.hosts[0].data;
		expect(proxy.id).toBeUndefined();
		expect(proxy.certificate).toBeUndefined();
		expect(proxy.meta.nginxOnline).toBeUndefined();
		expect(proxy.meta.directory).toBe("prod");
		expect(proxy.accessListId).toBeUndefined();
		expect("locations" in proxy).toBe(false);
		proxy.certificateId = 10;
		file.hosts[1].data.certificateId = 11;
		const { items, dropped } = parseImport(JSON.stringify(file), { certificateIds: [10], accessListIds: [] });
		expect(items).toHaveLength(5);
		expect(items[0].data.certificateId).toBe(10);
		expect(items[1].data.certificateId).toBe(0);
		expect(items[1].data.npmplusAccessListIds).toEqual([]);
		// mTLS CA 20 twice, certificate 11, access list 7
		expect(dropped).toBe(4);
		expect(() => parseImport("{}", { certificateIds: [], accessListIds: [] })).toThrow();
	});

	it("joins upstream checks and audit changes to the rows", () => {
		const joined = toRows(
			{
				...sources,
				upstreams: [
					{ type: "proxy-host", objectId: 1, host: "10.0.0.5", port: 8080, ok: true, ms: 1 },
					{ type: "proxy-host", objectId: 2, host: "10.0.0.6", port: 443, ok: false, error: "timeout" },
					// a stream with the same id is another host
					{ type: "stream", objectId: 1, host: "x", port: 1, ok: false, error: "ECONNREFUSED" },
				],
				changes: [
					{
						type: "proxy-host",
						objectId: 2,
						id: 9,
						action: "updated",
						createdOn: "2026-10-26T00:00:00Z",
						user: null,
						fields: [],
					},
					{
						type: "proxy-host",
						objectId: 1,
						id: 8,
						action: "created",
						createdOn: "2026-10-20T00:00:00Z",
						user: null,
						fields: [],
					},
				],
			},
			NOW,
		);
		const byKey = Object.fromEntries(joined.map((r) => [r.key, r]));
		expect(byKey["proxy-1"].upstream).toBe("ok");
		expect(byKey["proxy-2"].upstream).toBe("down");
		expect(byKey["proxy-2"].upstreamErrors).toEqual(["10.0.0.6:443 — timeout"]);
		expect(byKey["redirect-3"].upstream).toBeNull();
		expect(matches(byKey["proxy-2"], { q: "", rules: [{ field: "upstream", op: "is", value: "down" }] })).toBe(
			true,
		);
		expect(
			recommendations(joined, true)
				.find((r) => r.id === "upstream-down")
				?.rows.map((r) => r.key),
		).toEqual(["proxy-2"]);
		const newest = sortRows(joined, { key: "changed", desc: false }).map((r) => r.key);
		expect(newest.slice(0, 2)).toEqual(["proxy-2", "proxy-1"]);
	});
});
