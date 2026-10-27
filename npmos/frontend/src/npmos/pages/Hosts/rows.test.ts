import { describe, expect, it } from "vitest";
import {
	emptyFilters,
	exportData,
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

	it("filters by search and facets", () => {
		const f = (patch: object) => rows.filter((r) => matches(r, { ...emptyFilters(), ...patch })).map((r) => r.key);
		expect(f({ q: "10.0.0.6" })).toEqual(["proxy-2"]);
		expect(f({ q: "5432" })).toEqual(["stream-4"]);
		expect(f({ type: ["redirect", "dead"] })).toEqual(["redirect-3", "dead-5"]);
		expect(f({ tls: ["expiring"] })).toEqual(["proxy-2"]);
		expect(f({ tls: ["none"] })).toEqual(["redirect-3", "stream-4", "dead-5"]);
		expect(f({ waf: ["off"] })).toEqual(["proxy-2"]);
		expect(f({ access: ["7"] })).toEqual(["proxy-2"]);
		expect(f({ status: ["error", "disabled"] })).toEqual(["proxy-2", "stream-4"]);
		expect(f({ group: ["prod"] })).toEqual(["proxy-1"]);
	});

	it("keeps filters in the URL", () => {
		const filters = { ...emptyFilters(), q: "app", type: ["proxy" as const], waf: ["off" as const] };
		const params = filtersToParams(filters, new URLSearchParams("sort=tls"));
		expect(params.toString()).toBe("sort=tls&q=app&type=proxy&waf=off");
		expect(filtersFromParams(params)).toEqual(filters);
		expect(filtersFromParams(new URLSearchParams("type=bogus,stream")).type).toEqual(["stream"]);
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
});
