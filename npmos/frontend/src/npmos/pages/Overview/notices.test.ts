import { describe, expect, it } from "vitest";
import { certificateNotices, hostNotices, serviceNotices, sortNotices, wafNotices } from "./notices";

const NOW = Date.parse("2026-10-27T00:00:00Z");
const DAY = 24 * 60 * 60 * 1000;
const cert = (id: number, provider: string, days: number) =>
	({
		id,
		provider,
		niceName: `c${id}`,
		domainNames: [],
		expiresOn: new Date(NOW + days * DAY + 1000).toISOString(),
	}) as any;

describe("overview notices", () => {
	it("warns about certificates by kind, skips the ones of hosts", () => {
		const notices = certificateNotices(
			[
				cert(1, "other", 3),
				cert(2, "letsencrypt", 10),
				cert(3, "letsencrypt", 2),
				cert(4, "mtls", -1),
				cert(5, "other", 1),
			],
			[5, 4],
			NOW,
		);
		expect(notices.map((n) => [n.key, n.level, n.id])).toEqual([
			["cert-1", "warning", "npmos.overview.notice.cert-expiring"],
			["cert-3", "warning", "npmos.overview.notice.cert-expiring"],
			// a CA of hosts is listed: the host notices know nothing about mTLS CAs
			["cert-4", "alert", "npmos.overview.notice.ca-expired"],
		]);
	});

	it("collects WAF, services and host problems, alerts first", () => {
		const waf = wafNotices({
			enabled: true,
			active: true,
			restartRequired: true,
			agent: { reachable: false },
			policy: { file: "", generatedAt: null, hosts: 0, applied: { ok: false, at: "", error: "bad" } },
		});
		expect(waf.map((n) => n.key)).toEqual(["waf-agent", "waf-policy", "waf-restart"]);
		expect(wafNotices({ enabled: false, active: false, restartRequired: true })).toEqual([]);
		const services = serviceNotices([
			{ service: "a", name: "a", state: "running", status: "Up 1 hour (healthy)" },
			{ service: "b", name: "b", state: "running", status: "Up 1 hour (unhealthy)" },
			{ service: "c", name: "c", state: "exited", status: "Exited (1)" },
		] as any);
		expect(services.map((n) => n.key)).toEqual(["service-b", "service-c"]);
		const hosts = hostNotices([
			{ id: "waf-detect", level: "info", rows: [], filter: [] },
			{ id: "no-tls", level: "warning", rows: [{} as any], filter: [{ field: "tls", op: "is", value: "none" }] },
		]);
		expect(hosts).toEqual([
			{
				key: "hosts-no-tls",
				level: "warning",
				id: "npmos.hosts.rec.no-tls",
				data: { count: 1 },
				link: "/hosts?f=tls%3Ais%3Anone",
			},
		]);
		expect(sortNotices([...hosts, ...services]).map((n) => n.level)).toEqual(["alert", "alert", "warning"]);
	});
});
