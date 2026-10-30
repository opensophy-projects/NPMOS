import { describe, expect, it } from "vitest";
import {
	activeCount,
	DEFAULT_FILTERS,
	filtersFromParams,
	filtersToParams,
	filtersToQuery,
	withoutValue,
	withValue,
} from "./filters";

describe("event filters", () => {
	it("defaults: attacks of the last 24 h, nothing in the URL", () => {
		const f = filtersFromParams(new URLSearchParams(""));
		expect(f).toEqual(DEFAULT_FILTERS);
		expect(filtersToParams(f).toString()).toBe("");
		expect(filtersToQuery(f)).toEqual({ kind: "agents", period: "24h" });
	});

	it("round trip through the URL, other parameters kept", () => {
		const f = {
			...DEFAULT_FILTERS,
			period: "7d" as const,
			kind: "all" as const,
			important: true,
			q: "union select",
			host: ["app.example.com"],
			ip: ["203.0.113.7", "198.51.100.1"],
			action: ["Prevent"],
			severity: ["Critical", "High"],
			type: ["SQL Injection"],
			minScore: "6",
			maxScore: "9.5",
		};
		const params = filtersToParams(f, new URLSearchParams("tab=x"));
		expect(params.get("tab")).toBe("x");
		expect(params.get("ip")).toBe("203.0.113.7,198.51.100.1");
		expect(filtersFromParams(params)).toEqual(f);
		expect(filtersToQuery(f)).toEqual({
			kind: "all",
			period: "7d",
			important: true,
			q: "union select",
			host: "app.example.com",
			ip: "203.0.113.7,198.51.100.1",
			action: "Prevent",
			severity: "Critical,High",
			type: "SQL Injection",
			minScore: "6",
			maxScore: "9.5",
		});
		expect(activeCount(f)).toBe(10);
	});

	it("custom period needs a start; bad values are dropped", () => {
		expect(filtersFromParams(new URLSearchParams("period=custom")).period).toBe("24h");
		const custom = filtersFromParams(new URLSearchParams("period=custom&from=2026-10-27T00:00:00.000Z"));
		expect(filtersToQuery(custom)).toEqual({ kind: "agents", from: "2026-10-27T00:00:00.000Z" });
		const bad = filtersFromParams(new URLSearchParams("period=year&kind=x&min=abc&max=99999&from=no"));
		expect([bad.period, bad.kind, bad.minScore, bad.maxScore, bad.from]).toEqual(["24h", "agents", "", "", ""]);
	});

	it("values are added once and removed", () => {
		const one = withValue(DEFAULT_FILTERS, "ip", "203.0.113.7");
		expect(withValue(one, "ip", "203.0.113.7")).toBe(one);
		expect(withoutValue(one, "ip", "203.0.113.7").ip).toEqual([]);
	});
	it("opens links of before (kind=crowdsec) as the agents filtered by one agent", () => {
		const f = filtersFromParams(new URLSearchParams("kind=crowdsec"));
		expect([f.kind, f.agent]).toEqual(["agents", ["crowdsec"]]);
		expect(filtersToQuery(f)).toMatchObject({ kind: "agents", agent: "crowdsec" });
	});
});
