// Numbers of Analytics: compact counts (3,4 тыс.), sizes, milliseconds, shares, changes; countries by ISO code or by
// the English name GeoIP gives the events.
import { getLocale, intl } from "src/locale";

export const formatCount = (n: number | null | undefined) =>
	n === null || n === undefined ? "—" : intl.formatNumber(n, { notation: n >= 10000 ? "compact" : "standard" });

export const formatBytes = (n: number | null | undefined) => {
	if (n === null || n === undefined) return "—";
	const units = ["B", "KB", "MB", "GB", "TB"];
	let i = 0;
	let v = n;
	while (v >= 1024 && i < units.length - 1) {
		v /= 1024;
		i++;
	}
	return `${intl.formatNumber(v, { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`;
};

export const formatMs = (n: number | null | undefined) =>
	n === null || n === undefined
		? "—"
		: n >= 1000
			? `${intl.formatNumber(n / 1000, { maximumFractionDigits: 2 })} s`
			: `${intl.formatNumber(n, { maximumFractionDigits: 0 })} ms`;

export const formatPercent = (n: number | null | undefined, digits = 2) =>
	n === null || n === undefined
		? "—"
		: intl.formatNumber(n, { style: "percent", minimumFractionDigits: digits, maximumFractionDigits: digits });

/** "↗ 12,5 %" */
export const formatChange = (n: number | null | undefined) =>
	n === null || n === undefined || !Number.isFinite(n)
		? null
		: `${n >= 0 ? "↗" : "↘"} ${intl.formatNumber(Math.abs(n), { style: "percent", maximumFractionDigits: 1 })}`;

let names: { locale: string; display?: Intl.DisplayNames } = { locale: "" };

/** name of a country in the language of the interface */
export const countryName = (code: string) => {
	if (!code) return "";
	const locale = getLocale();
	if (names.locale !== locale) {
		try {
			names = { locale, display: new Intl.DisplayNames([locale], { type: "region" }) };
		} catch {
			names = { locale };
		}
	}
	try {
		return names.display?.of(code.toUpperCase()) ?? code;
	} catch {
		return code;
	}
};

let byEnglishName: Map<string, string> | null = null;

/** ISO code of a country given as a code ("DE") or as its English name ("Germany", what GeoIP gives events) */
export const countryCode = (value: string) => {
	if (/^[A-Za-z]{2}$/.test(value)) return value.toUpperCase();
	if (!byEnglishName) {
		byEnglishName = new Map();
		try {
			const en = new Intl.DisplayNames(["en"], { type: "region" });
			const A = 65;
			for (let i = 0; i < 26; i++) {
				for (let j = 0; j < 26; j++) {
					const code = String.fromCharCode(A + i, A + j);
					const name = en.of(code);
					if (name && name !== code) byEnglishName.set(name.toLowerCase(), code);
				}
			}
		} catch {
			// no names: only codes are matched
		}
		// the names of GeoLite2 that differ from those of Intl
		for (const [name, code] of [
			["united states", "US"],
			["russia", "RU"],
			["south korea", "KR"],
			["republic of korea", "KR"],
			["iran", "IR"],
			["vietnam", "VN"],
			["czechia", "CZ"],
			["türkiye", "TR"],
			["turkey", "TR"],
			["the netherlands", "NL"],
			["hong kong", "HK"],
			["republic of lithuania", "LT"],
			["republic of moldova", "MD"],
		] as const) {
			byEnglishName.set(name, code);
		}
	}
	return byEnglishName.get(value.toLowerCase()) ?? "";
};

/** a country of an event (English name or code) in the language of the interface */
export const eventCountry = (value: string) => {
	const code = countryCode(value);
	return code ? countryName(code) : value;
};
