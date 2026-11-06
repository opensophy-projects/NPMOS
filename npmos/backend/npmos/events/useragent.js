// Browser, operating system and device type of a User-Agent for Analytics (Top browsers, operating systems, device
// types). A few rules in order, no database of agents: names stay stable across updates and nothing is fetched.

/** [name, rule] — the first match wins, so the more specific ones come first */
const BROWSERS = [
	[
		"Bot",
		/bot\b|crawl|spider|slurp|bingpreview|facebookexternalhit|curl\/|wget\/|python-|go-http|java\/|httpclient|okhttp|libwww|scrapy|headless/i,
	],
	["Edge", /edg(e|a|ios)?\//i],
	["Opera", /opr\/|opera/i],
	["Yandex Browser", /yabrowser\//i],
	["Samsung Internet", /samsungbrowser\//i],
	["Vivaldi", /vivaldi\//i],
	["Firefox", /firefox\/|fxios\//i],
	["Chrome", /chrome\/|crios\//i],
	["Safari", /version\/[\d.]+.*safari\//i],
];

const SYSTEMS = [
	["Android", /android/i],
	["iOS", /iphone|ipad|ipod|ios /i],
	["Windows", /windows/i],
	["macOS", /mac os x|macintosh/i],
	["ChromeOS", /cros /i],
	["Linux", /linux|x11/i],
];

/**
 * @param {string} ua  User-Agent header
 * @returns {{browser: string, os: string, device: "desktop"|"mobile"|"tablet"|"bot"|"other"}}
 */
export const parseUserAgent = (ua) => {
	const text = String(ua || "");
	if (!text || text === "-") return { browser: "", os: "", device: "other" };
	const browser = BROWSERS.find(([, re]) => re.test(text))?.[0] ?? "Other";
	const os = SYSTEMS.find(([, re]) => re.test(text))?.[0] ?? "Other";
	let device = "desktop";
	if (browser === "Bot") device = "bot";
	else if (/ipad|tablet|kindle|silk|(android(?!.*mobile))/i.test(text)) device = "tablet";
	else if (/mobi|iphone|ipod|android|phone/i.test(text)) device = "mobile";
	else if (os === "Other") device = "other";
	return { browser, os, device };
};
