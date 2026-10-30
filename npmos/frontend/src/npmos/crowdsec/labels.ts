// Texts of CrowdSec values shared by the pages and modals.
import { intl } from "src/locale";
import { DURATIONS } from "./api";

export const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

/** "4h" → "4 hours"; durations the GUI does not offer stay as they are */
export const durationLabel = (d: string) =>
	DURATIONS.includes(d as (typeof DURATIONS)[number]) ? t(`npmos.crowdsec.duration.${d}`) : d;

/** remaining time of a decision as the LAPI gives it ("3h59m55.1s") → "3 h 59 min" */
export const remaining = (d: string) => {
	// a decision of an old alert ran out: the LAPI gives a negative duration ("-21h19m24s")
	if ((d || "").startsWith("-")) return t("npmos.crowdsec.left.expired");
	const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(d || "");
	if (!m) return d;
	const h = Number(m[1] || 0);
	const min = Number(m[2] || 0);
	// a ban "forever" (3650d) has years left
	if (h >= 24 * 365 * 5) return t("npmos.crowdsec.left.forever");
	if (h >= 48) return t("npmos.crowdsec.left.days", { days: Math.floor(h / 24) });
	if (h > 0) return t("npmos.crowdsec.left.hours", { hours: h, minutes: min });
	if (min > 0) return t("npmos.crowdsec.left.minutes", { minutes: min });
	return t("npmos.crowdsec.left.seconds", { seconds: Math.max(1, Math.floor(Number(m[3] || 0))) });
};

/** where a decision comes from */
export const originLabel = (origin: string) =>
	["crowdsec", "cscli", "lists", "appsec", "CAPI"].includes(origin) ? t(`npmos.crowdsec.origin.${origin}`) : origin;
