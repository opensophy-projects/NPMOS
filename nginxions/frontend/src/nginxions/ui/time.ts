// "5 minutes ago" in the language of the interface
import { intl } from "src/locale";

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
	["year", 365 * 24 * 3600],
	["month", 30 * 24 * 3600],
	["day", 24 * 3600],
	["hour", 3600],
	["minute", 60],
];

/** `narrow`: "14 h ago" for table cells */
export function timeAgo(date: string | number | Date, now = Date.now(), style: "long" | "narrow" = "long"): string {
	const seconds = Math.round((new Date(date).getTime() - now) / 1000);
	for (const [unit, size] of UNITS) {
		if (Math.abs(seconds) >= size) {
			return intl.formatRelativeTime(Math.round(seconds / size), unit, { numeric: "auto", style });
		}
	}
	return intl.formatRelativeTime(0, "minute", { numeric: "auto", style });
}

export const dateTime = (date: string | number | Date) =>
	intl.formatDate(date, { dateStyle: "medium", timeStyle: "short" });
