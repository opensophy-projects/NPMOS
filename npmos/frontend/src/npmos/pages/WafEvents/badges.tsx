import cn from "classnames";
import { useLocaleState } from "src/context";
import { formatDateTime } from "src/locale";

const SEVERITY: Record<string, string> = {
	// alerts are red, warnings yellow, the rest neutral (the accent is for actions)
	critical: "bg-red text-red-fg",
	high: "bg-red-lt",
	medium: "bg-yellow-lt",
	low: "bg-secondary-lt",
	info: "bg-secondary-lt",
};

/** severity and action are the agent's own terms (Critical, Prevent, ...), not translated */
export function SeverityBadge({ severity }: { severity: string }) {
	if (!severity) return null;
	return <span className={cn("badge", SEVERITY[severity.toLowerCase()] || "bg-secondary-lt")}>{severity}</span>;
}

export function ActionBadge({ action }: { action: string }) {
	if (!action) return null;
	const a = action.toLowerCase();
	return (
		<span
			className={cn(
				"badge",
				"text-white",
				a === "prevent" ? "bg-red" : a === "detect" ? "bg-orange" : "bg-secondary",
			)}
		>
			{action}
		</span>
	);
}

/** agent time in the interface language */
export function EventTime({ time }: { time: string | null }) {
	const { locale } = useLocaleState();
	return <>{time ? formatDateTime(time, locale) : "—"}</>;
}
