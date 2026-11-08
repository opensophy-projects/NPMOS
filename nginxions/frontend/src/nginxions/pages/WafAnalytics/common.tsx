// Parts of Analytics shared by its tabs: the period, tab and filters in the address (a link opens the same view),
// panels, top lists whose rows add a filter (the filter button of the Cloudflare lists), labels of the axis.
import cn from "classnames";
import { hasFlag } from "country-flag-icons";
// @ts-expect-error Creating a typing for a subfolder is not easily possible (as src/components/Flag.tsx)
import Flags from "country-flag-icons/react/3x2";
import { useSearchParams } from "react-router-dom";
import { intl } from "src/locale";
import type { AnalyticsPeriod, TopRow, TrafficFilters, TrafficTab } from "../../api";
import { BarList } from "../../ui/Charts";
import { InfoTip, infoOfNode } from "../../ui/InfoTip";
import chartStyles from "../../ui/charts/charts.module.css";
import { countryName, formatCount } from "../../ui/charts/format";
import styles from "./Analytics.module.css";

export const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export const PERIODS: AnalyticsPeriod[] = ["1h", "24h", "7d", "30d"];
export const TABS: TrafficTab[] = ["requests", "visitors", "performance", "security", "cache", "origin"];
export const FILTER_KEYS: (keyof TrafficFilters)[] = [
	"host",
	"country",
	"ip",
	"path",
	"status",
	"method",
	"browser",
	"os",
	"device",
	"client",
	"protocol",
	"tls",
	"cache",
	"contentType",
	"origin",
	"referer",
	"port",
	"originStatus",
	"minMs",
	"maxMs",
	"minBytes",
	"maxBytes",
	"unknown",
	"mitigated",
	"q",
];

/** tab, period and filters of the address */
export function useTrafficParams() {
	const [params, setParams] = useSearchParams();
	const live = params.get("period") === "live";
	const period: AnalyticsPeriod = live ? "1h" : (PERIODS.find((p) => p === params.get("period")) ?? "24h");
	const tab: TrafficTab = TABS.find((x) => x === params.get("tab")) ?? "requests";
	const filters: TrafficFilters = {};
	for (const key of FILTER_KEYS) {
		const v = params.get(key);
		if (v) filters[key] = v;
	}
	const set = (changes: Record<string, string | null>) => {
		const next = new URLSearchParams(params);
		for (const [key, value] of Object.entries(changes)) {
			if (value === null || value === "") next.delete(key);
			else next.set(key, value);
		}
		setParams(next, { replace: true });
	};
	return { live, period, tab, filters, set, params };
}

/** a bucket on the axis: time of day for a day or less, the date for longer periods */
export const bucketLabel = (iso: string, period: AnalyticsPeriod) =>
	period === "1h" || period === "24h"
		? intl.formatTime(iso, { hour: "2-digit", minute: "2-digit" })
		: period === "7d"
			? intl.formatDate(iso, { day: "numeric", month: "short", hour: "2-digit" })
			: intl.formatDate(iso, { day: "numeric", month: "short" });

export const bucketTitle = (iso: string) => intl.formatDate(iso, { dateStyle: "medium", timeStyle: "short" });

export function Panel({
	title,
	children,
	wide,
	action,
}: {
	title: React.ReactNode;
	children: React.ReactNode;
	wide?: boolean;
	action?: React.ReactNode;
}) {
	const info = infoOfNode(title);
	return (
		<section className={cn(styles.panel, wide && styles.wide)}>
			<div className={styles.panelHead}>
				<h3 className={styles.panelTitle}>
					{title}
					{info && <InfoTip id={info} />}
				</h3>
				{action}
			</div>
			{children}
		</section>
	);
}

export function Grid({ children }: { children: React.ReactNode }) {
	return <div className={styles.grid}>{children}</div>;
}

export function Section({ children }: { children: React.ReactNode }) {
	return <h2 className={styles.section}>{children}</h2>;
}

export function Country({ code }: { code: string }) {
	if (!code) return <>{t("nginxions.traffic.unknown")}</>;
	return (
		<span>
			{hasFlag(code) && <CountryFlag code={code} />}
			{countryName(code)}
		</span>
	);
}

/** flags of country-flag-icons as inline SVG (bundled, offline) */
function CountryFlag({ code }: { code: string }) {
	const FlagElement = (Flags as Record<string, React.ComponentType<{ className?: string; title?: string }>>)[code];
	return FlagElement ? <FlagElement className={chartStyles.flag} title={code} /> : null;
}

type Labeler = (value: string) => React.ReactNode;

/**
 * A top list: label, number, a bar; a click on a row filters the page by it.
 * metric: what the bars and numbers show
 */
export function TopList({
	rows,
	label = (v) => v,
	filter,
	metric = "requests",
	format,
	sub,
	limit = 10,
}: {
	rows: TopRow[] | undefined;
	label?: Labeler;
	/** the filter a click sets (key of the filters), none: the rows are not clickable */
	filter?: (value: string) => void;
	metric?: "requests" | "bytes" | "mitigated" | "pageviews" | "p95";
	format?: (n: number) => string;
	sub?: (row: TopRow) => React.ReactNode;
	limit?: number;
}) {
	return (
		<BarList
			emptyText={t("nginxions.traffic.no-data")}
			format={format ?? formatCount}
			items={(rows ?? []).slice(0, limit).map((r) => ({
				key: r.value,
				label: label(r.value),
				title: r.value,
				value: Number(r[metric] ?? 0),
				sub: sub?.(r),
				onClick: filter ? () => filter(r.value) : undefined,
			}))}
		/>
	);
}
