// Analytics: the traffic of the hosts and the attacks on them, after the Cloudflare dashboard (tabs Requests,
// Visitors, Performance, Security, Cache, Origin; KPI cards with sparklines; area charts; a world map; top lists that
// filter the page). Data: the request log of nginx (npmos/events/traffic.js) and the security events of open-appsec,
// CrowdSec and mTLS. "Now": the last hour, refreshed every few seconds, with what is happening now above it.
import { useQuery } from "@tanstack/react-query";
import { IconFilter, IconX } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { HasPermission, LoadingPage } from "src/components";
import { T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { getTraffic, type TrafficFilters } from "../../api";
import { countryName, formatBytes, formatMs } from "../../ui/charts/format";
import { Popover } from "../../ui/Popover";
import { dateTime } from "../../ui/time";
import hostStyles from "../Hosts/Hosts.module.css";
import eventStyles from "../WafEvents/Events.module.css";
import styles from "./Analytics.module.css";
import { FILTER_KEYS, PERIODS, t, TABS, useTrafficParams } from "./common";
import { LIVE_MS, LiveNow } from "./Live";
import { TAB_VIEWS } from "./tabs";

const VIEWS = ["live", ...PERIODS] as const;

/** fields of "Add filter" (those with a list of choices get a select) */
const FILTER_FIELDS: { key: keyof TrafficFilters; choices?: string[]; placeholder?: string }[] = [
	{ key: "host", placeholder: "example.com" },
	{ key: "country", placeholder: "DE" },
	{ key: "ip", placeholder: "203.0.113.7" },
	{ key: "path", placeholder: "/api/" },
	{ key: "status", placeholder: "404, 5xx" },
	{ key: "method", choices: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] },
	{ key: "device", choices: ["desktop", "mobile", "tablet", "bot", "other"] },
	{ key: "browser", placeholder: "Chrome" },
	{ key: "os", placeholder: "Windows" },
	{ key: "protocol", choices: ["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] },
	{ key: "cache", choices: ["HIT", "MISS", "EXPIRED", "BYPASS", "STALE"] },
	{ key: "origin", placeholder: "10.0.0.2:8080" },
	{ key: "originStatus", placeholder: "502, 5xx" },
	{ key: "referer", placeholder: "google.com" },
	{ key: "port", placeholder: "443" },
	{ key: "unknown", choices: ["1"] },
	{ key: "mitigated", choices: ["1", "0"] },
];

/** the value of a filter as shown in its chip */
export const filterValue = (key: keyof TrafficFilters, value: string) =>
	key === "country"
		? value
				.split(",")
				.map((c) => countryName(c.trim()))
				.join(", ")
		: key === "device"
			? value
					.split(",")
					.map((d) => t(`npmos.traffic.device.${d.trim()}`))
					.join(", ")
			: key === "unknown"
				? t("npmos.traffic.filter.unknown.yes")
				: key === "mitigated"
					? t(value === "1" ? "npmos.traffic.filter.mitigated.yes" : "npmos.traffic.filter.mitigated.no")
					: key === "minMs" || key === "maxMs"
						? formatMs(Number(value))
						: key === "minBytes" || key === "maxBytes"
							? formatBytes(Number(value))
							: value;

export const choiceLabel = (key: keyof TrafficFilters, value: string) =>
	key === "device" ? t(`npmos.traffic.device.${value}`) : filterValue(key, value);

export function AddFilter({ onAdd }: { onAdd: (key: keyof TrafficFilters, value: string) => void }) {
	const [key, setKey] = useState<keyof TrafficFilters>("host");
	const [value, setValue] = useState("");
	const field = FILTER_FIELDS.find((f) => f.key === key) ?? FILTER_FIELDS[0];
	return (
		<Popover
			ariaLabel={t("npmos.traffic.filter.add")}
			title={<T id="npmos.traffic.filter.add" />}
			width="20rem"
			triggerClassName={hostStyles.tool}
			activeClassName={hostStyles.toolOn}
			trigger={
				<>
					<IconFilter size={16} />
					<span className={hostStyles.toolText}>
						<T id="npmos.traffic.filter.add" />
					</span>
				</>
			}
		>
			{(close) => (
				<form
					className={styles.filterForm}
					onSubmit={(e) => {
						e.preventDefault();
						const v = field.choices && !value ? field.choices[0] : value.trim();
						if (!v) return;
						onAdd(key, v);
						setValue("");
						close();
					}}
				>
					<label htmlFor="npmos-traffic-filter-field" className="form-label small">
						<T id="npmos.traffic.filter.field" />
					</label>
					<select
						id="npmos-traffic-filter-field"
						className="form-select form-select-sm"
						value={key}
						onChange={(e) => {
							setKey(e.target.value as keyof TrafficFilters);
							setValue("");
						}}
					>
						{FILTER_FIELDS.map((f) => (
							<option key={f.key} value={f.key}>
								{t(`npmos.traffic.filter.${f.key}`)}
							</option>
						))}
					</select>
					<label htmlFor="npmos-traffic-filter-value" className="form-label small mt-2">
						<T id="npmos.traffic.filter.value" />
					</label>
					{field.choices ? (
						<select
							id="npmos-traffic-filter-value"
							className="form-select form-select-sm"
							value={value || field.choices[0]}
							onChange={(e) => setValue(e.target.value)}
						>
							{field.choices.map((c) => (
								<option key={c} value={c}>
									{choiceLabel(key, c)}
								</option>
							))}
						</select>
					) : (
						<input
							id="npmos-traffic-filter-value"
							className="form-control form-control-sm"
							placeholder={field.placeholder}
							value={value}
							autoComplete="off"
							onChange={(e) => setValue(e.target.value)}
						/>
					)}
					<div className="mt-3 text-end">
						<button type="submit" className="btn btn-sm btn-primary">
							<T id="npmos.traffic.filter.apply" />
						</button>
					</div>
				</form>
			)}
		</Popover>
	);
}

export function FilterChips({
	filters,
	remove,
	clear,
}: {
	filters: TrafficFilters;
	remove: (key: keyof TrafficFilters) => void;
	clear: () => void;
}) {
	// the search is shown in its field
	const keys = FILTER_KEYS.filter((k) => k !== "q" && filters[k]);
	if (!keys.length) return null;
	return (
		<div className={styles.chips}>
			{keys.map((k) => (
				<span key={k} className={styles.chip}>
					<span className={styles.chipKey}>{t(`npmos.traffic.filter.${k}`)}:</span>
					<span className={styles.chipValue}>{filterValue(k, String(filters[k]))}</span>
					<button
						type="button"
						className={styles.chipRemove}
						aria-label={t("npmos.traffic.filter.remove", { name: t(`npmos.traffic.filter.${k}`) })}
						onClick={() => remove(k)}
					>
						<IconX size={12} />
					</button>
				</span>
			))}
			<button type="button" className={styles.linkButton} onClick={clear}>
				<T id="npmos.traffic.filter.clear" />
			</button>
		</div>
	);
}

function AnalyticsPage() {
	const { live, period, tab, filters, set } = useTrafficParams();
	const { data, isLoading, isError, error, isFetching } = useQuery({
		queryKey: ["npmos-traffic", tab, period, filters],
		queryFn: () => getTraffic(tab, period, filters),
		refetchInterval: live ? LIVE_MS : 30000,
		placeholderData: (previous) => (previous?.tab === tab ? previous : undefined),
	});
	const View = TAB_VIEWS[tab];
	const filter = (key: keyof TrafficFilters, value: string) => set({ [key]: value });
	const clear = () => set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])));

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.analytics" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.traffic.description" />
					</p>
				</div>
			</div>

			<ul className="nav nav-tabs">
				{TABS.map((x) => (
					<li key={x} className="nav-item">
						<button
							type="button"
							className={cn("nav-link", { active: tab === x })}
							onClick={() => set({ tab: x === "requests" ? null : x })}
						>
							<T id={`npmos.traffic.tab.${x}`} />
						</button>
					</li>
				))}
			</ul>

			<div className={hostStyles.toolbar}>
				<AddFilter onAdd={filter} />
				<div className={eventStyles.periods} role="group" aria-label={t("npmos.events.period")}>
					{VIEWS.map((p) => {
						const on = p === "live" ? live : !live && period === p;
						return (
							<button
								key={p}
								type="button"
								className={cn(eventStyles.period, on && eventStyles.periodOn)}
								aria-pressed={on}
								onClick={() => set({ period: p === "24h" ? null : p })}
							>
								<T id={p === "live" ? "npmos.analytics.live" : `npmos.events.period.${p}`} />
							</button>
						);
					})}
				</div>
				{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
			</div>

			<FilterChips filters={filters} remove={(k) => set({ [k]: null })} clear={clear} />

			{live && <LiveNow host={filters.host ?? ""} />}

			{isLoading && !data ? (
				<LoadingPage noLogo />
			) : isError || !data ? (
				<Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>
			) : data.unsupported ? (
				<Alert variant="warning">
					<T id="npmos.traffic.unsupported" />
				</Alert>
			) : (
				<>
					{data.detailFrom && (
						<p className={styles.note}>
							<T
								id="npmos.traffic.detail-from"
								data={{ time: dateTime(data.detailFrom), days: data.requestDays }}
							/>
						</p>
					)}
					<View data={data} period={period} filter={filter} />
					<p className={styles.note}>
						<T id="npmos.traffic.note" />
					</p>
				</>
			)}
		</div>
	);
}

const WafAnalytics = () => (
	<HasPermission rbac="analytics" permission={VIEW} pageLoading loadingNoLogo>
		<AnalyticsPage />
	</HasPermission>
);

export default WafAnalytics;
