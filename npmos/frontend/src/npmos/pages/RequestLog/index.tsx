// Analytics → Requests: every request of the hosts from the request log of nginx, newest first, with the filters of
// Analytics (host, country, IP, path, status, …). Requests to names that are not hosts of NPMOS are marked: they
// are answered by the default site and were invisible before (only security events were listed).
import { useInfiniteQuery } from "@tanstack/react-query";
import cn from "classnames";
import { Fragment, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { HasPermission, LoadingPage } from "src/components";
import { T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { getRequestLog, type RequestLogRow, type TrafficFilters } from "../../api";
import { countryName, formatBytes, formatMs } from "../../ui/charts/format";
import { dateTime } from "../../ui/time";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../WafAnalytics/Analytics.module.css";
import { Country, FILTER_KEYS, PERIODS, t, useTrafficParams } from "../WafAnalytics/common";
import { AddFilter, FilterChips } from "../WafAnalytics/index";
import eventStyles from "../WafEvents/Events.module.css";
import logStyles from "./RequestLog.module.css";

const PERIOD_MS = { "1h": 3600e3, "24h": 86400e3, "7d": 7 * 86400e3, "30d": 30 * 86400e3 } as const;
const PAGE = 100;

const statusTone = (s: number) =>
	s >= 500 ? logStyles.s5 : s >= 400 ? logStyles.s4 : s >= 300 ? logStyles.s3 : logStyles.s2;

function Details({ r }: { r: RequestLogRow }) {
	const items: [string, React.ReactNode][] = [
		["npmos.traffic.log.time", dateTime(r.time)],
		["npmos.traffic.filter.host", `${r.host || "—"}${r.port ? `:${r.port}` : ""}`],
		["npmos.traffic.filter.ip", r.ip],
		["npmos.traffic.filter.country", r.country ? countryName(r.country) : "—"],
		["npmos.traffic.log.request", `${r.method} ${r.path}`],
		["npmos.traffic.filter.status", r.status],
		["npmos.traffic.log.size", `${formatBytes(r.bytes)} / ${formatBytes(r.requestBytes)}`],
		["npmos.traffic.log.duration", formatMs(r.durationMs)],
		["npmos.traffic.filter.origin", r.upstreamAddr || "—"],
		["npmos.traffic.log.origin-status", r.upstreamStatus ?? "—"],
		["npmos.traffic.log.origin-time", formatMs(r.upstreamMs)],
		["npmos.traffic.filter.cache", r.cache || "—"],
		["npmos.traffic.filter.protocol", `${r.protocol}${r.tls ? ` · ${r.tls}` : ""}`],
		["npmos.traffic.filter.contentType", r.contentType || "—"],
		["npmos.traffic.log.referer", r.refererHost || "—"],
		["npmos.traffic.log.agent", r.userAgent || "—"],
	];
	return (
		<dl className={logStyles.details}>
			{items.map(([id, v]) => (
				<Fragment key={id}>
					<dt>{t(id)}</dt>
					<dd>{v}</dd>
				</Fragment>
			))}
		</dl>
	);
}

function RequestLogPage() {
	const { period, filters, set } = useTrafficParams();
	const [open, setOpen] = useState<string | null>(null);
	const query = useInfiniteQuery({
		queryKey: ["npmos-request-log", period, filters],
		queryFn: ({ pageParam }) =>
			getRequestLog({
				...filters,
				from: new Date(Date.now() - PERIOD_MS[period]).toISOString(),
				limit: PAGE,
				...(pageParam ? { before: pageParam } : {}),
			}),
		initialPageParam: "",
		getNextPageParam: (last) => last.next ?? undefined,
		refetchInterval: 15000,
	});
	const rows = query.data?.pages.flatMap((p) => p.rows) ?? [];
	const filter = (key: keyof TrafficFilters, value: string) => set({ [key]: value });

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.traffic.log" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.traffic.log.description" />
					</p>
				</div>
			</div>
			<div className={hostStyles.toolbar}>
				<div className={eventStyles.periods} role="group" aria-label={t("npmos.events.period")}>
					{PERIODS.map((p) => (
						<button
							key={p}
							type="button"
							className={cn(eventStyles.period, period === p && eventStyles.periodOn)}
							aria-pressed={period === p}
							onClick={() => set({ period: p === "24h" ? null : p })}
						>
							<T id={`npmos.events.period.${p}`} />
						</button>
					))}
				</div>
				<AddFilter onAdd={filter} />
				<button
					type="button"
					className={cn(hostStyles.tool, filters.unknown && hostStyles.toolOn)}
					aria-pressed={!!filters.unknown}
					onClick={() => set({ unknown: filters.unknown ? null : "1" })}
				>
					<T id="npmos.traffic.log.only-unknown" />
				</button>
				{query.isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
			</div>
			<FilterChips
				filters={filters}
				remove={(k) => set({ [k]: null })}
				clear={() => set(Object.fromEntries(FILTER_KEYS.map((k) => [k, null])))}
			/>
			{query.isLoading ? (
				<LoadingPage noLogo />
			) : query.isError ? (
				<Alert variant="danger">{query.error.message}</Alert>
			) : query.data?.pages[0]?.unsupported ? (
				<Alert variant="warning">
					<T id="npmos.traffic.unsupported" />
				</Alert>
			) : (
				<div className="card">
					<div className={hostStyles.scroller}>
						<table className={cn("table table-vcenter card-table", hostStyles.table, logStyles.table)}>
							<thead>
								<tr>
									<th>
										<T id="npmos.traffic.log.time" />
									</th>
									<th>
										<T id="npmos.traffic.filter.host" />
									</th>
									<th>
										<T id="npmos.traffic.log.client" />
									</th>
									<th>
										<T id="npmos.traffic.log.request" />
									</th>
									<th className="text-end">
										<T id="npmos.traffic.filter.status" />
									</th>
									<th className="text-end">
										<T id="npmos.traffic.log.size" />
									</th>
									<th className="text-end">
										<T id="npmos.traffic.log.duration" />
									</th>
									<th>
										<T id="npmos.traffic.log.agent" />
									</th>
								</tr>
							</thead>
							<tbody>
								{rows.length === 0 ? (
									<tr>
										<td colSpan={8} className="text-center text-secondary py-4">
											<T id="npmos.traffic.log.empty" />
										</td>
									</tr>
								) : (
									rows.map((r) => (
										<Fragment key={r.id}>
											<tr
												className={cn(eventStyles.row, open === r.id && logStyles.open)}
												onClick={() => setOpen(open === r.id ? null : r.id)}
											>
												<td className={logStyles.time}>{dateTime(r.time)}</td>
												<td className={logStyles.host}>
													<button
														type="button"
														className={styles.linkButton}
														onClick={(e) => {
															e.stopPropagation();
															filter("host", r.host);
														}}
													>
														{r.host === "_" || !r.host
															? t("npmos.traffic.host.none")
															: r.host}
													</button>
													{!r.known && (
														<span className={cn(styles.unknown, logStyles.mark)}>
															{t("npmos.traffic.host.unknown")}
														</span>
													)}
												</td>
												<td className={logStyles.client}>
													<button
														type="button"
														className={styles.linkButton}
														onClick={(e) => {
															e.stopPropagation();
															filter("ip", r.ip);
														}}
													>
														{r.ip}
													</button>
													{r.country && (
														<span className={logStyles.country}>
															<Country code={r.country} />
														</span>
													)}
												</td>
												<td className={logStyles.request} title={r.path}>
													<span className={eventStyles.method}>{r.method}</span>
													{r.path}
												</td>
												<td className="text-end">
													<span className={cn(logStyles.status, statusTone(r.status))}>
														{r.status}
													</span>
												</td>
												<td className="text-end text-nowrap">{formatBytes(r.bytes)}</td>
												<td className="text-end text-nowrap">{formatMs(r.durationMs)}</td>
												<td className={logStyles.agent} title={r.userAgent}>
													{r.device === "bot" || !r.browser
														? r.userAgent || "—"
														: `${r.browser} · ${r.os} · ${t(`npmos.traffic.device.${r.device}`)}`}
												</td>
											</tr>
											{open === r.id && (
												<tr className={logStyles.detailRow}>
													<td colSpan={8}>
														<Details r={r} />
													</td>
												</tr>
											)}
										</Fragment>
									))
								)}
							</tbody>
						</table>
					</div>
					{query.hasNextPage && (
						<div className="p-3 text-center">
							<button
								type="button"
								className="btn btn-sm"
								disabled={query.isFetchingNextPage}
								onClick={() => query.fetchNextPage()}
							>
								<T id="npmos.traffic.log.more" />
							</button>
						</div>
					)}
				</div>
			)}
		</div>
	);
}

const RequestLog = () => (
	<HasPermission rbac="analytics" permission={VIEW} pageLoading loadingNoLogo>
		<RequestLogPage />
	</HasPermission>
);

export default RequestLog;
