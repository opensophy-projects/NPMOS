// Events → Requests: every request of the hosts from the request log of nginx, newest first. The toolbar is the one
// of the other kinds of Events (search, period with a range of dates, filters, export, retention); the filters cover
// every field of the log. Requests to names that are not hosts of NginxionS are marked: they are answered by the
// default site and were invisible before (only security events were listed).
import { IconChevronLeft, IconChevronRight, IconDownload } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import { useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useNavigate, useSearchParams } from "react-router-dom";
import { LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showError } from "src/notifications";
import { downloadRequests, getRequestLog, type TrafficFilters } from "../../api";
import { hostLabel, showRequestModal, statusTone } from "../../modals/RequestModal";
import { useCan } from "../../rbac/hooks";
import { formatBytes, formatMs } from "../../ui/charts/format";
import { DateTimePicker } from "../../ui/DateTimePicker";
import { Dropdown } from "../../ui/Dropdown";
import { Label } from "../../ui/InfoTip";
import { SearchField } from "../../ui/SearchField";
import { dateTime } from "../../ui/time";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../WafAnalytics/Analytics.module.css";
import { Country, FILTER_KEYS, t } from "../WafAnalytics/common";
import { FilterChips } from "../WafAnalytics/index";
import eventStyles from "../WafEvents/Events.module.css";
import { PERIODS, type Period } from "../WafEvents/filters";
import { RetentionPopover } from "../WafEvents/Retention";
import { RequestFilters } from "./Filters";
import logStyles from "./RequestLog.module.css";

const PERIOD_MS: Record<Exclude<Period, "custom">, number> = {
	"1h": 3600e3,
	"24h": 86400e3,
	"7d": 7 * 86400e3,
	"30d": 30 * 86400e3,
};
const PAGE = 100;

/** period, range and filters of the address (the same names as the other kinds of Events and Analytics) */
function useRequestParams() {
	const [params, setParams] = useSearchParams();
	const period: Period = PERIODS.find((p) => p === params.get("period")) ?? "24h";
	const from = period === "custom" ? params.get("from") || "" : "";
	const to = period === "custom" ? params.get("to") || "" : "";
	const key = params.toString();
	// biome-ignore lint/correctness/useExhaustiveDependencies: the filters change with the address only
	const filters = useMemo(() => {
		const f: TrafficFilters = {};
		for (const k of FILTER_KEYS) {
			const v = params.get(k);
			if (v) f[k] = v;
		}
		return f;
	}, [key]);
	const set = (changes: Record<string, string | null>) => {
		const next = new URLSearchParams(params);
		for (const [k, v] of Object.entries(changes)) {
			if (v === null || v === "") next.delete(k);
			else next.set(k, v);
		}
		setParams(next, { replace: true });
	};
	return { period: period === "custom" && !from ? ("24h" as Period) : period, from, to, filters, set };
}

/** time of a row: the day and the time to the second, without the year (the log keeps days, not years) */
const rowTime = (iso: string) =>
	intl.formatDate(iso, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });

/**
 * The request log inside Events (one panel of logs: attacks, bans, mTLS refusals and every request).
 * kinds: the switch between the kinds of Events, shown in the head of the table.
 */
export function RequestLogView({ kinds }: { kinds: React.ReactNode }) {
	const can = useCan();
	const { period, from, to, filters, set } = useRequestParams();
	const navigate = useNavigate();
	/** cursors of the pages before the current one (the first page has none) */
	const [cursors, setCursors] = useState<string[]>([]);
	const before = cursors[cursors.length - 1];
	const page = cursors.length;
	// other filters, another period: the first page again
	// biome-ignore lint/correctness/useExhaustiveDependencies: reset on a change of the query only
	useEffect(() => setCursors([]), [period, from, to, filters]);
	const [follow, setFollow] = useState(true);
	const [search, setSearch] = useState(filters.q ?? "");
	// a search set from outside (a link) shows in the field
	useEffect(() => setSearch(filters.q ?? ""), [filters.q]);
	// the search is applied a moment after typing stops
	// biome-ignore lint/correctness/useExhaustiveDependencies: runs when the typed text changes, with the filters of then
	useEffect(() => {
		if (search === (filters.q ?? "")) return;
		const timer = setTimeout(() => set({ q: search.trim() || null }), 300);
		return () => clearTimeout(timer);
	}, [search]);

	/** the range of the query: a period up to now, or the dates of "custom" */
	const range = () =>
		period === "custom"
			? { from, ...(to ? { to } : {}) }
			: { from: new Date(Date.now() - PERIOD_MS[period]).toISOString() };
	const query = useQuery({
		queryKey: ["nginxions-request-log", period, from, to, filters, before],
		queryFn: () => getRequestLog({ ...filters, ...range(), limit: PAGE, ...(before ? { before } : {}) }),
		// newer requests come in while following the first page (not for a closed range of dates)
		refetchInterval: follow && !before && !(period === "custom" && to) ? 15000 : false,
		placeholderData: (previous) => previous,
	});
	const data = query.data;
	const rows = data?.rows ?? [];
	const filter = (key: keyof TrafficFilters, value: string) => set({ [key]: value });
	const exportAs = async (format: "csv" | "json") => {
		try {
			await downloadRequests({ ...filters, ...range() }, format);
		} catch (err: any) {
			showError(err.message);
		}
	};

	return (
		<>
			<div className={hostStyles.toolbar}>
				<SearchField value={search} onChange={setSearch} placeholder={t("nginxions.traffic.log.search")} />
				<div className={eventStyles.periods} role="group" aria-label={t("nginxions.events.period")}>
					{PERIODS.map((p) => (
						<button
							key={p}
							type="button"
							className={cn(eventStyles.period, period === p && eventStyles.periodOn)}
							aria-pressed={period === p}
							onClick={() =>
								set({
									period: p === "24h" ? null : p,
									from: p === "custom" ? from || new Date(Date.now() - 86400e3).toISOString() : null,
									to: null,
								})
							}
						>
							<T id={`nginxions.events.period.${p}`} />
						</button>
					))}
				</div>
				<RequestFilters filters={filters} set={set} />
				<Dropdown
					floating
					inline
					ariaLabel={t("nginxions.events.export")}
					title={t("nginxions.events.export")}
					triggerClassName={hostStyles.tool}
					trigger={
						<>
							<IconDownload size={16} />
							<span className={hostStyles.toolText}>
								<T id="nginxions.events.export" />
							</span>
						</>
					}
					items={[
						{ key: "csv", label: "CSV", onSelect: () => exportAs("csv") },
						{ key: "json", label: "JSON", onSelect: () => exportAs("json") },
					]}
				/>
				{can("settings") && <RetentionPopover canManage={can("settings", "manage")} />}
			</div>

			{period === "custom" && (
				<div className={eventStyles.custom}>
					<T id="nginxions.events.from" />
					<DateTimePicker
						label={t("nginxions.events.from")}
						value={from}
						max={to || new Date().toISOString()}
						onChange={(iso) => iso && set({ from: iso })}
					/>
					<T id="nginxions.events.to" />
					<DateTimePicker
						label={t("nginxions.events.to")}
						value={to}
						min={from || undefined}
						placeholder={t("nginxions.date.now-placeholder")}
						clearable
						onChange={(iso) => set({ to: iso || null })}
					/>
				</div>
			)}

			<FilterChips
				filters={filters}
				remove={(k) => set({ [k]: null })}
				clear={() => set(Object.fromEntries(FILTER_KEYS.filter((k) => k !== "q").map((k) => [k, null])))}
			/>
			<div className={cn("card", hostStyles.tableCard)}>
				<div className={hostStyles.summary}>
					{kinds}
					{query.isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
					<label className="form-check form-switch m-0">
						<input
							className="form-check-input"
							type="checkbox"
							checked={follow}
							onChange={(e) => setFollow(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="nginxions.waf.events.follow" />
						</span>
					</label>
				</div>
				{query.isLoading ? (
					<LoadingPage noLogo />
				) : query.isError ? (
					<div className="card-body">
						<Alert variant="danger" className="mb-0">
							{query.error.message}
						</Alert>
					</div>
				) : data?.unsupported ? (
					<div className="card-body">
						<Alert variant="warning" className="mb-0">
							<T id="nginxions.traffic.unsupported" />
						</Alert>
					</div>
				) : (
					<>
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter card-table", hostStyles.table, logStyles.table)}>
								<thead>
									<tr>
										<th>
											<Label id="nginxions.traffic.log.time" />
										</th>
										<th>
											<Label id="nginxions.traffic.filter.host" />
										</th>
										<th>
											<Label id="nginxions.traffic.log.client" />
										</th>
										<th>
											<Label id="nginxions.traffic.log.request" />
										</th>
										<th className="text-end">
											<Label id="nginxions.traffic.filter.status" />
										</th>
										<th className="text-end">
											<Label id="nginxions.traffic.log.size" />
										</th>
										<th className="text-end">
											<Label id="nginxions.traffic.log.duration" />
										</th>
										<th>
											<Label id="nginxions.traffic.log.agent" />
										</th>
									</tr>
								</thead>
								<tbody>
									{rows.length === 0 ? (
										<tr>
											<td colSpan={8} className="text-center text-secondary py-4">
												<T id="nginxions.traffic.log.empty" />
											</td>
										</tr>
									) : (
										rows.map((r) => (
											<tr
												key={r.id}
												className={eventStyles.row}
												onClick={() => showRequestModal(r, filter, navigate)}
											>
												<td className={logStyles.time} title={dateTime(r.time)}>
													{rowTime(r.time)}
												</td>
												<td className={logStyles.host}>
													<button
														type="button"
														className={styles.linkButton}
														onClick={(e) => {
															e.stopPropagation();
															filter("host", r.host);
														}}
													>
														{hostLabel(r.host)}
													</button>
													{!r.known && (
														<span className={cn(styles.unknown, logStyles.mark)}>
															{t("nginxions.traffic.host.unknown")}
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
												<td title={r.path}>
													<div className={logStyles.request}>
														<span className={eventStyles.method}>{r.method}</span>
														{r.path}
													</div>
												</td>
												<td className="text-end">
													<span className={cn(logStyles.status, statusTone(r.status))}>
														{r.status}
													</span>
												</td>
												<td className="text-end text-nowrap">{formatBytes(r.bytes)}</td>
												<td className="text-end text-nowrap">{formatMs(r.durationMs)}</td>
												<td className={logStyles.fill} title={r.userAgent}>
													<div className={logStyles.agent}>
														{r.device === "bot" || !r.browser
															? r.userAgent || "—"
															: `${r.browser} · ${r.os} · ${t(`nginxions.traffic.device.${r.device}`)}`}
													</div>
												</td>
											</tr>
										))
									)}
								</tbody>
							</table>
						</div>
						<div className={eventStyles.pager}>
							<span>
								<T
									id={
										data?.totalCapped
											? "nginxions.traffic.log.total-capped"
											: "nginxions.traffic.log.total"
									}
									data={{ total: data?.total ?? rows.length }}
								/>
							</span>
							<div className={eventStyles.pagerButtons}>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page === 0}
									onClick={() => setCursors(cursors.slice(0, -1))}
								>
									<IconChevronLeft size={16} />
									<T id="nginxions.events.newer" />
								</button>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={!data?.next}
									onClick={() => data?.next && setCursors([...cursors, data.next])}
								>
									<T id="nginxions.events.older" />
									<IconChevronRight size={16} />
								</button>
							</div>
						</div>
					</>
				)}
			</div>
		</>
	);
}
