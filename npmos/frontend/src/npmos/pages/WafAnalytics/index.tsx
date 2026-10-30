// WAF → Analytics: what the open-appsec cloud dashboard showed, from the events NPMOS stores
// (docs/ROADMAP.md, phase 4): KPI, attacks over time (prevent/detect), top hosts, sources, attack
// types and URIs, severities, actions, countries, last blocked requests. Every list opens the
// events behind it.
import cn from "classnames";
import Alert from "react-bootstrap/Alert";
import { useNavigate, useSearchParams } from "react-router-dom";
import { HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import type { AnalyticsPeriod, SecurityEvent } from "../../api";
import { useAnalytics } from "../../hooks";
import { showWafEventModal } from "../../modals/WafEventModal";
import { BarList, formatNumber, StackedBars, Tile, Tiles } from "../../ui/Charts";
import { Dropdown } from "../../ui/Dropdown";
import hostStyles from "../Hosts/Hosts.module.css";
import { ActionBadge, EventTime, SeverityBadge } from "../WafEvents/badges";
import eventStyles from "../WafEvents/Events.module.css";
import styles from "./Analytics.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const PERIODS: AnalyticsPeriod[] = ["1h", "24h", "7d", "30d"];

/** a bucket on the axis: time of day for a day or less, the date for longer periods */
const bucketLabel = (iso: string, period: AnalyticsPeriod) =>
	period === "1h" || period === "24h"
		? intl.formatTime(iso, { hour: "2-digit", minute: "2-digit" })
		: period === "7d"
			? intl.formatDate(iso, { day: "numeric", month: "short", hour: "2-digit" })
			: intl.formatDate(iso, { day: "numeric", month: "short" });

/** "12 % of all" */
const share = (n: number, total: number) =>
	total > 0
		? t("npmos.analytics.traffic.share", {
				p: intl.formatNumber(n / total, { style: "percent", maximumFractionDigits: 1 }),
			})
		: undefined;

const formatBytes = (n: number) => {
	const units = ["B", "KB", "MB", "GB", "TB"];
	let i = 0;
	let v = n;
	while (v >= 1024 && i < units.length - 1) {
		v /= 1024;
		i++;
	}
	return `${intl.formatNumber(v, { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`;
};

function Panel({ title, children, wide }: { title: React.ReactNode; children: React.ReactNode; wide?: boolean }) {
	return (
		<div className={cn("card", styles.panel, wide && styles.wide)}>
			<h3 className={styles.panelTitle}>{title}</h3>
			{children}
		</div>
	);
}

function AnalyticsPage() {
	const navigate = useNavigate();
	const [params, setParams] = useSearchParams();
	const period = PERIODS.find((p) => p === params.get("period")) ?? "24h";
	const host = params.get("host") ?? "";
	const { data, isLoading, isError, error, isFetching } = useAnalytics(period, host);

	const set = (key: string, value: string, isDefault: boolean) => {
		const next = new URLSearchParams(params);
		if (isDefault) next.delete(key);
		else next.set(key, value);
		setParams(next, { replace: true });
	};
	/** the events behind a number of the page */
	const events = (filters: Record<string, string>) =>
		navigate(`/waf/events?${new URLSearchParams({ period, ...(host ? { host } : {}), ...filters })}`);
	const none = t("npmos.analytics.none");

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.analytics" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.analytics.description" />
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
							onClick={() => set("period", p, p === "24h")}
						>
							<T id={`npmos.events.period.${p}`} />
						</button>
					))}
				</div>
				<Dropdown
					floating
					inline
					ariaLabel={t("npmos.waf.events.host")}
					triggerClassName={hostStyles.tool}
					trigger={<span>{host || t("npmos.analytics.all-hosts")}</span>}
					items={[
						{
							key: "",
							label: t("npmos.analytics.all-hosts"),
							active: !host,
							onSelect: () => set("host", "", true),
						},
						...(data?.hosts ?? [])
							.filter((h) => h.host !== host)
							.map((h) => ({ key: h.host, label: h.host, onSelect: () => set("host", h.host, false) })),
						...(host ? [{ key: host, label: host, active: true, onSelect: () => {} }] : []),
					]}
				/>
				{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
			</div>

			{isLoading ? (
				<LoadingPage noLogo />
			) : isError || !data ? (
				<Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>
			) : (
				<>
					<h2 className={styles.section}>
						<T id="npmos.analytics.section.traffic" />
					</h2>
					<Tiles>
						<Tile
							value={formatNumber(data.traffic.requests)}
							label={<T id="npmos.analytics.traffic.requests" />}
							hint={
								<T
									id="npmos.analytics.traffic.sent"
									data={{ bytes: formatBytes(data.traffic.bytes) }}
								/>
							}
						/>
						<Tile
							value={formatNumber(data.traffic.ok)}
							label={<T id="npmos.analytics.traffic.ok" />}
							hint={share(data.traffic.ok, data.traffic.requests)}
						/>
						<Tile
							value={formatNumber(data.traffic.s4xx)}
							label={<T id="npmos.analytics.traffic.4xx" />}
							hint={share(data.traffic.s4xx, data.traffic.requests)}
						/>
						<Tile
							value={formatNumber(data.traffic.s5xx)}
							label={<T id="npmos.analytics.traffic.5xx" />}
							hint={share(data.traffic.s5xx, data.traffic.requests)}
						/>
						<Tile
							value={formatNumber(data.traffic.blocked)}
							label={<T id="npmos.analytics.traffic.blocked" />}
							hint={share(data.traffic.blocked, data.traffic.requests)}
						/>
					</Tiles>
					<div className={styles.grid}>
						<Panel title={<T id="npmos.analytics.traffic.timeline" />} wide>
							<StackedBars
								data={data.traffic.timeline.map((b) => ({
									t: b.t,
									passed: Math.max(0, b.requests - b.blocked),
									blocked: b.blocked,
								}))}
								series={[
									{
										key: "passed",
										label: t("npmos.analytics.traffic.passed"),
										color: "var(--series-3)",
									},
									{
										key: "blocked",
										label: t("npmos.analytics.traffic.blocked"),
										color: "var(--series-2)",
									},
								]}
								xLabel={(b) => bucketLabel(b.t, period)}
								tooltipTitle={(b) => intl.formatDate(b.t, { dateStyle: "medium", timeStyle: "short" })}
								emptyText={t("npmos.analytics.traffic.none")}
								ariaLabel={t("npmos.analytics.traffic.timeline")}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.traffic.hosts" />}>
							<BarList
								emptyText={t("npmos.analytics.traffic.none")}
								items={data.traffic.hosts.map((h) => ({
									key: h.host,
									label: h.host,
									value: h.requests,
									sub:
										h.errors || h.blocked
											? t("npmos.analytics.traffic.host-sub", {
													errors: formatNumber(h.errors),
													blocked: formatNumber(h.blocked),
												})
											: undefined,
									onClick: () => set("host", h.host, false),
								}))}
							/>
						</Panel>
					</div>

					<h2 className={styles.section}>
						<T id="npmos.analytics.section.attacks" />
					</h2>
					<Tiles>
						<Tile value={formatNumber(data.kpi.attacks)} label={<T id="npmos.analytics.attacks" />} />
						<Tile value={formatNumber(data.kpi.prevented)} label={<T id="npmos.analytics.prevented" />} />
						<Tile value={formatNumber(data.kpi.detected)} label={<T id="npmos.analytics.detected" />} />
						<Tile value={formatNumber(data.kpi.sources)} label={<T id="npmos.analytics.sources" />} />
						<Tile
							value={formatNumber(data.kpi.crowdsecBans)}
							label={<T id="npmos.analytics.crowdsec-bans" />}
							hint={<T id="npmos.analytics.crowdsec-alerts" data={{ count: data.kpi.crowdsecAlerts }} />}
						/>
					</Tiles>

					<div className={styles.grid}>
						<Panel title={<T id="npmos.analytics.timeline" />} wide>
							<StackedBars
								data={data.timeline}
								series={[
									{
										key: "prevent",
										label: t("npmos.analytics.series.prevent"),
										color: "var(--series-1)",
									},
									{
										key: "detect",
										label: t("npmos.analytics.series.detect"),
										color: "var(--series-2)",
									},
									{
										key: "other",
										label: t("npmos.analytics.series.other"),
										color: "var(--series-3)",
									},
								]}
								xLabel={(b) => bucketLabel(b.t, period)}
								tooltipTitle={(b) => intl.formatDate(b.t, { dateStyle: "medium", timeStyle: "short" })}
								emptyText={t("npmos.analytics.no-attacks")}
								ariaLabel={t("npmos.analytics.timeline")}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.top-hosts" />}>
							<BarList
								emptyText={none}
								items={data.hosts.map((h) => ({
									key: h.host,
									label: h.host,
									value: h.events,
									sub: t("npmos.analytics.prevented-n", { n: formatNumber(h.prevented) }),
									onClick: () => events({ host: h.host }),
								}))}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.top-sources" />}>
							<BarList
								emptyText={none}
								items={data.sources.map((s) => ({
									key: s.ip,
									label: s.ip,
									value: s.events,
									sub: s.country || undefined,
									onClick: () => events({ ip: s.ip, important: "1" }),
								}))}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.top-types" />}>
							<BarList
								emptyText={none}
								items={data.types.map((ty) => ({
									key: ty.type,
									label: ty.type,
									value: ty.events,
									onClick: () => events({ type: ty.type }),
								}))}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.top-uris" />}>
							<BarList
								emptyText={none}
								items={data.uris.map((u) => ({
									key: `${u.host} ${u.uri}`,
									label: u.uri || "/",
									title: `${u.host}${u.uri}`,
									value: u.events,
									sub: u.host,
									onClick: () => events({ host: u.host, q: u.uri }),
								}))}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.levels" />}>
							<BarList
								emptyText={none}
								items={["Critical", "High", "Medium", "Low", "Info"]
									.map((level) => ({
										level,
										events:
											data.severities.find(
												(s) => s.severity.toLowerCase() === level.toLowerCase(),
											)?.events ?? 0,
									}))
									.filter((s) => s.events > 0)
									.map((s) => ({
										key: s.level,
										label: s.level,
										value: s.events,
										onClick: () => events({ severity: s.level }),
									}))}
							/>
						</Panel>
						<Panel title={<T id="npmos.analytics.actions" />}>
							<BarList
								emptyText={none}
								items={data.actions.map((a) => ({
									key: a.action,
									label: a.action,
									value: a.events,
									onClick: () => events({ action: a.action }),
								}))}
							/>
						</Panel>
						{data.countries.length > 0 && (
							<Panel title={<T id="npmos.analytics.countries" />}>
								<BarList
									emptyText={none}
									items={data.countries.map((c) => ({
										key: c.country,
										label: c.country,
										value: c.events,
									}))}
								/>
							</Panel>
						)}
						<Panel title={<T id="npmos.analytics.last-blocked" />} wide>
							{data.lastBlocked.length === 0 ? (
								<div className="text-secondary small">{none}</div>
							) : (
								<div className={hostStyles.scroller}>
									<table
										className={cn("table table-vcenter table-hover card-table", hostStyles.table)}
									>
										<tbody>
											{data.lastBlocked.map((e) => (
												<tr
													key={e.id}
													className={eventStyles.row}
													onClick={() => showWafEventModal(e as SecurityEvent)}
												>
													<td className={eventStyles.time}>
														<EventTime time={e.time} />
													</td>
													<td>
														<SeverityBadge severity={e.severity} />
													</td>
													<td>{e.incidentType}</td>
													<td>
														<ActionBadge action={e.action} />
													</td>
													<td>{e.sourceIp}</td>
													<td>{e.host}</td>
													<td className={eventStyles.request}>
														{e.method && (
															<span className={eventStyles.method}>{e.method}</span>
														)}
														{e.uri}
													</td>
												</tr>
											))}
										</tbody>
									</table>
								</div>
							)}
						</Panel>
					</div>
					<p className={styles.note}>
						<T id="npmos.analytics.note" />
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
