// The tabs of Analytics, after the Cloudflare dashboard: Requests, Visitors, Performance, Security, Cache, Origin.
// Traffic and attacks over time are area charts (the area chart of the opensophy site); classes per bucket are
// stacked bars; top lists filter the page by a click.
import cn from "classnames";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { T } from "src/locale";
import type { AnalyticsPeriod, Bucket, EventRow, OriginEndpoint, TopRow, Traffic, TrafficFilters } from "../../api";
import { BarList, StackedBars } from "../../ui/Charts";
import { AreaChart, type AreaSeries } from "../../ui/charts/AreaChart";
import {
	countryCode,
	countryName,
	eventCountry,
	formatBytes,
	formatCount,
	formatMs,
	formatPercent,
} from "../../ui/charts/format";
import { Kpi, Kpis } from "../../ui/charts/Kpi";
import { WorldMap } from "../../ui/charts/WorldMap";
import hostStyles from "../Hosts/Hosts.module.css";
import { Admonition } from "../../ui/Admonition";
import styles from "./Analytics.module.css";
import { bucketLabel, bucketTitle, Country, Grid, Panel, Section, t, TopList } from "./common";

export interface TabProps {
	data: Traffic;
	period: AnalyticsPeriod;
	filter: (key: keyof TrafficFilters, value: string) => void;
}

type Row = Bucket;

const area = (
	data: Row[],
	period: AnalyticsPeriod,
	series: AreaSeries<Row>[],
	options: {
		stacked?: boolean;
		format?: (n: number) => string;
		legendTotal?: "sum" | "none";
		aria: string;
		height?: number;
	},
) => (
	<AreaChart
		data={data}
		series={series}
		stacked={options.stacked}
		format={options.format}
		legendTotal={options.legendTotal}
		height={options.height}
		xLabel={(b) => bucketLabel(b.t, period)}
		tooltipTitle={(b) => bucketTitle(b.t)}
		emptyText={t("npmos.traffic.no-data")}
		ariaLabel={options.aria}
	/>
);

const bars = (
	data: Row[],
	period: AnalyticsPeriod,
	series: { key: string; label: string; color: string }[],
	aria: string,
) => (
	<StackedBars
		data={data}
		series={series as { key: keyof Row & string; label: string; color: string }[]}
		xLabel={(b) => bucketLabel(b.t, period)}
		tooltipTitle={(b) => bucketTitle(b.t)}
		emptyText={t("npmos.traffic.no-data")}
		ariaLabel={aria}
	/>
);

const kpi = (data: Traffic, key: string) => data.kpi[key] ?? null;
const rows = (data: Traffic, key: string) => (data.top?.[key] ?? []) as TopRow[];
const eventRows = (data: Traffic, key: string) => (data.top?.[key] ?? []) as EventRow[];

const STATUS_SERIES = [
	{ key: "s2xx", label: "2xx", color: "var(--series-3)" },
	{ key: "s3xx", label: "3xx", color: "var(--series-1)" },
	{ key: "s4xx", label: "4xx", color: "var(--series-5)" },
	{ key: "s5xx", label: "5xx", color: "var(--series-2)" },
	{ key: "s1xx", label: "1xx", color: "var(--series-neutral)" },
];

/** the map with its list of countries next to it */
function Geography({
	countries,
	metric,
	unit,
	filter,
	color,
	title,
	action,
}: {
	countries: TopRow[];
	metric: "requests" | "pageviews" | "mitigated";
	unit: string;
	filter?: (code: string) => void;
	color?: string;
	title: React.ReactNode;
	action?: React.ReactNode;
}) {
	const values = new Map<string, number>();
	for (const c of countries) {
		const v = Number(c[metric] ?? 0);
		if (c.value && v > 0) values.set(c.value, (values.get(c.value) ?? 0) + v);
	}
	const sorted = [...values.entries()].sort((a, b) => b[1] - a[1]);
	return (
		<Panel title={title} wide action={action}>
			<div className={styles.geo}>
				<WorldMap
					values={values}
					color={color}
					unit={unit}
					lowLabel={t("npmos.traffic.map.less")}
					highLabel={t("npmos.traffic.map.more")}
					ariaLabel={t("npmos.traffic.map")}
					onSelect={filter}
				/>
				<div className={styles.geoList}>
					<BarList
						emptyText={t("npmos.traffic.map.empty")}
						format={formatCount}
						items={sorted.slice(0, 12).map(([code, v]) => ({
							key: code,
							label: <Country code={code} />,
							title: countryName(code),
							value: v,
							onClick: filter ? () => filter(code) : undefined,
						}))}
					/>
				</div>
			</div>
		</Panel>
	);
}

/** hosts with a mark for those not in NPMOS */
function HostList({
	data,
	filter,
	metric = "requests",
}: {
	data: Traffic;
	filter: TabProps["filter"];
	metric?: "requests";
}) {
	return (
		<TopList
			rows={rows(data, "hosts")}
			metric={metric}
			filter={(v) => filter("host", v)}
			label={(v) => (v === "_" || v === "" ? t("npmos.traffic.host.none") : v)}
			sub={(r) =>
				r.known === false ? <span className={styles.unknown}>{t("npmos.traffic.host.unknown")}</span> : null
			}
		/>
	);
}

/** requests to names that are not hosts of NPMOS: what they are and what to do */
function UnknownHosts({ data }: { data: Traffic }) {
	const unknown = rows(data, "hosts").filter((r) => r.known === false);
	const total = unknown.reduce((n, r) => n + r.requests, 0);
	if (!total) return null;
	return (
		<Admonition
			variant="caution"
			title={<T id="npmos.traffic.unknown-hosts.title" data={{ count: formatCount(total) }} />}
		>
			<T
				id="npmos.traffic.unknown-hosts.text"
				data={{
					hosts: unknown
						.slice(0, 3)
						.map((r) => (r.value === "_" || !r.value ? t("npmos.traffic.host.none") : r.value))
						.join(", "),
				}}
			/>
			<div className={styles.noticeActions}>
				<Link className="btn btn-sm" to="/waf/events?kind=requests&unknown=1">
					<T id="npmos.traffic.unknown-hosts.show" />
				</Link>
				<Link className="btn btn-sm" to="/hosts">
					<T id="npmos.traffic.unknown-hosts.add" />
				</Link>
				<Link className="btn btn-sm" to="/settings?section=default-site">
					<T id="npmos.traffic.unknown-hosts.default" />
				</Link>
			</div>
		</Admonition>
	);
}

export function RequestsTab({ data, period, filter }: TabProps) {
	const tl = data.timeline;
	const passed = tl.map((b) => ({ ...b, passed: Math.max(0, Number(b.requests ?? 0) - Number(b.mitigated ?? 0)) }));
	const hasCache = tl.some((b) => b.cacheable !== undefined);
	const cacheRows = tl.map((b) => ({
		...b,
		uncached: Math.max(0, Number(b.requests ?? 0) - Number(b.cached ?? 0)),
	}));
	return (
		<>
			<UnknownHosts data={data} />
			<Kpis>
				<Kpi
					label={<T id="npmos.traffic.kpi.requests" />}
					value={formatCount(kpi(data, "requests")?.value)}
					change={kpi(data, "requests")?.change}
					series={kpi(data, "requests")?.series}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.bytes" />}
					value={formatBytes(kpi(data, "bytes")?.value)}
					change={kpi(data, "bytes")?.change}
					series={kpi(data, "bytes")?.series}
					color="var(--series-4)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.visits" />}
					value={formatCount(kpi(data, "visits")?.value)}
					change={kpi(data, "visits")?.change}
					series={kpi(data, "visits")?.series}
					color="var(--series-3)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.cache-hit" />}
					value={formatPercent(kpi(data, "cacheHitRate")?.value)}
					hint={kpi(data, "cacheHitRate")?.value === null ? t("npmos.traffic.kpi.cache-off") : undefined}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.5xx-rate" />}
					value={formatPercent(kpi(data, "errorRate5xx")?.value)}
					change={kpi(data, "errorRate5xx")?.change}
					riseIsBad
				/>
			</Kpis>
			<Grid>
				<Panel title={<T id="npmos.traffic.requests-over-time" />}>
					{area(
						passed,
						period,
						[
							{ key: "passed", label: t("npmos.traffic.series.passed"), color: "var(--series-1)" },
							{ key: "mitigated", label: t("npmos.traffic.series.mitigated"), color: "var(--series-2)" },
						],
						{ stacked: true, aria: t("npmos.traffic.requests-over-time") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.bytes-over-time" />}>
					{area(
						tl,
						period,
						[{ key: "bytes", label: t("npmos.traffic.series.bytes"), color: "var(--series-4)" }],
						{
							format: formatBytes,
							aria: t("npmos.traffic.bytes-over-time"),
						},
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.by-status" />}>
					{bars(tl, period, STATUS_SERIES, t("npmos.traffic.by-status"))}
				</Panel>
				<Panel title={<T id="npmos.traffic.by-cache" />}>
					{hasCache ? (
						bars(
							cacheRows,
							period,
							[
								{ key: "cached", label: t("npmos.traffic.series.cached"), color: "var(--series-3)" },
								{
									key: "uncached",
									label: t("npmos.traffic.series.uncached"),
									color: "var(--series-neutral)",
								},
							],
							t("npmos.traffic.by-cache"),
						)
					) : (
						<p className="text-secondary small mb-0">
							<T id="npmos.traffic.detail-only" />
						</p>
					)}
				</Panel>
			</Grid>
			<Geography
				title={<T id="npmos.traffic.geography" />}
				countries={data.countries ?? []}
				metric="requests"
				unit={t("npmos.traffic.series.requests")}
				filter={(code) => filter("country", code)}
			/>
			<Grid>
				<Panel title={<T id="npmos.traffic.top.paths" />}>
					<TopList rows={rows(data, "paths")} filter={(v) => filter("path", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.ips" />}>
					<TopList
						rows={rows(data, "ips")}
						filter={(v) => filter("ip", v)}
						sub={(r) => (r.country ? countryName(r.country) : null)}
					/>
				</Panel>
				<Panel title={<T id="npmos.traffic.top.hosts" />}>
					<HostList data={data} filter={filter} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.statuses" />}>
					<TopList rows={rows(data, "statuses")} filter={(v) => filter("status", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.browsers" />}>
					<TopList rows={rows(data, "browsers")} filter={(v) => filter("browser", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.os" />}>
					<TopList rows={rows(data, "os")} filter={(v) => filter("os", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.devices" />}>
					<TopList
						rows={rows(data, "devices")}
						filter={(v) => filter("device", v)}
						label={(v) => t(`npmos.traffic.device.${v}`)}
					/>
				</Panel>
				<Panel title={<T id="npmos.traffic.top.protocols" />}>
					<TopList rows={rows(data, "protocols")} filter={(v) => filter("protocol", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.agents" />} wide>
					<TopList rows={rows(data, "agents")} />
				</Panel>
			</Grid>
		</>
	);
}

/** who made the page views and visits: people, bots that say so, scanners (backend events/client.js) */
const CLIENT_SERIES = [
	{ key: "Human", label: "npmos.traffic.client.human", color: "var(--series-1)" },
	{ key: "Bot", label: "npmos.traffic.client.bot", color: "var(--series-4)" },
	{ key: "Scanner", label: "npmos.traffic.client.scanner", color: "var(--series-5)" },
] as const;

const byClient = (prefix: "pv" | "visit") =>
	CLIENT_SERIES.map(({ key, label, color }) => ({ key: `${prefix}${key}`, label: t(label), color }));

export function VisitorsTab({ data, period, filter }: TabProps) {
	const tl = data.timeline;
	return (
		<>
			<Kpis>
				<Kpi
					label={<T id="npmos.traffic.kpi.pageviews" />}
					value={formatCount(kpi(data, "pageviews")?.value)}
					change={kpi(data, "pageviews")?.change}
					series={kpi(data, "pageviews")?.series}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.visits" />}
					value={formatCount(kpi(data, "visits")?.value)}
					change={kpi(data, "visits")?.change}
					series={kpi(data, "visits")?.series}
					color="var(--series-3)"
				/>
			</Kpis>
			<p className={styles.note}>
				<T id="npmos.traffic.visitors.hint" />
			</p>
			<Grid>
				<Panel title={<T id="npmos.traffic.pageviews-over-time" />}>
					{area(tl, period, byClient("pv"), { stacked: true, aria: t("npmos.traffic.pageviews-over-time") })}
				</Panel>
				<Panel title={<T id="npmos.traffic.visits-over-time" />}>
					{area(tl, period, byClient("visit"), { stacked: true, aria: t("npmos.traffic.visits-over-time") })}
				</Panel>
			</Grid>
			<Section>
				<T id="npmos.traffic.geography" />
			</Section>
			<Geography
				title={<T id="npmos.traffic.pageviews-by-country" />}
				countries={data.countries ?? []}
				metric="pageviews"
				unit={t("npmos.traffic.kpi.pageviews")}
				filter={(code) => filter("country", code)}
			/>
			<Section>
				<T id="npmos.traffic.content" />
			</Section>
			<Grid>
				<Panel title={<T id="npmos.traffic.top.paths" />}>
					<TopList rows={rows(data, "paths")} filter={(v) => filter("path", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.hosts" />}>
					<HostList data={data} filter={filter} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.referers" />}>
					<TopList rows={rows(data, "referers")} />
				</Panel>
			</Grid>
			<Section>
				<T id="npmos.traffic.technology" />
			</Section>
			<Grid>
				<Panel title={<T id="npmos.traffic.devices-over-time" />} wide>
					{area(
						tl,
						period,
						(["desktop", "mobile", "tablet", "other"] as const).map((k, i) => ({
							key: k,
							label: t(`npmos.traffic.device.${k}`),
							color: ["var(--series-1)", "var(--series-3)", "var(--series-4)", "var(--series-neutral)"][
								i
							],
						})),
						{ stacked: true, aria: t("npmos.traffic.devices-over-time") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.top.os" />}>
					<TopList rows={rows(data, "os")} filter={(v) => filter("os", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.browsers" />}>
					<TopList rows={rows(data, "browsers")} filter={(v) => filter("browser", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.agents" />} wide>
					<TopList rows={rows(data, "agents")} />
				</Panel>
			</Grid>
		</>
	);
}

export function PerformanceTab({ data, period, filter }: TabProps) {
	return (
		<>
			<Kpis>
				<Kpi
					label={<T id="npmos.traffic.kpi.origin-p50" />}
					value={formatMs(kpi(data, "originP50")?.value)}
					change={kpi(data, "originP50")?.change}
					series={kpi(data, "originP50")?.series}
					riseIsBad
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.origin-p95" />}
					value={formatMs(kpi(data, "originP95")?.value)}
					change={kpi(data, "originP95")?.change}
					series={kpi(data, "originP95")?.series}
					color="var(--series-5)"
					riseIsBad
				/>
				<Kpi label={<T id="npmos.traffic.kpi.total-p50" />} value={formatMs(kpi(data, "totalP50")?.value)} />
				<Kpi label={<T id="npmos.traffic.kpi.total-p95" />} value={formatMs(kpi(data, "totalP95")?.value)} />
			</Kpis>
			<Grid>
				<Panel title={<T id="npmos.traffic.origin-percentiles" />}>
					{area(
						data.timeline,
						period,
						[
							{ key: "p50", label: "p50", color: "var(--series-1)" },
							{ key: "p95", label: "p95", color: "var(--series-5)" },
							{ key: "p99", label: "p99", color: "var(--series-2)" },
						],
						{ format: formatMs, legendTotal: "none", aria: t("npmos.traffic.origin-percentiles") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.by-protocol" />}>
					{bars(
						data.protocolTimeline ?? [],
						period,
						[
							{ key: "http1", label: "HTTP/1.x", color: "var(--series-neutral)" },
							{ key: "http2", label: "HTTP/2", color: "var(--series-1)" },
							{ key: "http3", label: "HTTP/3", color: "var(--series-3)" },
							{ key: "other", label: t("npmos.traffic.series.other"), color: "var(--series-5)" },
						],
						t("npmos.traffic.by-protocol"),
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.top.tls" />}>
					<TopList rows={rows(data, "tls")} filter={(v) => filter("tls", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.paths-bytes" />}>
					<TopList
						rows={rows(data, "pathsByBytes")}
						metric="bytes"
						format={formatBytes}
						filter={(v) => filter("path", v)}
					/>
				</Panel>
				<Panel title={<T id="npmos.traffic.top.slow-paths" />} wide>
					<TopList
						rows={rows(data, "slowPaths")}
						metric="p95"
						format={formatMs}
						filter={(v) => filter("path", v)}
						sub={(r) => t("npmos.traffic.requests-n", { n: formatCount(r.requests) })}
					/>
				</Panel>
			</Grid>
		</>
	);
}

const ACTION_LABEL: Record<string, string> = {
	"security:prevent": "npmos.traffic.product.appsec-prevent",
	"security:detect": "npmos.traffic.product.appsec-detect",
	"crowdsec:alert": "npmos.traffic.product.crowdsec-alert",
	"crowdsec:ban": "npmos.traffic.product.crowdsec-ban",
	"crowdsec:captcha": "npmos.traffic.product.crowdsec-captcha",
	"mtls:denied": "npmos.traffic.product.mtls",
};

export function SecurityTab({ data, period, filter }: TabProps) {
	const navigate = useNavigate();
	const [mapOf, setMapOf] = useState<"attacks" | "mitigated">("attacks");
	// countries of the events: English names of GeoIP → ISO codes
	const attackCountries: TopRow[] = (data.attackCountries ?? []).map((r) => ({
		value: countryCode(r.value),
		requests: r.events,
		bytes: 0,
		mitigated: r.events,
	}));
	const events = (filters: Record<string, string>) =>
		navigate(`/waf/events?${new URLSearchParams({ period, kind: "agents", ...filters })}`);
	const tl = data.timeline;
	return (
		<>
			<Kpis>
				<Kpi
					label={<T id="npmos.traffic.kpi.requests" />}
					value={formatCount(kpi(data, "requests")?.value)}
					change={kpi(data, "requests")?.change}
					series={kpi(data, "requests")?.series}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.mitigated" />}
					value={formatCount(kpi(data, "mitigated")?.value)}
					change={kpi(data, "mitigated")?.change}
					series={kpi(data, "mitigated")?.series}
					color="var(--series-2)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.mitigated-rate" />}
					value={formatPercent(kpi(data, "mitigatedRate")?.value)}
					change={kpi(data, "mitigatedRate")?.change}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.appsec" />}
					value={formatCount(kpi(data, "appsec")?.value)}
					series={kpi(data, "appsec")?.series}
					color="var(--series-4)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.crowdsec" />}
					value={formatCount(kpi(data, "crowdsec")?.value)}
					series={kpi(data, "crowdsec")?.series}
					color="var(--series-5)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.rate-limited" />}
					value={formatCount(kpi(data, "rateLimited")?.value)}
					series={kpi(data, "rateLimited")?.series}
					color="var(--series-neutral)"
				/>
			</Kpis>
			<Grid>
				<Panel title={<T id="npmos.traffic.outcomes-over-time" />}>
					{area(
						tl,
						period,
						[
							{ key: "allowed", label: t("npmos.traffic.series.passed"), color: "var(--series-1)" },
							{ key: "mitigated", label: t("npmos.traffic.series.mitigated"), color: "var(--series-2)" },
						],
						{ stacked: true, aria: t("npmos.traffic.outcomes-over-time") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.attacks-over-time" />}>
					{area(
						data.productTimeline ?? [],
						period,
						[
							{
								key: "appsecPrevent",
								label: t("npmos.traffic.product.appsec-prevent"),
								color: "var(--series-4)",
							},
							{
								key: "appsecDetect",
								label: t("npmos.traffic.product.appsec-detect"),
								color: "var(--series-1)",
							},
							{
								key: "crowdsecBan",
								label: t("npmos.traffic.product.crowdsec-ban"),
								color: "var(--series-2)",
							},
							{
								key: "crowdsecAlert",
								label: t("npmos.traffic.product.crowdsec-alert"),
								color: "var(--series-5)",
							},
							{ key: "mtls", label: t("npmos.traffic.product.mtls"), color: "var(--series-3)" },
						],
						{ stacked: true, aria: t("npmos.traffic.attacks-over-time") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.mitigations-by-answer" />}>
					{bars(
						tl,
						period,
						[
							{ key: "refused", label: t("npmos.traffic.answer.403"), color: "var(--series-2)" },
							{ key: "rateLimited", label: t("npmos.traffic.answer.429"), color: "var(--series-5)" },
							{ key: "dropped", label: t("npmos.traffic.answer.444"), color: "var(--series-neutral)" },
							{ key: "mtls", label: t("npmos.traffic.answer.mtls"), color: "var(--series-3)" },
						],
						t("npmos.traffic.mitigations-by-answer"),
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.security-actions" />}>
					<BarList
						emptyText={t("npmos.traffic.no-attacks")}
						items={(data.actions ?? []).map((a) => {
							const id = ACTION_LABEL[`${a.kind}:${a.action.toLowerCase()}`];
							return {
								key: `${a.kind}:${a.action}`,
								label: id ? t(id) : `${t(`npmos.traffic.kind.${a.kind}`)}: ${a.action}`,
								value: a.events,
								onClick: () => events({ kind: a.kind, action: a.action }),
							};
						})}
					/>
				</Panel>
			</Grid>
			<Geography
				title={<T id="npmos.traffic.attack-map" />}
				countries={mapOf === "attacks" ? attackCountries : (data.countries ?? [])}
				metric="mitigated"
				unit={mapOf === "attacks" ? t("npmos.traffic.series.attacks") : t("npmos.traffic.series.mitigated")}
				color="var(--series-2)"
				filter={mapOf === "mitigated" ? (code) => filter("country", code) : undefined}
				action={
					<div className={styles.toggle} role="group">
						{(["attacks", "mitigated"] as const).map((m) => (
							<button
								key={m}
								type="button"
								aria-pressed={mapOf === m}
								className={cn(styles.toggleItem, mapOf === m && styles.toggleOn)}
								onClick={() => setMapOf(m)}
							>
								<T id={`npmos.traffic.map.${m}`} />
							</button>
						))}
					</div>
				}
			/>
			<Grid>
				<Panel title={<T id="npmos.traffic.top.attack-types" />}>
					<BarList
						emptyText={t("npmos.traffic.no-attacks")}
						items={eventRows(data, "attackTypes").map((r) => ({
							key: r.value,
							label: r.value || t("npmos.traffic.unknown"),
							value: r.events,
						}))}
					/>
				</Panel>
				<Panel title={<T id="npmos.traffic.top.attack-sources" />}>
					<BarList
						emptyText={t("npmos.traffic.no-attacks")}
						items={eventRows(data, "attackSources").map((r) => ({
							key: r.value,
							label: r.value,
							value: r.events,
							sub: r.country ? eventCountry(r.country) : undefined,
							onClick: () => events({ ip: r.value }),
						}))}
					/>
				</Panel>
				<Panel title={<T id="npmos.traffic.top.attack-paths" />}>
					<BarList
						emptyText={t("npmos.traffic.no-attacks")}
						items={eventRows(data, "attackPaths").map((r) => ({
							key: r.value,
							label: r.value,
							value: r.events,
							onClick: () => events({ q: r.value }),
						}))}
					/>
				</Panel>
				<Panel title={<T id="npmos.traffic.top.mitigated-paths" />}>
					<TopList rows={rows(data, "paths")} filter={(v) => filter("path", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.mitigated-ips" />} wide>
					<TopList
						rows={rows(data, "ips")}
						filter={(v) => filter("ip", v)}
						sub={(r) => (r.country ? countryName(r.country) : null)}
					/>
				</Panel>
			</Grid>
		</>
	);
}

export function CacheTab({ data, period, filter }: TabProps) {
	const tl = data.timeline.map((b) => ({
		...b,
		uncachedBytes: Math.max(0, Number(b.bytes ?? 0) - Number(b.cachedBytes ?? 0)),
	}));
	return (
		<>
			<Kpis>
				<Kpi
					label={<T id="npmos.traffic.kpi.cache-hit" />}
					value={formatPercent(kpi(data, "hitRate")?.value)}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.cached" />}
					value={formatCount(kpi(data, "cached")?.value)}
					series={kpi(data, "cached")?.series}
					color="var(--series-3)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.uncached" />}
					value={formatCount(kpi(data, "uncached")?.value)}
					series={kpi(data, "uncached")?.series}
					color="var(--series-neutral)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.cached-bytes" />}
					value={formatBytes(kpi(data, "cachedBytes")?.value)}
					series={kpi(data, "cachedBytes")?.series}
					color="var(--series-3)"
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.bytes" />}
					value={formatBytes(kpi(data, "bytes")?.value)}
					series={kpi(data, "bytes")?.series}
					color="var(--series-4)"
				/>
				<Kpi label={<T id="npmos.traffic.kpi.saved" />} value={formatPercent(kpi(data, "savedRate")?.value)} />
			</Kpis>
			<p className={styles.note}>
				<T id="npmos.traffic.cache.hint" />
			</p>
			<Grid>
				<Panel title={<T id="npmos.traffic.by-cache" />} wide>
					{bars(
						tl,
						period,
						[
							{ key: "hit", label: "HIT", color: "var(--series-3)" },
							{ key: "miss", label: "MISS", color: "var(--series-2)" },
							{ key: "expired", label: "EXPIRED", color: "var(--series-5)" },
							{ key: "bypass", label: "BYPASS", color: "var(--series-4)" },
							{ key: "other", label: t("npmos.traffic.series.other"), color: "var(--series-1)" },
							{
								key: "none",
								label: t("npmos.traffic.series.not-cacheable"),
								color: "var(--series-neutral)",
							},
						],
						t("npmos.traffic.by-cache"),
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.cached-vs-uncached" />}>
					{area(
						tl,
						period,
						[
							{ key: "cached", label: t("npmos.traffic.series.cached"), color: "var(--series-3)" },
							{
								key: "uncached",
								label: t("npmos.traffic.series.uncached"),
								color: "var(--series-neutral)",
							},
						],
						{ stacked: true, aria: t("npmos.traffic.cached-vs-uncached") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.bytes-cached-vs-uncached" />}>
					{area(
						tl,
						period,
						[
							{ key: "cachedBytes", label: t("npmos.traffic.series.cached"), color: "var(--series-3)" },
							{
								key: "uncachedBytes",
								label: t("npmos.traffic.series.uncached"),
								color: "var(--series-neutral)",
							},
						],
						{ stacked: true, format: formatBytes, aria: t("npmos.traffic.bytes-cached-vs-uncached") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.top.cached-paths" />}>
					<TopList rows={rows(data, "cachedPaths")} filter={(v) => filter("path", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.uncached-paths" />}>
					<TopList rows={rows(data, "uncachedPaths")} filter={(v) => filter("path", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.cached-types" />}>
					<TopList rows={rows(data, "cachedTypes")} filter={(v) => filter("contentType", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.uncached-types" />}>
					<TopList rows={rows(data, "uncachedTypes")} filter={(v) => filter("contentType", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.cache-statuses" />} wide>
					<TopList rows={rows(data, "statuses")} filter={(v) => filter("cache", v)} />
				</Panel>
			</Grid>
		</>
	);
}

function Endpoints({ rows: list, filter }: { rows: OriginEndpoint[]; filter: TabProps["filter"] }) {
	const [q, setQ] = useState("");
	const shown = list.filter((r) => !q || `${r.host}${r.path}`.toLowerCase().includes(q.toLowerCase()));
	return (
		<>
			<input
				type="search"
				className="form-control form-control-sm mb-2"
				placeholder={t("npmos.traffic.endpoints.search")}
				aria-label={t("npmos.traffic.endpoints.search")}
				value={q}
				onChange={(e) => setQ(e.target.value)}
			/>
			<div className={cn(hostStyles.scroller, styles.bleed)}>
				<table className={cn("table table-vcenter card-table", hostStyles.table)}>
					<thead>
						<tr>
							<th>
								<T id="npmos.traffic.endpoints.path" />
							</th>
							<th>
								<T id="npmos.traffic.endpoints.host" />
							</th>
							<th className="text-end">p95</th>
							<th className="text-end">4xx</th>
							<th className="text-end">5xx</th>
							<th className="text-end">
								<T id="npmos.traffic.endpoints.failed" />
							</th>
							<th className="text-end">
								<T id="npmos.traffic.endpoints.requests" />
							</th>
						</tr>
					</thead>
					<tbody>
						{shown.length === 0 ? (
							<tr>
								<td colSpan={7} className="text-secondary text-center small">
									<T id="npmos.traffic.no-data" />
								</td>
							</tr>
						) : (
							shown.map((r) => (
								<tr key={`${r.host} ${r.path}`}>
									<td className="text-truncate" style={{ maxWidth: "20rem" }}>
										<button
											type="button"
											className={styles.linkButton}
											onClick={() => filter("path", r.path)}
										>
											{r.path}
										</button>
									</td>
									<td>{r.host}</td>
									<td className="text-end">{formatMs(r.p95)}</td>
									<td className="text-end">{formatPercent(r.rate4xx, 1)}</td>
									<td className="text-end">{formatPercent(r.rate5xx, 1)}</td>
									<td className="text-end">{formatCount(r.failed)}</td>
									<td className="text-end">{formatCount(r.requests)}</td>
								</tr>
							))
						)}
					</tbody>
				</table>
			</div>
		</>
	);
}

export function OriginTab({ data, period, filter }: TabProps) {
	return (
		<>
			<Kpis>
				<Kpi
					label={<T id="npmos.traffic.kpi.reachability" />}
					value={formatPercent(kpi(data, "reachability")?.value)}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.connection" />}
					value={formatPercent(kpi(data, "connectionSuccess")?.value)}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.origin-p50" />}
					value={formatMs(kpi(data, "p50")?.value)}
					series={kpi(data, "p50")?.series}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.origin-errors" />}
					value={formatPercent(kpi(data, "errorRate")?.value)}
				/>
				<Kpi
					label={<T id="npmos.traffic.kpi.to-origin" />}
					value={formatCount(kpi(data, "requests")?.value)}
					series={kpi(data, "requests")?.series}
					color="var(--series-3)"
				/>
				<Kpi label={<T id="npmos.traffic.kpi.origin-bytes" />} value={formatBytes(kpi(data, "bytes")?.value)} />
			</Kpis>
			<Grid>
				<Panel title={<T id="npmos.traffic.origin-outcomes" />}>
					{area(
						data.timeline,
						period,
						[
							{ key: "reached", label: t("npmos.traffic.series.reached"), color: "var(--series-1)" },
							{ key: "failed", label: t("npmos.traffic.series.failed"), color: "var(--series-2)" },
						],
						{ stacked: true, aria: t("npmos.traffic.origin-outcomes") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.origin-breakdown" />}>
					{area(
						data.timeline,
						period,
						[
							{ key: "connectMs", label: t("npmos.traffic.series.connect"), color: "var(--series-1)" },
							{ key: "upstreamMs", label: t("npmos.traffic.series.wait"), color: "var(--series-5)" },
						],
						{ format: formatMs, legendTotal: "none", aria: t("npmos.traffic.origin-breakdown") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.origin-percentiles" />}>
					{area(
						data.percentiles ?? [],
						period,
						[
							{ key: "p50", label: "p50", color: "var(--series-1)" },
							{ key: "p95", label: "p95", color: "var(--series-5)" },
							{ key: "p99", label: "p99", color: "var(--series-2)" },
						],
						{ format: formatMs, legendTotal: "none", aria: t("npmos.traffic.origin-percentiles") },
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.origin-requests" />}>
					{area(
						data.timeline,
						period,
						[{ key: "toOrigin", label: t("npmos.traffic.series.requests"), color: "var(--series-3)" }],
						{
							aria: t("npmos.traffic.origin-requests"),
						},
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.origin-statuses" />}>
					{bars(
						data.timeline,
						period,
						[
							{ key: "u2xx", label: "2xx", color: "var(--series-3)" },
							{ key: "u3xx", label: "3xx", color: "var(--series-1)" },
							{ key: "u4xx", label: "4xx", color: "var(--series-5)" },
							{ key: "u5xx", label: "5xx", color: "var(--series-2)" },
							{ key: "u1xx", label: "1xx", color: "var(--series-neutral)" },
						],
						t("npmos.traffic.origin-statuses"),
					)}
				</Panel>
				<Panel title={<T id="npmos.traffic.top.origin-paths" />}>
					<TopList rows={rows(data, "paths")} filter={(v) => filter("path", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.origin-statuses" />}>
					<TopList rows={rows(data, "statuses")} />
				</Panel>
				<Panel title={<T id="npmos.traffic.top.origins" />}>
					<TopList rows={rows(data, "origins")} filter={(v) => filter("origin", v)} />
				</Panel>
				<Panel title={<T id="npmos.traffic.endpoints" />} wide>
					<Endpoints rows={(data.top?.endpoints ?? []) as OriginEndpoint[]} filter={filter} />
				</Panel>
			</Grid>
		</>
	);
}

export const TAB_VIEWS = {
	requests: RequestsTab,
	visitors: VisitorsTab,
	performance: PerformanceTab,
	security: SecurityTab,
	cache: CacheTab,
	origin: OriginTab,
} as const;
