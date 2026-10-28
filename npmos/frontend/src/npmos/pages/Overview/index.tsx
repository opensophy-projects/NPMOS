// Overview (docs/ROADMAP.md, phase 2): hosts by type, system monitoring, WAF, a short summary of
// WAF events and the notices that need the administrator. Replaces the upstream dashboard.
import { IconArrowRight } from "@tabler/icons-react";
import cn from "classnames";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { LoadingPage } from "src/components";
import { useCertificates, useDeadHosts, useProxyHosts, useRedirectionHosts, useStreams, useUser } from "src/hooks";
import { intl, T } from "src/locale";
import {
	CERTIFICATES,
	DEAD_HOSTS,
	hasPermission,
	PROXY_HOSTS,
	REDIRECTION_HOSTS,
	type Section,
	STREAMS,
	VIEW,
} from "src/modules/Permissions";
import { useEvents, useServices, useUpstreamChecks, useWafHosts, useWafStatus } from "../../hooks";
import { useCan } from "../../rbac/hooks";
import { Admonition, type AdmonitionVariant } from "../../ui/Admonition";
import { timeAgo } from "../../ui/time";
import { filtersToParams, HOST_TYPES, type HostRow, type HostType, recommendations, toRows } from "../Hosts/rows";
import {
	certificateNotices,
	hostNotices,
	type NoticeLevel,
	serviceNotices,
	serviceProblem,
	sortNotices,
	wafNotices,
} from "./notices";
import styles from "./Overview.module.css";

const SECTION: Record<HostType, Section> = {
	proxy: PROXY_HOSTS,
	redirect: REDIRECTION_HOSTS,
	stream: STREAMS,
	dead: DEAD_HOSTS,
};

const VARIANT: Record<NoticeLevel, AdmonitionVariant> = { alert: "alert", warning: "warning", info: "tip" };

function Panel({ title, link, children }: { title: ReactNode; link?: string; children: ReactNode }) {
	return (
		<section className={cn("card", styles.panel)}>
			<div className={styles.panelHead}>
				<h2 className={styles.panelTitle}>{title}</h2>
				{link && (
					<Link to={link} className={styles.more}>
						<T id="npmos.overview.open" />
						<IconArrowRight size={14} />
					</Link>
				)}
			</div>
			{children}
		</section>
	);
}

function Line({ label, value, tone }: { label: ReactNode; value: ReactNode; tone?: "ok" | "warning" | "alert" }) {
	return (
		<div className={styles.line}>
			<span className={styles.lineLabel}>{label}</span>
			<span className={cn(styles.lineValue, tone && styles[tone])}>{value}</span>
		</div>
	);
}

function HostCard({ type, rows }: { type: HostType; rows: HostRow[] }) {
	const enabled = rows.filter((r) => r.enabled).length;
	const problems = rows.filter((r) => r.status === "error" || r.upstream === "down").length;
	const link = `/hosts?${filtersToParams({ q: "", rules: [{ field: "type", op: "is", value: type }] })}`;
	return (
		<Link to={link} className={cn("card", styles.stat)}>
			<span className={styles.statValue}>{rows.length}</span>
			<span className={styles.statLabel}>
				<T id={`npmos.overview.hosts.${type}`} data={{ count: rows.length }} />
			</span>
			<span className={styles.statMeta}>
				<T id="npmos.overview.hosts.enabled" data={{ count: enabled }} />
				{problems > 0 && (
					<span className={styles.alert}>
						{" · "}
						<T id="npmos.overview.hosts.problems" data={{ count: problems }} />
					</span>
				)}
			</span>
		</Link>
	);
}

function OverviewPage() {
	const { data: me } = useUser("me");
	const perms = me?.permissions;
	const roles = me?.roles;
	const rbac = useCan();
	const can = (type: HostType) => hasPermission(SECTION[type], VIEW, perms, roles);
	const types = HOST_TYPES.filter(can);

	const proxy = useProxyHosts(["certificate"], { enabled: can("proxy") });
	const redirect = useRedirectionHosts(["certificate"], { enabled: can("redirect") });
	const stream = useStreams(["certificate"], { enabled: can("stream") });
	const dead = useDeadHosts(["certificate"], { enabled: can("dead") });
	const waf = useWafHosts({ enabled: can("proxy") });
	const upstreams = useUpstreamChecks({ enabled: can("proxy") || can("stream") });
	const certificates = useCertificates([], { enabled: hasPermission(CERTIFICATES, VIEW, perms, roles) });
	const wafStatus = useWafStatus({ enabled: rbac("waf_policy") });
	const services = useServices({ enabled: rbac("services"), refetchInterval: 15000 });
	const eventsOptions = { enabled: rbac("waf_events"), refetchInterval: 30000 };
	const events = useEvents({ period: "24h", important: true, limit: 1 }, false, eventsOptions);
	const preventedEvents = useEvents(
		{ period: "24h", important: true, action: "prevent", limit: 1 },
		false,
		eventsOptions,
	);

	if (!me || [proxy, redirect, stream, dead].some((q, i) => can(HOST_TYPES[i]) && q.isLoading)) {
		return <LoadingPage />;
	}

	const rows = toRows({
		proxy: proxy.data,
		redirect: redirect.data,
		stream: stream.data,
		dead: dead.data,
		waf: waf.data,
		upstreams: upstreams.data,
	});
	const notices = sortNotices([
		...serviceNotices(rbac("services") ? services.data : undefined),
		...wafNotices(rbac("waf_policy") ? wafStatus.data : undefined),
		...hostNotices(recommendations(rows, wafStatus.data?.enabled)),
		...certificateNotices(
			certificates.data ?? [],
			rows.flatMap((r) => (r.certificate ? [r.certificate.id] : [])),
		),
	]);

	const proxies = rows.filter((r) => r.type === "proxy");
	const wafCount = (state: string) => proxies.filter((r) => r.waf === state).length;
	const running = (services.data ?? []).filter((s) => !serviceProblem(s)).length;
	const recent = events.data ? `${events.data.total}${events.data.totalCapped ? "+" : ""}` : "—";
	const prevented = preventedEvents.data
		? `${preventedEvents.data.total}${preventedEvents.data.totalCapped ? "+" : ""}`
		: "—";

	return (
		<div className={styles.page}>
			<div className={styles.head}>
				<h1 className={styles.title}>
					<T id="npmos.nav.overview" />
				</h1>
				<p className={styles.subtitle}>
					<T id="npmos.overview.subtitle" />
				</p>
			</div>

			{types.length > 0 && (
				<div className={styles.stats}>
					{types.map((type) => (
						<HostCard key={type} type={type} rows={rows.filter((r) => r.type === type)} />
					))}
				</div>
			)}

			{(rbac("services") || rbac("waf_policy") || rbac("waf_events")) && (
				<div className={styles.panels}>
					{rbac("services") && (
						<Panel title={<T id="npmos.overview.system" />} link="/system/services">
							{services.isError ? (
								<Line label={<T id="npmos.services" />} value={services.error.message} tone="alert" />
							) : (
								<>
									<Line
										label={<T id="npmos.overview.system.services" />}
										value={
											<T
												id="npmos.overview.system.running"
												data={{ running, total: services.data?.length ?? 0 }}
											/>
										}
										tone={services.data && running === services.data.length ? "ok" : "alert"}
									/>
									{(services.data ?? []).filter(serviceProblem).map((s) => (
										<Line
											key={s.service}
											label={s.name || s.service}
											value={s.status || s.state}
											tone="alert"
										/>
									))}
								</>
							)}
						</Panel>
					)}

					{rbac("waf_policy") && (
						<Panel title="WAF" link="/waf/agent">
							<Line
								label={<T id="npmos.overview.waf.state" />}
								value={<T id={wafStatus.data?.enabled ? "npmos.overview.on" : "npmos.overview.off"} />}
								tone={wafStatus.data?.enabled ? "ok" : "warning"}
							/>
							{wafStatus.data?.enabled && (
								<Line
									label={<T id="npmos.waf.agent" />}
									value={
										<T
											id={
												wafStatus.data.agent?.reachable
													? "npmos.overview.waf.agent-ok"
													: "npmos.overview.waf.agent-down"
											}
										/>
									}
									tone={wafStatus.data.agent?.reachable ? "ok" : "alert"}
								/>
							)}
							{(["prevent", "detect", "off"] as const).map((state) => (
								<Line
									key={state}
									label={
										<T
											id="npmos.overview.waf.hosts"
											data={{ mode: intl.formatMessage({ id: `npmos.hosts.waf.${state}` }) }}
										/>
									}
									value={wafCount(state)}
								/>
							))}
						</Panel>
					)}

					{rbac("waf_events") && (
						<Panel title={<T id="npmos.overview.analytics" />} link="/waf/events?important=1">
							<Line
								label={<T id="npmos.overview.analytics.important" />}
								value={recent}
								tone={events.data?.total ? "warning" : "ok"}
							/>
							<Line label={<T id="npmos.overview.analytics.prevented" />} value={prevented} />
							<Line
								label={<T id="npmos.overview.analytics.last" />}
								value={
									events.data?.events[0]?.time ? (
										<span title={events.data.events[0].host}>
											{timeAgo(events.data.events[0].time)}
										</span>
									) : (
										"—"
									)
								}
							/>
							<p className={styles.note}>
								<T id="npmos.overview.analytics.note" />
							</p>
						</Panel>
					)}
				</div>
			)}

			<section className={styles.notices}>
				<h2 className={styles.sectionTitle}>
					<T id="npmos.overview.notices" />
					{notices.length > 0 && <span className={styles.count}>{notices.length}</span>}
				</h2>
				{notices.length ? (
					notices.map((notice) => (
						<Admonition
							key={notice.key}
							compact
							variant={VARIANT[notice.level]}
							title={<T id={`npmos.notice.${notice.level}`} />}
							aside={
								<Link to={notice.link} className={styles.more}>
									<T id="npmos.overview.fix" />
									<IconArrowRight size={14} />
								</Link>
							}
						>
							<span className={styles.noticeTitle}>
								<T id={notice.id} data={notice.data} />
							</span>{" "}
							<T id={`${notice.id}.hint`} data={notice.data} />
						</Admonition>
					))
				) : (
					<Admonition compact variant="success" title={<T id="npmos.overview.all-good" />}>
						<T id="npmos.overview.all-good.hint" />
					</Admonition>
				)}
			</section>
		</div>
	);
}

export default function Overview() {
	return <OverviewPage />;
}
