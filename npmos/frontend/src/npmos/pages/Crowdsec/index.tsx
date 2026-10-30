// Security → CrowdSec (docs/ROADMAP.md, phase 7; ADR-0010), instead of the CrowdSec Console and
// cscli: the state of the local API, what CrowdSec reads and decides, decisions and alerts, local
// blocklists, the hub, machines and bouncers, and every setting. Nothing here needs the internet.
import { useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import Alert from "react-bootstrap/Alert";
import { Link, useSearchParams } from "react-router-dom";
import { HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { applySettings, type CrowdsecOverview, useCrowdsec, useCrowdsecSettings } from "../../crowdsec/api";
import { showBanModal } from "../../crowdsec/BanModal";
import { originLabel, t } from "../../crowdsec/labels";
import { useCan } from "../../rbac/hooks";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../Pki/Pki.module.css";
import { BlocklistsTab, RegistryTab } from "./Blocklists";
import { AlertsTab, DecisionsTab } from "./Decisions";
import { HubTab } from "./Hub";
import { SettingsTab } from "./Settings";

const TABS = ["overview", "decisions", "alerts", "blocklists", "hub", "settings", "registry"] as const;
type Tab = (typeof TABS)[number];

const n = (v: number) => intl.formatNumber(v);

function Summary({ data }: { data: CrowdsecOverview }) {
	const items: [string, React.ReactNode, string?][] = [
		[
			"npmos.crowdsec.summary.lapi",
			<T key="lapi" id={data.lapi.healthy ? "npmos.crowdsec.lapi.ok" : "npmos.crowdsec.lapi.down"} />,
			data.lapi.healthy ? "text-green" : "text-red",
		],
		["npmos.crowdsec.summary.decisions", n(data.decisions.total)],
		["npmos.crowdsec.summary.alerts", n(data.alerts24h)],
		["npmos.crowdsec.summary.machines", n(data.machines.length)],
		["npmos.crowdsec.summary.bouncers", n(data.bouncers.length)],
		[
			"npmos.crowdsec.summary.hub",
			data.hub.outdated ? `${n(data.hub.installed)} / ${n(data.hub.outdated)}` : n(data.hub.installed),
			data.hub.outdated ? "text-yellow" : undefined,
		],
	];
	return (
		<div className={styles.summary}>
			{items.map(([label, value, tone]) => (
				<div className={cn("card", styles.stat)} key={label}>
					<div className={cn(styles.statValue, tone)}>{value}</div>
					<div className={styles.statLabel}>
						<T id={label} />
					</div>
				</div>
			))}
		</div>
	);
}

function Status({ on, label }: { on: boolean; label: string }) {
	return (
		<li className={styles.item}>
			<span className={cn("badge", on ? "bg-green-lt" : "bg-secondary-lt")}>
				<T id={on ? "enabled" : "disabled"} />
			</span>
			<span>
				<T id={label} />
			</span>
		</li>
	);
}

function Counters({
	heading,
	rows,
	empty,
}: {
	heading: string;
	rows: { key: string; value: number }[];
	empty: string;
}) {
	return (
		<section className={cn("card", styles.card)}>
			<h3 className="card-title">
				<T id={heading} />
			</h3>
			{rows.length ? (
				<ul className={styles.list}>
					{rows.map((r) => (
						<li className={cn(styles.item, "justify-content-between")} key={r.key}>
							<span className={cn(styles.sub, "font-monospace")} title={r.key}>
								{r.key || "—"}
							</span>
							<span>{n(r.value)}</span>
						</li>
					))}
				</ul>
			) : (
				<p className={styles.empty}>
					<T id={empty} />
				</p>
			)}
		</section>
	);
}

function OverviewTab({ data, go }: { data: CrowdsecOverview; go: (tab: Tab) => void }) {
	const m = data.metrics;
	const s = data.settings;
	return (
		<>
			<div className="row g-3">
				<div className="col-lg-6">
					<section className={cn("card h-100", styles.card)}>
						<h3 className="card-title">
							<T id="npmos.crowdsec.protection" />
						</h3>
						<ul className={styles.list}>
							<Status on={s.bouncer} label="npmos.crowdsec.protection.bouncer" />
							<Status on={s.sources.nginx} label="npmos.crowdsec.protection.nginx" />
							<Status on={s.sources.openappsec} label="npmos.crowdsec.protection.openappsec" />
							<li className={styles.item}>
								<span
									className={cn("badge", s.openappsecBan.enabled ? "bg-green-lt" : "bg-secondary-lt")}
								>
									<T id={s.openappsecBan.enabled ? "enabled" : "disabled"} />
								</span>
								<span>
									<T
										id="npmos.crowdsec.protection.openappsec-ban"
										data={{ events: s.openappsecBan.events, minutes: s.openappsecBan.minutes }}
									/>
								</span>
							</li>
							<Status on={s.appsec} label="npmos.crowdsec.protection.appsec" />
						</ul>
						<button
							type="button"
							className="btn btn-sm mt-3 align-self-start"
							onClick={() => go("settings")}
						>
							<T id="npmos.crowdsec.open-settings" />
						</button>
					</section>
				</div>
				<div className="col-lg-6">
					<section className={cn("card h-100", styles.card)}>
						<h3 className="card-title">
							<T id="npmos.crowdsec.activity" />
						</h3>
						{m ? (
							<ul className={styles.list}>
								<li className={cn(styles.item, "justify-content-between")}>
									<T id="npmos.crowdsec.metrics.parsed" />
									<span>
										{n(m.linesParsed)} / {n(m.linesParsed + m.linesUnparsed)}
									</span>
								</li>
								{s.appsec && (
									<li className={cn(styles.item, "justify-content-between")}>
										<T id="npmos.crowdsec.metrics.appsec" />
										<span>
											{n(m.appsecBlocked)} / {n(m.appsecRequests)}
										</span>
									</li>
								)}
								{Object.entries(data.decisions.byOrigin).map(([origin, count]) => (
									<li className={cn(styles.item, "justify-content-between")} key={origin}>
										<span>
											<T
												id="npmos.crowdsec.metrics.decisions-of"
												data={{ origin: originLabel(origin) }}
											/>
										</span>
										<span>{n(count)}</span>
									</li>
								))}
								<li className={cn(styles.item, "justify-content-between")}>
									<T id="npmos.crowdsec.version" />
									<span className="font-monospace">{m.version || "—"}</span>
								</li>
							</ul>
						) : (
							<p className={styles.empty}>
								<T id="npmos.crowdsec.metrics.none" />
							</p>
						)}
					</section>
				</div>
			</div>
			<div className="row g-3">
				<div className="col-lg-6">
					<Counters
						heading="npmos.crowdsec.metrics.sources"
						rows={m?.linesRead ?? []}
						empty="npmos.crowdsec.metrics.sources.none"
					/>
				</div>
				<div className="col-lg-6">
					<Counters
						heading="npmos.crowdsec.metrics.overflows"
						rows={m?.overflows ?? []}
						empty="npmos.crowdsec.metrics.overflows.none"
					/>
				</div>
			</div>
		</>
	);
}

function CrowdsecPage() {
	const can = useCan();
	const queryClient = useQueryClient();
	const [params, setParams] = useSearchParams();
	const tab = (TABS.find((x) => x === params.get("tab")) ?? "overview") as Tab;
	const go = (x: Tab) => setParams(x === "overview" ? {} : { tab: x }, { replace: true });
	const overview = useCrowdsec({ refetchInterval: 30000 });
	const settings = useCrowdsecSettings();
	const refresh = () => {
		for (const key of [
			"npmos-crowdsec",
			"npmos-crowdsec-settings",
			"npmos-crowdsec-decisions",
			"npmos-crowdsec-alerts",
			"npmos-crowdsec-hosts",
		])
			queryClient.invalidateQueries({ queryKey: [key] });
	};

	if (overview.isLoading || settings.isLoading) return <LoadingPage noLogo />;
	if (overview.isError || !overview.data)
		return <Alert variant="danger">{overview.error?.message || <T id="npmos.common.unknown-error" />}</Alert>;
	const data = overview.data;

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.crowdsec" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.crowdsec.subtitle" />
					</p>
				</div>
				<div className={hostStyles.toolbar}>
					{can("crowdsec", "decide") && (
						<button
							type="button"
							className={cn("btn btn-primary btn-sm", hostStyles.add)}
							onClick={() => showBanModal({ onDone: refresh })}
						>
							<T id="npmos.crowdsec.ban.title" />
						</button>
					)}
				</div>
			</div>

			{!data.lapi.healthy && (
				<Alert variant="danger" className="mb-0">
					<T id="npmos.crowdsec.lapi.down.text" data={{ error: data.lapi.error }} />{" "}
					<Link to="/system/services">
						<T id="npmos.crowdsec.open-services" />
					</Link>
				</Alert>
			)}
			{data.pending.length > 0 && can("crowdsec", "manage") && (
				<Alert variant="warning" className="mb-0 d-flex align-items-center gap-3">
					<span>
						<T id="npmos.crowdsec.settings.pending" data={{ files: data.pending.join(", ") }} />
					</span>
					<button
						type="button"
						className="btn btn-sm ms-auto"
						onClick={async () => {
							try {
								await applySettings();
								showSuccess(t("npmos.crowdsec.settings.applied"));
							} catch (err: any) {
								showError(err.message);
							}
							refresh();
						}}
					>
						<T id="npmos.crowdsec.apply" />
					</button>
				</Alert>
			)}

			<Summary data={data} />

			<ul className="nav nav-tabs flex-nowrap overflow-auto">
				{TABS.map((x) => (
					<li className="nav-item" key={x}>
						<button
							type="button"
							className={cn("nav-link text-nowrap", { active: tab === x })}
							onClick={() => go(x)}
						>
							<T id={`npmos.crowdsec.tab.${x}`} />
						</button>
					</li>
				))}
			</ul>

			{tab === "overview" && <OverviewTab data={data} go={go} />}
			{tab === "decisions" && <DecisionsTab refresh={refresh} />}
			{tab === "alerts" && <AlertsTab initialQuery={params.get("q") ?? ""} refresh={refresh} />}
			{tab === "blocklists" && <BlocklistsTab shareEnabled={!!settings.data?.shareEnabled} refresh={refresh} />}
			{tab === "hub" && <HubTab onlineHub={!!settings.data?.onlineHub} refresh={refresh} />}
			{tab === "settings" && settings.data && <SettingsTab data={settings.data} refresh={refresh} />}
			{tab === "registry" && <RegistryTab />}
		</div>
	);
}

const Crowdsec = () => (
	<HasPermission rbac="crowdsec" permission={VIEW} pageLoading loadingNoLogo>
		<CrowdsecPage />
	</HasPermission>
);

export default Crowdsec;
