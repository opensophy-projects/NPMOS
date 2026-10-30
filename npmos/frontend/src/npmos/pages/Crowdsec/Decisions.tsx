// CrowdSec → Decisions and Alerts: active bans and captchas (search, filters, unban one or many,
// ban by hand), alerts of the scenarios with their source and host.
import cn from "classnames";
import { useMemo, useState } from "react";
import { T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { type CrowdsecAlert, type Decision, unban, useAlerts, useDecisions } from "../../crowdsec/api";
import { showBanModal } from "../../crowdsec/BanModal";
import { originLabel, remaining, t } from "../../crowdsec/labels";
import { useCan } from "../../rbac/hooks";
import { dateTime, timeAgo } from "../../ui/time";
import styles from "../Pki/Pki.module.css";
import { SearchField } from "../../ui/SearchField";

const PAGE = 100;

/** "3h59m55.1s" → seconds */
const seconds = (d: string) => {
	const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(d || "");
	return m ? Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0) : 0;
};

interface DecisionRow {
	key: string;
	ids: number[];
	value: string;
	type: string;
	scenarios: string[];
	origins: string[];
	/** the longest time left */
	duration: string;
}

const groupDecisions = (list: Decision[]): DecisionRow[] => {
	const rows = new Map<string, DecisionRow>();
	for (const d of list) {
		const key = `${d.value}|${d.type}`;
		const row = rows.get(key);
		if (!row) {
			rows.set(key, {
				key,
				ids: [d.id],
				value: d.value,
				type: d.type,
				scenarios: [d.scenario],
				origins: [d.origin],
				duration: d.duration,
			});
			continue;
		}
		row.ids.push(d.id);
		if (!row.scenarios.includes(d.scenario)) row.scenarios.push(d.scenario);
		if (!row.origins.includes(d.origin)) row.origins.push(d.origin);
		if (seconds(d.duration) > seconds(row.duration)) row.duration = d.duration;
	}
	return [...rows.values()];
};

const TYPE_TONE: Record<string, string> = { ban: "bg-red-lt", captcha: "bg-yellow-lt" };

export function DecisionsTab({ refresh }: { refresh: () => void }) {
	const can = useCan();
	const [q, setQ] = useState("");
	const [type, setType] = useState("");
	const [origin, setOrigin] = useState("");
	const [offset, setOffset] = useState(0);
	const [selected, setSelected] = useState<number[]>([]);
	const decisions = useDecisions({ q, type, origin, offset, limit: PAGE }, { refetchInterval: 15000 });
	// one row per address and decision type: a scenario ban and a ban by hand of the same address
	// are one line with both scenarios, the longest time left and every id (unban removes all)
	const items = useMemo(() => groupDecisions(decisions.data?.items ?? []), [decisions.data]);
	const total = decisions.data?.total ?? 0;
	const decide = can("crowdsec", "decide");

	const reload = () => {
		setSelected([]);
		decisions.refetch();
		refresh();
	};
	const remove = async (data: { ids?: number[]; values?: string[] }) => {
		try {
			const { deleted } = await unban(data);
			showSuccess(t("npmos.crowdsec.unban.done", { count: deleted }));
		} catch (err: any) {
			showError(err.message);
		}
		reload();
	};

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.filters}>
				<SearchField
					variant="inset"
					value={q}
					onChange={(value) => {
						setQ(value);
						setOffset(0);
					}}
					placeholder={t("npmos.crowdsec.decisions.search")}
				/>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.crowdsec.decision")}
					value={type}
					onChange={(e) => setType(e.target.value)}
				>
					<option value="">{t("npmos.crowdsec.decision.all")}</option>
					<option value="ban">{t("npmos.crowdsec.decision.ban")}</option>
					<option value="captcha">{t("npmos.crowdsec.decision.captcha")}</option>
				</select>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.crowdsec.origin")}
					value={origin}
					onChange={(e) => setOrigin(e.target.value)}
				>
					<option value="">{t("npmos.crowdsec.origin.all")}</option>
					{["crowdsec", "cscli", "lists", "appsec"].map((o) => (
						<option key={o} value={o}>
							{originLabel(o)}
						</option>
					))}
				</select>
				{decide && selected.length > 0 && (
					<button
						type="button"
						className="btn btn-sm btn-outline-danger"
						onClick={() => remove({ ids: selected })}
					>
						<T id="npmos.crowdsec.unban.selected" data={{ count: selected.length }} />
					</button>
				)}
				{decide && (
					<button
						type="button"
						className="btn btn-sm btn-primary ms-auto"
						onClick={() => showBanModal({ onDone: reload })}
					>
						<T id="npmos.crowdsec.ban.title" />
					</button>
				)}
			</div>
			{decisions.isError ? (
				<p className="text-danger mb-0">{decisions.error.message}</p>
			) : !items.length ? (
				<p className={styles.empty}>
					<T
						id={
							decisions.isLoading
								? "loading"
								: q || type || origin
									? "npmos.crowdsec.none-found"
									: "npmos.crowdsec.decisions.none"
						}
					/>
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								{decide && (
									<th className="w-1">
										<input
											type="checkbox"
											className="form-check-input"
											aria-label={t("npmos.crowdsec.select-all")}
											checked={items.every((d) => d.ids.every((id) => selected.includes(id)))}
											onChange={(e) =>
												setSelected(e.target.checked ? items.flatMap((d) => d.ids) : [])
											}
										/>
									</th>
								)}
								<th>
									<T id="npmos.crowdsec.value" />
								</th>
								<th>
									<T id="npmos.crowdsec.decision" />
								</th>
								<th>
									<T id="npmos.crowdsec.scenario" />
								</th>
								<th>
									<T id="npmos.crowdsec.origin" />
								</th>
								<th>
									<T id="npmos.crowdsec.left" />
								</th>
								{decide && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{items.map((d) => (
								<tr key={d.key}>
									{decide && (
										<td>
											<input
												type="checkbox"
												className="form-check-input"
												aria-label={d.value}
												checked={d.ids.every((id) => selected.includes(id))}
												onChange={(e) =>
													setSelected(
														e.target.checked
															? [...selected, ...d.ids]
															: selected.filter((x) => !d.ids.includes(x)),
													)
												}
											/>
										</td>
									)}
									<td className="font-monospace">{d.value}</td>
									<td>
										<span className={cn("badge", TYPE_TONE[d.type] || "bg-secondary-lt")}>
											{["ban", "captcha"].includes(d.type)
												? t(`npmos.crowdsec.decision.${d.type}`)
												: d.type}
										</span>
									</td>
									<td className={styles.sub}>{d.scenarios.join(", ")}</td>
									<td>{d.origins.map(originLabel).join(", ")}</td>
									<td className="text-nowrap">{remaining(d.duration)}</td>
									{decide && (
										<td>
											<button
												type="button"
												className="btn btn-sm btn-ghost-danger"
												onClick={() => remove({ ids: d.ids })}
											>
												<T id="npmos.crowdsec.unban" />
											</button>
										</td>
									)}
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
			{total > PAGE && (
				<div className="d-flex align-items-center gap-2 mt-2 small">
					<button
						type="button"
						className="btn btn-sm"
						disabled={offset === 0}
						onClick={() => setOffset(Math.max(0, offset - PAGE))}
					>
						<T id="npmos.crowdsec.page.prev" />
					</button>
					<span>
						<T
							id="npmos.crowdsec.page"
							data={{ from: offset + 1, to: Math.min(total, offset + PAGE), total }}
						/>
					</span>
					<button
						type="button"
						className="btn btn-sm"
						disabled={offset + PAGE >= total}
						onClick={() => setOffset(offset + PAGE)}
					>
						<T id="npmos.crowdsec.page.next" />
					</button>
				</div>
			)}
		</section>
	);
}

const meta = (a: CrowdsecAlert, key: string) => {
	const m = a.meta.find((x) => x.key === key)?.value;
	if (!m) return "";
	try {
		const v = JSON.parse(m);
		return Array.isArray(v) ? v.join(", ") : String(v);
	} catch {
		return m;
	}
};

export function AlertsTab({ initialQuery = "", refresh }: { initialQuery?: string; refresh: () => void }) {
	const can = useCan();
	const [q, setQ] = useState(initialQuery);
	const [active, setActive] = useState(false);
	const alerts = useAlerts({ limit: 300, active }, { refetchInterval: 30000 });
	const rows = useMemo(() => {
		const s = q.trim().toLowerCase();
		return (alerts.data ?? []).filter(
			(a) =>
				!s ||
				[a.scenario, a.source.ip, a.source.value, a.source.cn, meta(a, "target_fqdn"), a.message]
					.join(" ")
					.toLowerCase()
					.includes(s),
		);
	}, [alerts.data, q]);
	const decide = can("crowdsec", "decide");

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.filters}>
				<SearchField
					variant="inset"
					value={q}
					onChange={(value) => setQ(value)}
					placeholder={t("npmos.crowdsec.alerts.search")}
				/>
				<label className="form-check form-switch mb-0">
					<input
						type="checkbox"
						className="form-check-input"
						checked={active}
						onChange={(e) => setActive(e.target.checked)}
					/>
					<span className="form-check-label">
						<T id="npmos.crowdsec.alerts.active" />
					</span>
				</label>
			</div>
			{alerts.isError ? (
				<p className="text-danger mb-0">{alerts.error.message}</p>
			) : !rows.length ? (
				<p className={styles.empty}>
					<T
						id={
							alerts.isLoading
								? "loading"
								: q
									? "npmos.crowdsec.none-found"
									: "npmos.crowdsec.alerts.none"
						}
					/>
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.crowdsec.time" />
								</th>
								<th>
									<T id="npmos.crowdsec.scenario" />
								</th>
								<th>
									<T id="npmos.crowdsec.source" />
								</th>
								<th>
									<T id="npmos.crowdsec.host" />
								</th>
								<th>
									<T id="npmos.crowdsec.events" />
								</th>
								<th>
									<T id="npmos.crowdsec.decision" />
								</th>
								{decide && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{rows.map((a) => {
								const ip = a.source.ip || a.source.value || "";
								const d = a.decisions[0];
								return (
									<tr key={a.id}>
										<td className="text-nowrap" title={dateTime(a.createdAt)}>
											{timeAgo(a.createdAt)}
										</td>
										<td>
											<div>{a.scenario}</div>
											{a.simulated && (
												<span className="badge bg-secondary-lt">
													<T id="npmos.crowdsec.simulated" />
												</span>
											)}
										</td>
										<td className="font-monospace">
											{ip}
											{a.source.cn && <span className="text-secondary ms-1">{a.source.cn}</span>}
										</td>
										<td className={styles.used}>{meta(a, "target_fqdn") || "—"}</td>
										<td>{a.eventsCount}</td>
										<td>
											{d ? (
												<span className={cn("badge", TYPE_TONE[d.type] || "bg-secondary-lt")}>
													{["ban", "captcha"].includes(d.type)
														? t(`npmos.crowdsec.decision.${d.type}`)
														: d.type}{" "}
													{remaining(d.duration)}
												</span>
											) : (
												<span className="text-secondary">—</span>
											)}
										</td>
										{decide && (
											<td>
												{ip && a.source.scope !== "Range" && !d && (
													<button
														type="button"
														className="btn btn-sm btn-ghost-danger"
														onClick={() =>
															showBanModal({
																values: [ip],
																reason: a.scenario,
																onDone: refresh,
															})
														}
													>
														<T id="npmos.crowdsec.ban" />
													</button>
												)}
												{d && (
													<button
														type="button"
														className="btn btn-sm btn-ghost-secondary"
														onClick={async () => {
															try {
																await unban({ ids: a.decisions.map((x) => x.id) });
																showSuccess(
																	t("npmos.crowdsec.unban.done", {
																		count: a.decisions.length,
																	}),
																);
															} catch (err: any) {
																showError(err.message);
															}
															alerts.refetch();
															refresh();
														}}
													>
														<T id="npmos.crowdsec.unban" />
													</button>
												)}
											</td>
										)}
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}
