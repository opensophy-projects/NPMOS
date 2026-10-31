// Agents → open-appsec → Learning: readiness of the hosts, the queue of what the agent is not sure about (and the
// suggestions of the tuning service), the history of labels with undo.
import { IconCheck, IconChevronLeft, IconChevronRight, IconPlayerSkipForward, IconShieldX } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useSearchParams } from "react-router-dom";
import { LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { setWafHost } from "../api";
import eventStyles from "../pages/WafEvents/Events.module.css";
import hostStyles from "../pages/Hosts/Hosts.module.css";
import { useCan } from "../rbac/hooks";
import { SearchField } from "../ui/SearchField";
import { dateTime, timeAgo } from "../ui/time";
import {
	type Decision,
	getLabels,
	getLearningHosts,
	getQueue,
	type LearningHost,
	type QueueGroup,
	type Reason,
	type Suggestion,
	undoLabel,
} from "./api";
import { showLabelModal } from "./LabelModal";
import styles from "./Learning.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const PAGE_SIZE = 25;
const PERIODS = ["24h", "7d", "30d"] as const;
const REASONS: Reason[] = ["blocked", "grey", "detected"];

const useRefresh = () => {
	const queryClient = useQueryClient();
	return () => {
		for (const key of ["npmos-learning-queue", "npmos-learning-labels", "npmos-learning-hosts"]) {
			queryClient.invalidateQueries({ queryKey: [key] });
		}
	};
};

function Readiness({ host }: { host: LearningHost }) {
	const level = host.stats?.level ?? 0;
	return (
		<span
			className={styles.level}
			title={host.stats ? t(`npmos.learning.recommendation.${host.stats.recommendation}`) : ""}
		>
			<span className={styles.levelBar} aria-hidden>
				{[1, 2, 3, 4, 5, 6].map((n) => (
					<span key={n} className={cn(styles.levelStep, n <= level && styles.levelStepOn)} />
				))}
			</span>
			<T id={`npmos.learning.readiness.${host.stats?.readiness ?? "none"}`} />
		</span>
	);
}

function Hosts({ manage }: { manage: boolean }) {
	const refresh = useRefresh();
	const { data, isLoading, isError, error } = useQuery({
		queryKey: ["npmos-learning-hosts"],
		queryFn: getLearningHosts,
		refetchInterval: 60000,
	});
	const [busy, setBusy] = useState<number | null>(null);

	const prevent = async (host: LearningHost) => {
		setBusy(host.id);
		try {
			await setWafHost(host.id, {
				enabled: true,
				mode: "prevent-learn",
				minimumConfidence: host.minimumConfidence as any,
			});
			showSuccess(t("npmos.learning.prevent.done", { name: host.name }));
			refresh();
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(null);
	};

	return (
		<div className={styles.section}>
			<div className={styles.sectionHead}>
				<div>
					<h2 className={styles.sectionTitle}>
						<T id="npmos.learning.hosts" />
					</h2>
					<p className={styles.sectionText}>
						<T id="npmos.learning.hosts.text" />
					</p>
				</div>
			</div>
			{data?.error && (
				<Alert variant="warning">
					<T id="npmos.learning.tuning-error" data={{ error: data.error }} />
				</Alert>
			)}
			<div className={cn("card", hostStyles.tableCard)}>
				{isLoading ? (
					<LoadingPage noLogo />
				) : isError || !data ? (
					<div className="card-body">
						<Alert variant="danger" className="mb-0">
							{(error as Error)?.message}
						</Alert>
					</div>
				) : (
					<div className={hostStyles.scroller}>
						<table className={cn("table table-vcenter card-table", hostStyles.table)}>
							<thead>
								<tr>
									<th>
										<T id="npmos.learning.host" />
									</th>
									<th>
										<T id="npmos.learning.mode" />
									</th>
									<th>
										<T id="npmos.learning.readiness" />
									</th>
									<th>
										<T id="npmos.learning.labels" />
									</th>
									<th>
										<T id="npmos.learning.false-positives" />
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{data.hosts.length === 0 ? (
									<tr>
										<td colSpan={6} className={hostStyles.empty}>
											<T id="npmos.learning.hosts.empty" />
										</td>
									</tr>
								) : (
									data.hosts.map((h) => (
										<tr key={h.id}>
											<td>{h.name}</td>
											<td>
												<T id={`npmos.learning.mode.${h.mode}`} />
											</td>
											<td>
												<Readiness host={h} />
												{h.stats && (
													<div className={styles.muted}>
														<T
															id={`npmos.learning.recommendation.${h.stats.recommendation}`}
														/>
													</div>
												)}
											</td>
											<td className={styles.num}>
												<T
													id="npmos.learning.labels.value"
													data={{
														benign: h.labels.benign,
														malicious: h.labels.malicious,
														queue: h.queue,
													}}
												/>
												{h.enforced > 0 && (
													<div className={styles.muted}>
														<T id="npmos.learning.enforced" data={{ count: h.enforced }} />
													</div>
												)}
											</td>
											<td className={styles.num}>
												{h.falsePositives.before || h.falsePositives.after ? (
													<T
														id="npmos.learning.false-positives.value"
														data={{
															before: h.falsePositives.before,
															after: h.falsePositives.after,
														}}
													/>
												) : (
													"—"
												)}
											</td>
											<td className="text-end">
												{h.readyToPrevent ? (
													manage ? (
														<button
															type="button"
															className="btn btn-sm btn-primary"
															disabled={busy === h.id}
															onClick={() => prevent(h)}
														>
															<T id="npmos.learning.prevent" />
														</button>
													) : (
														<span className={styles.ready}>
															<T id="npmos.learning.ready" />
														</span>
													)
												) : null}
											</td>
										</tr>
									))
								)}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
}

const DECISION_ICON: Record<Decision, React.ReactNode> = {
	benign: <IconCheck size={14} />,
	malicious: <IconShieldX size={14} />,
	dismiss: <IconPlayerSkipForward size={14} />,
};

function LabelButtons({ onLabel }: { onLabel: (d: Decision) => void }) {
	return (
		<div className={styles.actions}>
			{(["benign", "malicious", "dismiss"] as Decision[]).map((d) => (
				<button
					key={d}
					type="button"
					className="btn btn-sm"
					title={t(`npmos.learning.decision.${d}.text`)}
					aria-label={t(`npmos.learning.decision.${d}`)}
					onClick={() => onLabel(d)}
				>
					{DECISION_ICON[d]}
					{/* the most frequent answer keeps its word, the others are icons with a hint: the row fits the card */}
					{d === "benign" && <T id={`npmos.learning.decision.${d}`} />}
				</button>
			))}
		</div>
	);
}

function Queue({ label }: { label: boolean }) {
	const refresh = useRefresh();
	const [params, setParams] = useSearchParams();
	const asked = params.get("period") || "";
	const period = (PERIODS as readonly string[]).includes(asked) ? asked : "7d";
	const reason = (REASONS as string[]).includes(params.get("reason") || "") ? (params.get("reason") as Reason) : null;
	const q = params.get("q") || "";
	const page = Math.max(Number.parseInt(params.get("page") || "0", 10) || 0, 0);
	const [search, setSearch] = useState(q);

	const update = (changes: Record<string, string>) => {
		const next = new URLSearchParams(params);
		for (const [key, value] of Object.entries(changes)) {
			if (value) next.set(key, value);
			else next.delete(key);
		}
		if (!("page" in changes)) next.delete("page");
		setParams(next, { replace: true });
	};
	useEffect(() => setSearch(q), [q]);
	// biome-ignore lint/correctness/useExhaustiveDependencies: runs when the typed text changes
	useEffect(() => {
		if (search === q) return;
		const timer = setTimeout(() => update({ q: search }), 400);
		return () => clearTimeout(timer);
	}, [search]);

	const { data, isLoading, isError, error, isFetching } = useQuery({
		queryKey: ["npmos-learning-queue", period, reason, q, page],
		queryFn: () =>
			getQueue({
				period,
				reason: reason ?? undefined,
				q: q || undefined,
				limit: PAGE_SIZE,
				offset: page * PAGE_SIZE,
			}),
		refetchInterval: 60000,
	});
	const pages = data ? Math.max(Math.ceil(data.total / PAGE_SIZE), 1) : 1;
	const open = (group: QueueGroup, decision: Decision) => showLabelModal({ group, decision, onDone: refresh });
	const openSuggestion = (suggestion: Suggestion, decision: Decision) =>
		showLabelModal({ suggestion, decision, onDone: refresh });

	return (
		<div className={styles.section}>
			<div className={styles.sectionHead}>
				<div>
					<h2 className={styles.sectionTitle}>
						<T id="npmos.learning.queue" />
					</h2>
					<p className={styles.sectionText}>
						<T id="npmos.learning.queue.text" />
					</p>
				</div>
			</div>
			<div className={cn(hostStyles.toolbar, styles.toolbar)}>
				<SearchField value={search} onChange={setSearch} placeholder={t("npmos.learning.search")} />
				<div className={eventStyles.periods} role="group" aria-label={t("npmos.events.period")}>
					{PERIODS.map((p) => (
						<button
							key={p}
							type="button"
							className={cn(eventStyles.period, period === p && eventStyles.periodOn)}
							aria-pressed={period === p}
							onClick={() => update({ period: p === "7d" ? "" : p })}
						>
							<T id={`npmos.audit.period.${p}`} />
						</button>
					))}
				</div>
				<div className={styles.reasons} role="group" aria-label={t("npmos.learning.reason")}>
					{REASONS.map((r) => (
						<button
							key={r}
							type="button"
							className={cn(styles.reason, reason === r && styles.reasonOn)}
							aria-pressed={reason === r}
							title={t(`npmos.learning.reason.${r}.text`)}
							onClick={() => update({ reason: reason === r ? "" : r })}
						>
							<T id={`npmos.learning.reason.${r}`} />
							<span className={styles.reasonCount}>{data?.counts[r] ?? 0}</span>
						</button>
					))}
				</div>
			</div>

			<div className={cn("card", hostStyles.tableCard)}>
				{isLoading ? (
					<LoadingPage noLogo />
				) : isError || !data ? (
					<div className="card-body">
						<Alert variant="danger" className="mb-0">
							{(error as Error)?.message}
						</Alert>
					</div>
				) : (
					<>
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter card-table", hostStyles.table)}>
								<thead>
									<tr>
										<th>
											<T id="npmos.learning.what" />
										</th>
										<th>
											<T id="npmos.learning.events" />
										</th>
										<th>
											<T id="npmos.learning.score" />
										</th>
										<th>
											<T id="npmos.learning.last" />
										</th>
										{label && <th />}
									</tr>
								</thead>
								<tbody>
									{data.items.length === 0 ? (
										<tr>
											<td colSpan={label ? 5 : 4} className={hostStyles.empty}>
												<T id="npmos.learning.queue.empty" />
											</td>
										</tr>
									) : (
										data.items.map((g) => (
											<tr key={g.key}>
												<td className={styles.what}>
													<div className={styles.whatHead}>
														<span className={cn(styles.badge, styles[g.reason])}>
															<T id={`npmos.learning.reason.${g.reason}`} />
														</span>
														{g.new && (
															<span className={styles.newMark}>
																<T id="npmos.learning.new" />
															</span>
														)}
														<span>{g.hostName}</span>
													</div>
													<div className={styles.url}>{g.uri || "/"}</div>
													{(g.parameter || g.indicators) && (
														<div className={styles.muted}>
															{g.parameter && (
																<>
																	<T id="npmos.learning.parameter" />:{" "}
																	<span className={styles.mono}>{g.parameter}</span>
																</>
															)}
															{g.parameter && g.indicators ? " · " : ""}
															{g.indicators}
														</div>
													)}
												</td>
												<td className={cn(styles.num, styles.wrap)}>
													<div>{g.events.toLocaleString(intl.locale)}</div>
													<div className={styles.muted}>
														<T
															id="npmos.learning.events.value"
															data={{ sources: g.sources, blocked: g.blocked }}
														/>
													</div>
												</td>
												<td className={styles.num}>{g.score ?? "—"}</td>
												<td className={styles.num} title={g.last ? dateTime(g.last) : ""}>
													{g.last ? timeAgo(g.last) : "—"}
												</td>
												{label && (
													<td>
														<LabelButtons onLabel={(d) => open(g, d)} />
													</td>
												)}
											</tr>
										))
									)}
								</tbody>
							</table>
						</div>
						<div className={eventStyles.pager}>
							<span>
								<T id="npmos.learning.queue.total" data={{ total: data.total }} />
							</span>
							{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
							<div className={eventStyles.pagerButtons}>
								<span>
									<T id="npmos.audit.page" data={{ page: page + 1, pages }} />
								</span>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page === 0}
									onClick={() => update({ page: page > 1 ? String(page - 1) : "" })}
								>
									<IconChevronLeft size={16} />
								</button>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page + 1 >= pages}
									onClick={() => update({ page: String(page + 1) })}
								>
									<IconChevronRight size={16} />
								</button>
							</div>
						</div>
					</>
				)}
			</div>

			{data && (data.suggestions.length > 0 || data.suggestionsError) && (
				<div className={styles.section}>
					<div className={styles.sectionHead}>
						<div>
							<h2 className={styles.sectionTitle}>
								<T id="npmos.learning.suggestions" />
							</h2>
							<p className={styles.sectionText}>
								<T id="npmos.learning.suggestions.text" />
							</p>
						</div>
					</div>
					{data.suggestionsError && (
						<Alert variant="warning">
							<T id="npmos.learning.tuning-error" data={{ error: data.suggestionsError }} />
						</Alert>
					)}
					{data.suggestions.length > 0 && (
						<div className={cn("card", hostStyles.tableCard)}>
							<div className={hostStyles.scroller}>
								<table className={cn("table table-vcenter card-table", hostStyles.table)}>
									<thead>
										<tr>
											<th>
												<T id="npmos.learning.severity" />
											</th>
											<th>
												<T id="npmos.learning.what" />
											</th>
											<th>
												<T id="npmos.learning.attacks" />
											</th>
											{label && <th />}
										</tr>
									</thead>
									<tbody>
										{data.suggestions.map((s) => (
											<tr key={`${s.asset}:${s.id}`}>
												<td>{s.severity || "—"}</td>
												<td className={styles.what}>
													<div>{s.asset}</div>
													<div className={styles.muted}>
														<T id={`npmos.learning.scope.${s.type}`} />:{" "}
														<span className={styles.mono}>{s.title}</span>
													</div>
												</td>
												<td>{s.attackTypes.join(", ") || "—"}</td>
												{label && (
													<td>
														<LabelButtons onLabel={(d) => openSuggestion(s, d)} />
													</td>
												)}
											</tr>
										))}
									</tbody>
								</table>
							</div>
						</div>
					)}
				</div>
			)}
		</div>
	);
}

function History({ label }: { label: boolean }) {
	const refresh = useRefresh();
	const [page, setPage] = useState(0);
	const { data, isLoading, isError, error } = useQuery({
		queryKey: ["npmos-learning-labels", page],
		queryFn: () => getLabels({ limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
	});
	const pages = data ? Math.max(Math.ceil(data.total / PAGE_SIZE), 1) : 1;

	const undo = async (id: number) => {
		try {
			await undoLabel(id);
			showSuccess(t("npmos.learning.undo.done"));
			refresh();
		} catch (err: any) {
			showError(err.message);
		}
	};

	return (
		<div className={styles.section}>
			<div className={styles.sectionHead}>
				<div>
					<h2 className={styles.sectionTitle}>
						<T id="npmos.learning.history" />
					</h2>
					<p className={styles.sectionText}>
						<T id="npmos.learning.history.text" />
					</p>
				</div>
			</div>
			<div className={cn("card", hostStyles.tableCard)}>
				{isLoading ? (
					<LoadingPage noLogo />
				) : isError || !data ? (
					<div className="card-body">
						<Alert variant="danger" className="mb-0">
							{(error as Error)?.message}
						</Alert>
					</div>
				) : (
					<>
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter card-table", hostStyles.table)}>
								<thead>
									<tr>
										<th>
											<T id="npmos.learning.when" />
										</th>
										<th>
											<T id="npmos.learning.decision" />
										</th>
										<th>
											<T id="npmos.learning.what" />
										</th>
										<th>
											<T id="npmos.learning.effects" />
										</th>
										{label && <th />}
									</tr>
								</thead>
								<tbody>
									{data.items.length === 0 ? (
										<tr>
											<td colSpan={label ? 5 : 4} className={hostStyles.empty}>
												<T id="npmos.learning.history.empty" />
											</td>
										</tr>
									) : (
										data.items.map((l) => (
											<tr key={l.id} className={cn(l.undoneOn && "text-secondary")}>
												<td className={styles.num}>
													<div title={dateTime(l.createdOn)}>{timeAgo(l.createdOn)}</div>
													<div className={styles.muted}>{l.user?.name ?? "—"}</div>
												</td>
												<td>
													<span className={cn(styles.badge, styles[l.decision])}>
														<T id={`npmos.learning.decision.${l.decision}`} />
													</span>
													{l.undoneOn && (
														<div className={styles.muted}>
															<T
																id="npmos.learning.undone"
																data={{
																	who: l.undoneBy?.name ?? "—",
																	when: timeAgo(l.undoneOn),
																}}
															/>
														</div>
													)}
												</td>
												<td className={styles.what}>
													<div>{l.host}</div>
													{l.features.uri !== undefined && (
														<div className={styles.url}>{l.features.uri || "/"}</div>
													)}
													<div className={styles.muted}>
														{l.scopes.length
															? l.scopes
																	.map(
																		(s) =>
																			`${t(`npmos.learning.scope.${s.type}`)}: ${s.value}`,
																	)
																	.join(" · ")
															: "—"}
													</div>
													{l.note && <div className={styles.muted}>{l.note}</div>}
												</td>
												<td className={styles.muted}>
													{l.undoneOn ? (
														"—"
													) : l.origin === "tuning" ? (
														<T id="npmos.learning.effect.tuning" />
													) : l.decision === "dismiss" ? (
														<T id="npmos.learning.effect.dismiss" />
													) : (
														<>
															<div>
																{l.syncError ? (
																	<span className="text-danger">
																		<T
																			id="npmos.learning.effect.error"
																			data={{ error: l.syncError }}
																		/>
																	</span>
																) : l.syncedOn ? (
																	<T id="npmos.learning.effect.synced" />
																) : (
																	<T id="npmos.learning.effect.pending" />
																)}
															</div>
															{l.exception && (
																<div>
																	<T
																		id={
																			l.exceptionActive
																				? l.expiresOn
																					? "npmos.learning.effect.exception.until"
																					: "npmos.learning.effect.exception"
																				: "npmos.learning.effect.exception.ended"
																		}
																		data={{
																			date: l.expiresOn
																				? dateTime(l.expiresOn)
																				: "",
																		}}
																	/>
																</div>
															)}
															{l.banned.length > 0 && (
																<div>
																	<T
																		id="npmos.learning.effect.banned"
																		data={{
																			count: l.banned.length,
																			duration: l.banDuration,
																		}}
																	/>
																</div>
															)}
														</>
													)}
												</td>
												{label && (
													<td className="text-end">
														{!l.undoneOn && (
															<button
																type="button"
																className="btn btn-sm"
																onClick={() => undo(l.id)}
															>
																<T id="npmos.learning.undo" />
															</button>
														)}
													</td>
												)}
											</tr>
										))
									)}
								</tbody>
							</table>
						</div>
						{pages > 1 && (
							<div className={eventStyles.pager}>
								<span>
									<T id="npmos.audit.total" data={{ total: data.total }} />
								</span>
								<div className={eventStyles.pagerButtons}>
									<span>
										<T id="npmos.audit.page" data={{ page: page + 1, pages }} />
									</span>
									<button
										type="button"
										className={hostStyles.tool}
										disabled={page === 0}
										onClick={() => setPage(page - 1)}
									>
										<IconChevronLeft size={16} />
									</button>
									<button
										type="button"
										className={hostStyles.tool}
										disabled={page + 1 >= pages}
										onClick={() => setPage(page + 1)}
									>
										<IconChevronRight size={16} />
									</button>
								</div>
							</div>
						)}
					</>
				)}
			</div>
		</div>
	);
}

export function LearningTab() {
	const can = useCan();
	const label = can("waf_learning", "label");
	return (
		<div>
			<p className={styles.lead}>
				<T id="npmos.learning.description" />
			</p>
			<Queue label={label} />
			<Hosts manage={can("proxy_hosts", "manage")} />
			<History label={label} />
		</div>
	);
}
