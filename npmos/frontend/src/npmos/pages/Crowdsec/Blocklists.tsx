// CrowdSec → Blocklists: local lists instead of the community blocklist (a file or a URL) and the
// export of this node's decisions that other NPMOS nodes subscribe to.
import { IconDots, IconPlus, IconTrash } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import { T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import {
	type Blocklist,
	type Bouncer,
	deleteBlocklist,
	deleteRegistered,
	type Machine,
	setShare,
	shareUrl,
	syncBlocklist,
	useBlocklists,
	useRegistry,
} from "../../crowdsec/api";
import { showBlocklistModal } from "../../crowdsec/BlocklistModal";
import { durationLabel, t } from "../../crowdsec/labels";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown } from "../../ui/Dropdown";
import { dateTime, timeAgo } from "../../ui/time";
import styles from "../Pki/Pki.module.css";

function Share({ enabled, onChange }: { enabled: boolean; onChange: () => void }) {
	const can = useCan();
	const [token, setToken] = useState("");
	const toggle = async (on: boolean) => {
		try {
			const r = await setShare(on);
			setToken(r.token);
		} catch (err: any) {
			showError(err.message);
		}
		onChange();
	};
	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<div>
					<h3 className="card-title mb-1">
						<T id="npmos.crowdsec.share" />
					</h3>
					<div className="text-secondary small">
						<T id="npmos.crowdsec.share.hint" />
					</div>
				</div>
				{can("crowdsec", "manage") && (
					<div className="d-flex gap-2">
						<button type="button" className="btn btn-sm" onClick={() => toggle(true)}>
							<T id={enabled ? "npmos.crowdsec.share.new-token" : "npmos.crowdsec.share.enable"} />
						</button>
						{enabled && (
							<button type="button" className="btn btn-sm btn-ghost-danger" onClick={() => toggle(false)}>
								<T id="npmos.crowdsec.share.disable" />
							</button>
						)}
					</div>
				)}
			</div>
			<div className="small">
				<span className={cn("badge me-2", enabled ? "bg-green-lt" : "bg-secondary-lt")}>
					<T id={enabled ? "enabled" : "disabled"} />
				</span>
				<span className="font-monospace">{shareUrl()}</span>
			</div>
			{token && (
				<div className="alert alert-warning mt-3 mb-0">
					<div className="mb-1">
						<T id="npmos.crowdsec.share.token" />
					</div>
					<code className="user-select-all">{token}</code>
				</div>
			)}
		</section>
	);
}

export function BlocklistsTab({ shareEnabled, refresh }: { shareEnabled: boolean; refresh: () => void }) {
	const can = useCan();
	const lists = useBlocklists({ refetchInterval: 60000 });
	const manage = can("crowdsec", "manage");
	const reload = () => {
		lists.refetch();
		refresh();
	};
	const sync = async (b: Blocklist) => {
		try {
			const { count, invalid } = await syncBlocklist(b.id);
			showSuccess(t("npmos.crowdsec.blocklist.synced", { count, invalid }));
		} catch (err: any) {
			showError(err.message);
		}
		reload();
	};

	return (
		<>
			<section className={cn("card", styles.card)}>
				<div className={styles.cardHead}>
					<div className="text-secondary small">
						<T id="npmos.crowdsec.blocklists.hint" />
					</div>
					{manage && (
						<button
							type="button"
							className="btn btn-sm btn-primary"
							onClick={() => showBlocklistModal({ onDone: reload })}
						>
							<IconPlus size={16} />
							<T id="npmos.crowdsec.blocklist.add" />
						</button>
					)}
				</div>
				{lists.isError ? (
					<p className="text-danger mb-0">{lists.error.message}</p>
				) : !lists.data?.length ? (
					<p className={styles.empty}>
						<T id={lists.isLoading ? "loading" : "npmos.crowdsec.blocklists.none"} />
					</p>
				) : (
					<div className="table-responsive">
						<table className="table table-vcenter card-table">
							<thead>
								<tr>
									<th>
										<T id="npmos.crowdsec.name" />
									</th>
									<th>
										<T id="npmos.crowdsec.blocklist.source" />
									</th>
									<th>
										<T id="npmos.crowdsec.decision" />
									</th>
									<th>
										<T id="npmos.crowdsec.blocklist.count" />
									</th>
									<th>
										<T id="npmos.crowdsec.blocklist.synced-on" />
									</th>
									<th className="w-1" />
								</tr>
							</thead>
							<tbody>
								{lists.data.map((b) => (
									<tr key={b.id}>
										<td>
											<div>{b.name}</div>
											{!b.enabled && (
												<span className="badge bg-secondary-lt">
													<T id="disabled" />
												</span>
											)}
										</td>
										<td className={styles.sub}>
											{b.source === "url" ? (
												<span title={b.url}>{b.url}</span>
											) : (
												<T
													id="npmos.crowdsec.blocklist.file.lines"
													data={{ count: b.lines ?? 0 }}
												/>
											)}
										</td>
										<td className="text-nowrap">
											{t(`npmos.crowdsec.decision.${b.decision}`)}, {durationLabel(b.duration)}
										</td>
										<td>{b.count}</td>
										<td>
											{b.syncedOn ? (
												<span title={dateTime(b.syncedOn)}>{timeAgo(b.syncedOn)}</span>
											) : (
												"—"
											)}
											{b.error && <div className="text-danger small">{b.error}</div>}
										</td>
										<td>
											{(manage || can("crowdsec", "decide")) && (
												<Dropdown
													floating
													inline
													ariaLabel={t("npmos.crowdsec.actions")}
													triggerClassName="btn btn-sm btn-ghost-secondary"
													trigger={<IconDots size={16} />}
													items={[
														{
															key: "sync",
															label: <T id="npmos.crowdsec.blocklist.sync" />,
															onSelect: () => sync(b),
														},
														...(manage
															? [
																	{
																		key: "edit",
																		label: <T id="npmos.crowdsec.blocklist.edit" />,
																		onSelect: () =>
																			showBlocklistModal({
																				list: b,
																				onDone: reload,
																			}),
																	},
																	{
																		key: "delete",
																		divider: true,
																		label: (
																			<span className="text-danger">
																				{t("action.delete")}
																			</span>
																		),
																		onSelect: () =>
																			showConfirmModal({
																				tTitle: "npmos.crowdsec.blocklist.delete",
																				tConfirm: "action.delete",
																				danger: true,
																				children: (
																					<T
																						id="npmos.crowdsec.blocklist.delete.text"
																						data={{
																							name: b.name,
																							count: b.count,
																						}}
																					/>
																				),
																				onConfirm: async () => {
																					await deleteBlocklist(b.id);
																					reload();
																				},
																			}),
																	},
																]
															: []),
													]}
												/>
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</section>
			<Share enabled={shareEnabled} onChange={refresh} />
		</>
	);
}

const ago = (date: string | null) => (date ? <span title={dateTime(date)}>{timeAgo(date)}</span> : "—");

function DeleteRegistered({ kind, name, onDone }: { kind: "machines" | "bouncers"; name: string; onDone: () => void }) {
	return (
		<button
			type="button"
			className="btn btn-sm btn-ghost-danger btn-icon"
			title={t("action.delete")}
			onClick={() =>
				showConfirmModal({
					tTitle: `npmos.crowdsec.${kind}.delete`,
					tConfirm: "action.delete",
					danger: true,
					children: <T id={`npmos.crowdsec.${kind}.delete.text`} data={{ name }} />,
					onConfirm: async () => {
						await deleteRegistered(kind, name);
						showSuccess(t("npmos.crowdsec.registry.deleted"));
						onDone();
					},
				})
			}
		>
			<IconTrash size={16} />
		</button>
	);
}

export function RegistryTab() {
	const can = useCan();
	const manage = can("crowdsec", "manage");
	const registry = useRegistry({ refetchInterval: 30000 });
	if (registry.isError) return <p className="text-danger">{(registry.error as Error).message}</p>;
	const data = registry.data;
	const reload = () => registry.refetch();
	const deletable = (kind: "machines" | "bouncers", name: string) =>
		manage && !data?.protected?.[kind]?.includes(name) && !(kind === "machines" && name === data?.ownMachine);
	return (
		<>
			<section className={cn("card", styles.card)}>
				<h3 className="card-title">
					<T id="npmos.crowdsec.machines" />
				</h3>
				<div className="text-secondary small mb-2">
					<T id="npmos.crowdsec.machines.hint" />
				</div>
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.crowdsec.name" />
								</th>
								<th>
									<T id="npmos.crowdsec.ip" />
								</th>
								<th>
									<T id="npmos.crowdsec.version" />
								</th>
								<th>
									<T id="npmos.crowdsec.machine.heartbeat" />
								</th>
								<th>
									<T id="npmos.crowdsec.machine.push" />
								</th>
								{manage && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{(data?.machines ?? []).map((m: Machine) => (
								<tr key={m.name}>
									<td>
										{m.name}
										{m.name === data?.ownMachine && (
											<span className="badge bg-blue-lt ms-2">
												<T id="npmos.crowdsec.machine.npmos" />
											</span>
										)}
										{m.name === "localhost" && (
											<span className="badge bg-secondary-lt ms-2">
												<T id="npmos.crowdsec.machine.local" />
											</span>
										)}
										{!m.validated && (
											<span className="badge bg-yellow-lt ms-2">
												<T id="npmos.crowdsec.machine.pending" />
											</span>
										)}
									</td>
									<td className="font-monospace">{m.ipAddress || "—"}</td>
									<td className={styles.sub}>{m.version || "—"}</td>
									<td>{ago(m.lastHeartbeat)}</td>
									<td>{ago(m.lastPush)}</td>
									{manage && (
										<td>
											{deletable("machines", m.name) && (
												<DeleteRegistered kind="machines" name={m.name} onDone={reload} />
											)}
										</td>
									)}
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</section>
			<section className={cn("card", styles.card)}>
				<h3 className="card-title">
					<T id="npmos.crowdsec.bouncers" />
				</h3>
				<div className="text-secondary small mb-2">
					<T id="npmos.crowdsec.bouncers.hint" />
				</div>
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.crowdsec.name" />
								</th>
								<th>
									<T id="npmos.crowdsec.ip" />
								</th>
								<th>
									<T id="npmos.crowdsec.bouncer.type" />
								</th>
								<th>
									<T id="npmos.crowdsec.bouncer.pull" />
								</th>
								{manage && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{(data?.bouncers ?? []).map((b: Bouncer) => (
								<tr key={b.name}>
									<td>
										{b.name}
										{["npmos", "appsec"].includes(b.name) && (
											<span className="badge bg-blue-lt ms-2">
												<T id={`npmos.crowdsec.bouncer.${b.name}`} />
											</span>
										)}
										{!b.valid && (
											<span className="badge bg-red-lt ms-2">
												<T id="npmos.crowdsec.bouncer.revoked" />
											</span>
										)}
									</td>
									<td className="font-monospace">{b.ipAddress || "—"}</td>
									<td className={styles.sub}>
										{[b.type, b.version].filter(Boolean).join(" ") || "—"}
									</td>
									<td>{ago(b.lastPull)}</td>
									{manage && (
										<td>
											{deletable("bouncers", b.name) && (
												<DeleteRegistered kind="bouncers" name={b.name} onDone={reload} />
											)}
										</td>
									)}
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</section>
		</>
	);
}
