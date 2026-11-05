// Analytics → Blocks → Triggers: what the agents refused lately in one list — requests open-appsec blocked and
// the bans CrowdSec decided (its alerts with a decision), the agent named in each row. Active bans are on the
// Decisions tab, the full log with all filters is Analytics → Events; an address open-appsec refused is banned
// from here in one step. The alerts of CrowdSec with their details stay in Agents → CrowdSec.
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import { Link } from "react-router-dom";
import { T } from "src/locale";
import { getEvents } from "../../api";
import { showBanModal } from "../../crowdsec/BanModal";
import { useCan } from "../../rbac/hooks";
import { dateTime, timeAgo } from "../../ui/time";
import { AGENT_OF } from "../WafEvents/filters";
import styles from "../Pki/Pki.module.css";

const LIMIT = 100;
// open-appsec: Prevent; CrowdSec: the decision of an alert (a simulated one or an alert without one did not block)
const ACTIONS = "Prevent,ban,captcha";

export function AgentTriggersTab({ refresh }: { refresh: () => void }) {
	const can = useCan();
	const decide = can("crowdsec", "decide");
	const from = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
	const events = useQuery({
		queryKey: ["npmos-blocks-triggers"],
		queryFn: () => getEvents({ kind: "agents", action: ACTIONS, from, limit: LIMIT }),
		refetchInterval: 30000,
	});
	const items = events.data?.events ?? [];
	const all = `/waf/events?${new URLSearchParams({ action: ACTIONS }).toString()}`;
	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.filters}>
				<span className="text-secondary small">
					<T id="npmos.blocks.triggers.hint" data={{ count: events.data?.total ?? 0 }} />
				</span>
				<Link to={all} className="btn btn-sm ms-auto">
					<T id="npmos.blocks.openappsec.all" />
				</Link>
			</div>
			{events.isError ? (
				<p className="text-danger mb-0">{(events.error as Error).message}</p>
			) : !items.length ? (
				<p className={styles.empty}>
					<T id={events.isLoading ? "loading" : "npmos.blocks.triggers.none"} />
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.blocks.openappsec.time" />
								</th>
								<th>
									<T id="npmos.events.agent" />
								</th>
								<th>
									<T id="npmos.crowdsec.value" />
								</th>
								<th>
									<T id="npmos.blocks.openappsec.host" />
								</th>
								<th>
									<T id="npmos.blocks.openappsec.attack" />
								</th>
								{decide && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{items.map((e) => {
								const agent = AGENT_OF[e.kind] ?? "open-appsec";
								return (
									<tr key={`${e.id}-${e.time}`}>
										<td className="text-nowrap" title={dateTime(e.time)}>
											{timeAgo(e.time)}
										</td>
										<td className="text-nowrap">
											<T id={`npmos.events.agent.${agent}`} />
										</td>
										<td className="font-monospace">{e.sourceIp || "—"}</td>
										<td className="text-break">
											{e.host || "—"}
											{e.uri && <div className="text-secondary small text-break">{e.uri}</div>}
										</td>
										<td>
											{e.incidentType || e.name || "—"}
											{e.severity && <div className="text-secondary small">{e.severity}</div>}
										</td>
										{decide && (
											<td>
												{/* CrowdSec has banned the address already */}
												{agent === "open-appsec" && e.sourceIp && (
													<button
														type="button"
														className="btn btn-sm btn-outline-danger text-nowrap"
														onClick={() =>
															showBanModal({
																values: [e.sourceIp],
																reason: `open-appsec: ${e.incidentType || e.name}`,
																onDone: refresh,
															})
														}
													>
														<T id="npmos.blocks.openappsec.ban" />
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
