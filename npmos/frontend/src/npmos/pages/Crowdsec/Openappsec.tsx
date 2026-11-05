// Analytics → Blocks → open-appsec: what the WAF refused lately (prevented events), next to the decisions of
// CrowdSec. The full log with all filters is Analytics → Events; an address is banned from here in one step.
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import { Link } from "react-router-dom";
import { T } from "src/locale";
import { getEvents } from "../../api";
import { showBanModal } from "../../crowdsec/BanModal";
import { useCan } from "../../rbac/hooks";
import { dateTime, timeAgo } from "../../ui/time";
import styles from "../Pki/Pki.module.css";

const LIMIT = 100;
const FILTER = { agent: "open-appsec", action: "Prevent" };

export function OpenappsecBlocksTab({ refresh }: { refresh: () => void }) {
	const can = useCan();
	const decide = can("crowdsec", "decide");
	const from = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
	const events = useQuery({
		queryKey: ["npmos-blocks-openappsec"],
		queryFn: () => getEvents({ ...FILTER, from, limit: LIMIT }),
		refetchInterval: 30000,
	});
	const items = events.data?.events ?? [];
	const all = `/waf/events?${new URLSearchParams({ agent: FILTER.agent, action: FILTER.action }).toString()}`;
	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.filters}>
				<span className="text-secondary small">
					<T id="npmos.blocks.openappsec.hint" data={{ count: events.data?.total ?? 0 }} />
				</span>
				<Link to={all} className="btn btn-sm ms-auto">
					<T id="npmos.blocks.openappsec.all" />
				</Link>
			</div>
			{events.isError ? (
				<p className="text-danger mb-0">{(events.error as Error).message}</p>
			) : !items.length ? (
				<p className={styles.empty}>
					<T id={events.isLoading ? "loading" : "npmos.blocks.openappsec.none"} />
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
							{items.map((e) => (
								<tr key={`${e.id}-${e.time}`}>
									<td className="text-nowrap" title={dateTime(e.time)}>
										{timeAgo(e.time)}
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
											{e.sourceIp && (
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
							))}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}
