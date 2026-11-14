// WAF → Agent: metrics of the agent (its prometheus nano service, waf/metrics.js of the backend), refreshed every minute
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { getWafAgentMetrics } from "../../api";
import { SearchField } from "../../ui/SearchField";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const labelsOf = (labels: [string, string][]) => labels.map(([k, v]) => `${k}=${v}`).join(", ");

export function AgentMetricsCard() {
	const { data, isLoading, error } = useQuery({
		queryKey: ["nginxions-waf-agent-metrics"],
		queryFn: getWafAgentMetrics,
		refetchInterval: 60000,
	});
	const [q, setQ] = useState("");
	const needle = q.trim().toLowerCase();
	const metrics = (data?.metrics ?? []).filter(
		(m) => !needle || m.name.toLowerCase().includes(needle) || m.help.toLowerCase().includes(needle),
	);
	return (
		<div className="card mt-4">
			<div className="card-header">
				<h3 className="card-title">
					<T id="nginxions.waf.metrics" />
				</h3>
				<div className="card-actions">
					<SearchField value={q} onChange={setQ} placeholder={t("nginxions.waf.metrics.search")} />
				</div>
			</div>
			<div className="card-body">
				{isLoading ? (
					<LoadingPage noLogo />
				) : error || !data?.reachable ? (
					<Alert variant="warning" className="mb-0">
						<T id="nginxions.waf.metrics.unreachable" />
						{` (${(error as Error)?.message || data?.error || "—"})`}
					</Alert>
				) : !data.metrics.length ? (
					<p className="text-secondary mb-0">
						<T id="nginxions.waf.metrics.none" />
					</p>
				) : (
					<div className="table-responsive">
						<table className="table table-sm table-vcenter">
							<thead>
								<tr>
									<th>
										<T id="nginxions.waf.metrics.name" />
									</th>
									<th>
										<T id="nginxions.waf.metrics.labels" />
									</th>
									<th className="text-end">
										<T id="nginxions.waf.metrics.value" />
									</th>
								</tr>
							</thead>
							<tbody>
								{metrics.flatMap((m) =>
									m.samples.map((s, i) => (
										<tr key={`${m.name}-${labelsOf(s.labels)}`}>
											<td title={m.help}>{i === 0 ? m.name : ""}</td>
											<td className="text-secondary small">{labelsOf(s.labels)}</td>
											<td className="text-end">{intl.formatNumber(s.value)}</td>
										</tr>
									)),
								)}
							</tbody>
						</table>
					</div>
				)}
			</div>
		</div>
	);
}
