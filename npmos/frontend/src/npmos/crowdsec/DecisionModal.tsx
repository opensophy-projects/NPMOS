// Blocks → Decisions → an address: why and how long it is blocked (every decision, the alerts of CrowdSec that
// led to them), where it comes from and what it asked for lately (the request log). Unban, extend the ban, open
// everything of the address in Events.
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { getRequestLog } from "../api";
import { hostLabel, statusTone } from "../modals/RequestModal";
import logStyles from "../pages/RequestLog/RequestLog.module.css";
import { Country } from "../pages/WafAnalytics/common";
import { useCan } from "../rbac/hooks";
import { dateTime } from "../ui/time";
import { type Decision, unban, useAlerts } from "./api";
import { showBanModal } from "./BanModal";
import { originLabel, remaining, t } from "./labels";

interface Props extends InnerModalProps {
	value: string;
	type: string;
	decisions: Decision[];
	/** after an unban or a new ban */
	onChange?: () => void;
	/** the window is outside the router: the page navigates */
	navigate?: (to: string) => void;
}

const isIp = (v: string) => /^[\d.]+$|:/.test(v) && !v.includes("/");

function Item({ label, children }: { label: string; children: React.ReactNode }) {
	return (
		<div className="datagrid-item">
			<div className="datagrid-title">
				<T id={label} />
			</div>
			<div className="datagrid-content text-break">{children}</div>
		</div>
	);
}

const DecisionModal = EasyModal.create(({ visible, remove, value, type, decisions, onChange, navigate }: Props) => {
	const can = useCan();
	const ip = isIp(value);
	const alerts = useAlerts({ ip: value, limit: 10 }, { enabled: ip });
	const requests = useQuery({
		queryKey: ["npmos-decision-requests", value],
		queryFn: () => getRequestLog({ ip: value, limit: 10 }),
		enabled: ip && can("analytics"),
	});
	const last = requests.data?.rows ?? [];
	const country = last.find((r) => r.country)?.country || alerts.data?.find((a) => a.source?.cn)?.source.cn || "";
	const asName = alerts.data?.find((a) => a.source?.asName)?.source.asName;
	const decide = can("crowdsec", "decide");
	const doUnban = async () => {
		try {
			const { deleted } = await unban({ ids: decisions.map((d) => d.id) });
			showSuccess(t("npmos.crowdsec.unban.done", { count: deleted }));
			onChange?.();
			remove();
		} catch (err: any) {
			showError(err.message);
		}
	};
	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<span className="font-monospace">{value}</span>{" "}
					<span className={cn("badge ms-1", type === "ban" ? "bg-red-lt" : "bg-yellow-lt")}>
						{["ban", "captcha"].includes(type) ? t(`npmos.crowdsec.decision.${type}`) : type}
					</span>
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<div className="datagrid mb-3">
					<Item label="npmos.traffic.filter.country">{country ? <Country code={country} /> : "—"}</Item>
					{asName && <Item label="npmos.crowdsec.blocked.network">{asName}</Item>}
					<Item label="npmos.crowdsec.left">
						{remaining(
							decisions.reduce((a, d) => (d.duration > a ? d.duration : a), decisions[0]?.duration ?? ""),
						)}
					</Item>
					<Item label="npmos.traffic.log.total-short">
						{requests.data
							? requests.data.totalCapped
								? `${requests.data.total}+`
								: requests.data.total
							: "—"}
					</Item>
				</div>
				<h4>
					<T id="npmos.crowdsec.blocked.decisions" />
				</h4>
				<table className="table table-sm mb-3">
					<tbody>
						{decisions.map((d) => (
							<tr key={d.id}>
								<td>{d.scenario}</td>
								<td className="text-secondary">{originLabel(d.origin)}</td>
								<td className="text-end text-nowrap">{remaining(d.duration)}</td>
							</tr>
						))}
					</tbody>
				</table>
				{!!alerts.data?.length && (
					<>
						<h4>
							<T id="npmos.crowdsec.blocked.alerts" />
						</h4>
						<table className="table table-sm mb-3">
							<tbody>
								{alerts.data.map((a) => (
									<tr key={a.id}>
										<td className="text-nowrap">{dateTime(a.createdAt)}</td>
										<td>{a.scenario}</td>
										<td className="text-secondary text-break">{a.message}</td>
									</tr>
								))}
							</tbody>
						</table>
					</>
				)}
				{ip && can("analytics") && (
					<>
						<h4>
							<T id="npmos.crowdsec.blocked.requests" />
						</h4>
						{last.length === 0 ? (
							<p className="text-secondary">
								<T id="npmos.traffic.no-data" />
							</p>
						) : (
							<table className="table table-sm mb-0">
								<tbody>
									{last.map((r) => (
										<tr key={r.id}>
											<td className="text-nowrap">{dateTime(r.time)}</td>
											<td className="text-break">
												{r.method} {hostLabel(r.host)}
												{r.path}
											</td>
											<td className="text-end">
												<span className={cn(logStyles.status, statusTone(r.status))}>
													{r.status}
												</span>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						)}
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				{decide && (
					<Button className="btn-ghost-danger" onClick={doUnban}>
						<T id="npmos.crowdsec.unban" />
					</Button>
				)}
				{decide && ip && (
					<Button
						onClick={() => {
							remove();
							showBanModal({ values: [value], extend: true, onDone: onChange });
						}}
					>
						<T id="npmos.crowdsec.ban.extend" />
					</Button>
				)}
				{ip && navigate && can("waf_events") && (
					<Button
						onClick={() => {
							remove();
							navigate(`/waf/events?kind=all&ip=${encodeURIComponent(value)}`);
						}}
					>
						<T id="npmos.traffic.log.ip-events" />
					</Button>
				)}
				<Button onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showDecisionModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(DecisionModal, props);
