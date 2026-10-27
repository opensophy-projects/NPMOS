// WAF → Agent: open-appsec on/off (nginx attachment) and agent status
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { ADMIN, MANAGE, VIEW } from "src/modules/Permissions";
import { showSuccess } from "src/notifications";
import { type AgentStatus, applyWafPolicy, setWafEnabled, type WafPolicyState, type WafStatus } from "../../api";
import { useWafStatus } from "../../hooks";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { showWafPolicyModal } from "../../modals/WafPolicyModal";
import { AgentSettingsCard } from "./AgentSettings";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
	return (
		<div className="datagrid-item">
			<div className="datagrid-title">
				<T id={label} />
			</div>
			<div className="datagrid-content">{children}</div>
		</div>
	);
}

function AgentCard({ agent }: { agent?: AgentStatus }) {
	return (
		<div className="card mt-4">
			<div className="card-header">
				<h3 className="card-title">
					<T id="npmos.waf.agent" />
				</h3>
			</div>
			<div className="card-body">
				{!agent?.reachable ? (
					<Alert variant="warning" className="mb-0">
						<T id="npmos.waf.agent-unreachable" />
						{agent?.error ? ` (${agent.error})` : null}
					</Alert>
				) : (
					<div className="datagrid">
						<Row label="npmos.waf.agent-mode">
							<span className="badge bg-green-lt">
								<T id="npmos.waf.agent-mode-local" />
							</span>
						</Row>
						<Row label="npmos.waf.policy-version">{agent.policyVersion || "—"}</Row>
						<Row label="npmos.waf.last-policy-update">
							{agent.lastPolicyUpdate || <T id="npmos.waf.policy-not-applied" />}
						</Row>
						<Row label="npmos.waf.last-update-status">{agent.lastUpdateStatus || "—"}</Row>
					</div>
				)}
			</div>
		</div>
	);
}

function PolicyCard({ policy }: { policy?: WafPolicyState }) {
	const queryClient = useQueryClient();
	const { locale } = useLocaleState();
	const when = (iso?: string | null) => (iso ? formatDateTime(iso, locale) : "—");
	const [applying, setApplying] = useState(false);
	const apply = async () => {
		setApplying(true);
		try {
			await applyWafPolicy();
			showSuccess(intl.formatMessage({ id: "npmos.waf.policy-applied" }));
		} finally {
			setApplying(false);
			queryClient.invalidateQueries({ queryKey: ["npmos-waf"] });
		}
	};
	return (
		<div className="card mt-4">
			<div className="card-header">
				<h3 className="card-title">
					<T id="npmos.waf.policy" />
				</h3>
				<div className="card-actions btn-actions">
					<Button size="sm" onClick={showWafPolicyModal}>
						<T id="npmos.waf.policy-show" />
					</Button>
					<HasPermission section={ADMIN} permission={MANAGE} hideError>
						<Button size="sm" actionType="primary" className="ms-2" isLoading={applying} onClick={apply}>
							<T id="npmos.waf.policy-apply" />
						</Button>
					</HasPermission>
				</div>
			</div>
			<div className="card-body">
				<div className="datagrid">
					<Row label="npmos.waf.policy-hosts">{policy?.hosts ?? "—"}</Row>
					<Row label="npmos.waf.policy-generated">{when(policy?.generatedAt)}</Row>
					<Row label="npmos.waf.policy-sent">
						{!policy?.applied ? (
							"—"
						) : policy.applied.ok ? (
							<span className="badge bg-green-lt">{when(policy.applied.at)}</span>
						) : (
							<span className="badge bg-yellow-lt" title={policy.applied.error || ""}>
								<T id="npmos.waf.policy-not-sent" /> ({policy.applied.error})
							</span>
						)}
					</Row>
				</div>
			</div>
		</div>
	);
}

function WafCard({ status }: { status: WafStatus }) {
	const queryClient = useQueryClient();
	const [restarting, setRestarting] = useState(false);

	// the old process answers with restartRequired until it is gone; the new one has applied the switch
	useEffect(() => {
		if (!status.restartRequired) setRestarting(false);
	}, [status.restartRequired]);

	const submit = async (enabled: boolean) => {
		const result = await setWafEnabled(enabled, true);
		setRestarting(!!result.restarting);
		queryClient.invalidateQueries({ queryKey: ["npmos-waf"] });
	};

	const change = (enabled: boolean) =>
		showConfirmModal({
			tTitle: enabled ? "npmos.waf.enable-title" : "npmos.waf.disable-title",
			tConfirm: enabled ? "npmos.waf.enable" : "npmos.waf.disable",
			danger: !enabled,
			children: (
				<p>
					<T id="npmos.waf.restart-warning" />
				</p>
			),
			onConfirm: () => submit(enabled),
		});

	const apply = () =>
		showConfirmModal({
			tTitle: "npmos.waf.apply",
			tConfirm: "npmos.waf.apply",
			children: (
				<p>
					<T id="npmos.waf.restart-warning" />
				</p>
			),
			onConfirm: () => submit(status.enabled),
		});

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-red" />
			<div className="card-header">
				<div className="row w-full align-items-center">
					<div className="col">
						<h2 className="mt-1 mb-0">
							<T id="npmos.waf" />
						</h2>
						<div className="text-secondary">
							<T id="npmos.waf.description" />
						</div>
					</div>
					<div className="col-auto">
						<label className="form-check form-switch form-switch-lg m-0">
							<input
								className="form-check-input"
								type="checkbox"
								checked={status.enabled}
								onChange={(e) => change(e.target.checked)}
							/>
							<span className="form-check-label">
								<T id={status.enabled ? "npmos.waf.on" : "npmos.waf.off"} />
							</span>
						</label>
					</div>
				</div>
			</div>
			{restarting && (
				<div className="card-body">
					<Alert variant="info" className="mb-0 d-flex align-items-center">
						<span className="spinner-border spinner-border-sm me-2" />
						<T id="npmos.waf.restarting" />
					</Alert>
				</div>
			)}
			{status.restartRequired && !restarting && (
				<div className="card-body">
					<Alert variant="warning" className="mb-0 d-flex align-items-center">
						<div className="flex-fill">
							<T id={status.enabled ? "npmos.waf.pending-enable" : "npmos.waf.pending-disable"} />
						</div>
						<Button size="sm" actionType="warning" onClick={apply}>
							<T id="npmos.waf.apply" />
						</Button>
					</Alert>
				</div>
			)}
		</div>
	);
}

function WafAgentPage() {
	const { data, isLoading, error } = useWafStatus();
	if (isLoading) return <LoadingPage />;
	// a failed refetch (npmos restarting to apply the WAF switch) keeps the last known state
	if (!data) return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;
	return (
		<>
			<WafCard status={data} />
			<AgentCard agent={data.agent} />
			<AgentSettingsCard />
			<PolicyCard policy={data.policy} />
		</>
	);
}

const WafAgent = () => (
	<HasPermission section={ADMIN} permission={VIEW} pageLoading loadingNoLogo>
		<WafAgentPage />
	</HasPermission>
);

export default WafAgent;
