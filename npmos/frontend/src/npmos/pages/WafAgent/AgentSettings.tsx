// WAF → Agent: settings of the open-appsec agent (CrowdSec, fail-open) and the advanced ML model.
// Applied by restarting the agent (its entrypoint reads them), traffic is not interrupted with fail-open.
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, HasPermission, Loading } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { MANAGE } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { setWafAgent, uploadWafModel, type WafAgentSettings } from "../../api";
import { useWafAgent } from "../../hooks";
import { showConfirmModal } from "../../modals/ConfirmModal";

const sameSettings = (a: WafAgentSettings, b: WafAgentSettings) =>
	JSON.stringify([a.crowdsec, a.failOpen]) === JSON.stringify([b.crowdsec, b.failOpen]);

function SettingsCard() {
	const queryClient = useQueryClient();
	const { data, isLoading, error } = useWafAgent();
	const [form, setForm] = useState<WafAgentSettings | null>(null);
	const [saving, setSaving] = useState(false);

	useEffect(() => {
		if (data && !form) setForm({ crowdsec: data.crowdsec, failOpen: data.failOpen });
	}, [data, form]);

	if (isLoading || !form) return error ? <Alert variant="danger">{error.message}</Alert> : <Loading noLogo />;

	const changed = !!data && !sameSettings(form, data);
	const save = () =>
		showConfirmModal({
			tTitle: "npmos.waf.agent-settings.save",
			tConfirm: "npmos.waf.agent-settings.save",
			children: (
				<p>
					<T id="npmos.waf.agent-settings.restart-warning" />
				</p>
			),
			onConfirm: async () => {
				setSaving(true);
				try {
					await setWafAgent(form, true);
					showSuccess(intl.formatMessage({ id: "npmos.waf.agent-settings.saved" }));
				} catch (err: any) {
					showError(err.message);
				} finally {
					setSaving(false);
					queryClient.invalidateQueries({ queryKey: ["npmos-waf-agent"] });
					queryClient.invalidateQueries({ queryKey: ["npmos-waf"] });
				}
			},
		});

	return (
		<>
			{data?.restartRequired && (
				<Alert variant="warning">
					<T id="npmos.waf.agent-settings.pending" />
				</Alert>
			)}
			<div className="row">
				<div className="col-md-6 mb-3">
					<label className="form-check form-switch">
						<input
							className="form-check-input"
							type="checkbox"
							checked={form.crowdsec.enabled}
							onChange={(e) =>
								setForm({ ...form, crowdsec: { ...form.crowdsec, enabled: e.target.checked } })
							}
						/>
						<span className="form-check-label">
							<T id="npmos.waf.agent-settings.crowdsec" />
						</span>
					</label>
					<div className="form-hint mb-2">
						<T id="npmos.waf.agent-settings.crowdsec.hint" />
					</div>
					<select
						className="form-select"
						aria-label={intl.formatMessage({ id: "npmos.waf.agent-settings.crowdsec-mode" })}
						value={form.crowdsec.mode}
						disabled={!form.crowdsec.enabled}
						onChange={(e) =>
							setForm({
								...form,
								crowdsec: { ...form.crowdsec, mode: e.target.value as "prevent" | "detect" },
							})
						}
					>
						<option value="prevent">
							{intl.formatMessage({ id: "npmos.waf.agent-settings.crowdsec.prevent" })}
						</option>
						<option value="detect">
							{intl.formatMessage({ id: "npmos.waf.agent-settings.crowdsec.detect" })}
						</option>
					</select>
				</div>
				<div className="col-md-6 mb-3">
					<label className="form-check form-switch">
						<input
							className="form-check-input"
							type="checkbox"
							checked={form.failOpen.enabled}
							onChange={(e) =>
								setForm({ ...form, failOpen: { ...form.failOpen, enabled: e.target.checked } })
							}
						/>
						<span className="form-check-label">
							<T id="npmos.waf.agent-settings.fail-open" />
						</span>
					</label>
					<div className="form-hint mb-2">
						<T id={`npmos.waf.agent-settings.fail-open.${form.failOpen.enabled ? "on" : "off"}`} />
					</div>
					<div className="input-group">
						<span className="input-group-text">
							<T id="npmos.waf.agent-settings.fail-open-timeout" />
						</span>
						<input
							type="number"
							className="form-control"
							min={10}
							max={10000}
							value={form.failOpen.timeoutMs}
							onChange={(e) =>
								setForm({ ...form, failOpen: { ...form.failOpen, timeoutMs: Number(e.target.value) } })
							}
						/>
						<span className="input-group-text">
							<T id="npmos.common.ms" />
						</span>
					</div>
				</div>
			</div>
			<HasPermission rbac="waf_policy" permission={MANAGE} hideError>
				<Button
					actionType="primary"
					size="sm"
					disabled={!changed || form.failOpen.timeoutMs < 10 || form.failOpen.timeoutMs > 10000}
					isLoading={saving}
					onClick={save}
				>
					<T id="npmos.waf.agent-settings.save" />
				</Button>
			</HasPermission>
		</>
	);
}

const formatSize = (bytes?: number) => (bytes ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : "—");

function ModelCard() {
	const queryClient = useQueryClient();
	const { locale } = useLocaleState();
	const { data } = useWafAgent();
	const input = useRef<HTMLInputElement>(null);
	const [uploading, setUploading] = useState(false);

	const upload = async (file?: File) => {
		if (!file) return;
		setUploading(true);
		try {
			await uploadWafModel(file);
			showSuccess(intl.formatMessage({ id: "npmos.waf.model.uploaded" }));
		} catch (err: any) {
			showError(err.message);
		} finally {
			setUploading(false);
			if (input.current) input.current.value = "";
			queryClient.invalidateQueries({ queryKey: ["npmos-waf-agent"] });
		}
	};

	return (
		<>
			<p className="text-secondary">
				<T id="npmos.waf.model.description" />
			</p>
			<div className="d-flex align-items-center gap-3">
				<div className="flex-fill">
					{data?.model.present ? (
						<span className="badge bg-green-lt">
							<T
								id="npmos.waf.model.present"
								data={{
									size: formatSize(data.model.size),
									date: data.model.modifiedOn ? formatDateTime(data.model.modifiedOn, locale) : "—",
								}}
							/>
						</span>
					) : (
						<span className="badge bg-secondary-lt">
							<T id="npmos.waf.model.basic" />
						</span>
					)}
				</div>
				<HasPermission rbac="waf_policy" permission={MANAGE} hideError>
					<input
						ref={input}
						type="file"
						accept=".tgz,.tar.gz,application/gzip"
						className="d-none"
						onChange={(e) => upload(e.target.files?.[0])}
					/>
					<Button size="sm" isLoading={uploading} onClick={() => input.current?.click()}>
						<T id="npmos.waf.model.upload" />
					</Button>
				</HasPermission>
			</div>
		</>
	);
}

export function AgentSettingsCard() {
	return (
		<div className="card mt-4">
			<div className="card-header">
				<h3 className="card-title">
					<T id="npmos.waf.agent-settings" />
				</h3>
			</div>
			<div className="card-body">
				<SettingsCard />
				<hr />
				<h4>
					<T id="npmos.waf.model" />
				</h4>
				<ModelCard />
			</div>
		</div>
	);
}
