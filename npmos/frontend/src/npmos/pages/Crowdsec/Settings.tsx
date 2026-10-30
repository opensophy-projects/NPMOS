// CrowdSec → Settings: the bouncer of NPMOS, sources of logs, the rule "blocked by open-appsec N
// times → ban", CrowdSec AppSec, profiles, the allowlist and the rest. Saving writes the files of
// CrowdSec and restarts it; if it does not start, the previous files come back.
import { IconArrowDown, IconArrowUp, IconPencil, IconPlus, IconTrash } from "@tabler/icons-react";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { T } from "src/locale";
import { showSuccess } from "src/notifications";
import {
	CAPTCHA_PROVIDERS,
	type CrowdsecProfile,
	type CrowdsecSettings,
	type CrowdsecSettingsState,
	DECISION_TYPES,
	LOG_LEVELS,
	setSettings,
} from "../../crowdsec/api";
import { durationLabel, t } from "../../crowdsec/labels";
import { showProfileModal } from "../../crowdsec/ProfileModal";
import { useCan } from "../../rbac/hooks";
import styles from "../Pki/Pki.module.css";

const SCENARIO_PLACEHOLDER = "crowdsecurity/http-probing\nnpmos/openappsec-prevent";

const lines = (text: string) =>
	text
		.split("\n")
		.map((l) => l.trim())
		.filter(Boolean);

function Section({ heading, hint, children }: { heading: string; hint?: string; children: React.ReactNode }) {
	return (
		<section className={cn("card", styles.card)}>
			<h3 className="card-title mb-1">
				<T id={heading} />
			</h3>
			{hint && (
				<div className="text-secondary small mb-3">
					<T id={hint} />
				</div>
			)}
			{children}
		</section>
	);
}

function Check({
	label,
	hint,
	checked,
	disabled,
	onChange,
}: {
	label: string;
	hint?: string;
	checked: boolean;
	disabled?: boolean;
	onChange: (v: boolean) => void;
}) {
	return (
		<label className="form-check form-switch mb-2">
			<input
				type="checkbox"
				className="form-check-input"
				checked={checked}
				disabled={disabled}
				onChange={(e) => onChange(e.target.checked)}
			/>
			<span className="form-check-label">
				<T id={label} />
			</span>
			{hint && (
				<span className="form-check-description">
					<T id={hint} />
				</span>
			)}
		</label>
	);
}

export function SettingsTab({ data, refresh }: { data: CrowdsecSettingsState; refresh: () => void }) {
	const can = useCan();
	const manage = can("crowdsec", "manage");
	const [s, setS] = useState<CrowdsecSettings>(data);
	const [secret, setSecret] = useState("");
	const [excluded, setExcluded] = useState(data.bouncer.excludeLocations.join("\n"));
	const [ips, setIps] = useState(data.allowlist.ips.join("\n"));
	const [expressions, setExpressions] = useState(data.allowlist.expressions.join("\n"));
	const [configs, setConfigs] = useState(data.appsec.configs.join("\n"));
	const [simulated, setSimulated] = useState(data.simulation.scenarios.join("\n"));
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// biome-ignore lint/correctness/useExhaustiveDependencies: the form starts over when the saved settings change
	useEffect(() => {
		setS(data);
		setExcluded(data.bouncer.excludeLocations.join("\n"));
		setIps(data.allowlist.ips.join("\n"));
		setExpressions(data.allowlist.expressions.join("\n"));
		setConfigs(data.appsec.configs.join("\n"));
		setSimulated(data.simulation.scenarios.join("\n"));
	}, [JSON.stringify(data)]);

	const b = s.bouncer;
	const setB = (patch: Partial<CrowdsecSettings["bouncer"]>) => setS({ ...s, bouncer: { ...b, ...patch } });
	const profiles = s.profiles;
	const setProfiles = (list: CrowdsecProfile[]) => setS({ ...s, profiles: list });
	const move = (i: number, d: number) => {
		const list = [...profiles];
		[list[i], list[i + d]] = [list[i + d], list[i]];
		setProfiles(list);
	};
	const captchaUsed = profiles.some((p) => p.enabled && p.type === "captcha") || b.fallback === "captcha";

	const save = async () => {
		setBusy(true);
		setError(null);
		try {
			const r = await setSettings({
				...s,
				bouncer: { ...b, excludeLocations: lines(excluded), captcha: { ...b.captcha, secretKey: secret } },
				allowlist: { ...s.allowlist, ips: lines(ips), expressions: lines(expressions) },
				appsec: { ...s.appsec, configs: lines(configs) },
				simulation: { ...s.simulation, scenarios: lines(simulated) },
			});
			setSecret("");
			showSuccess(t(r.result?.restarted ? "npmos.crowdsec.settings.applied" : "npmos.crowdsec.settings.saved"));
		} catch (err: any) {
			setError(err.message);
		}
		setBusy(false);
		refresh();
	};

	const number = (value: number, min: number, max: number, onChange: (v: number) => void, id: string) => (
		<input
			id={id}
			type="number"
			min={min}
			max={max}
			className="form-control"
			disabled={!manage}
			value={value}
			onChange={(e) => onChange(Number(e.target.value))}
		/>
	);

	return (
		<>
			{data.pending.length > 0 && (
				<Alert variant="warning" className="mb-0">
					<T id="npmos.crowdsec.settings.pending" data={{ files: data.pending.join(", ") }} />
				</Alert>
			)}
			<Section heading="npmos.crowdsec.bouncer.title" hint="npmos.crowdsec.bouncer.hint">
				<Check
					label="npmos.crowdsec.bouncer.enabled"
					checked={b.enabled}
					disabled={!manage}
					onChange={(enabled) => setB({ enabled })}
				/>
				<Check
					label="npmos.crowdsec.bouncer.admin"
					hint="npmos.crowdsec.bouncer.admin.hint"
					checked={b.admin}
					disabled={!manage || !b.enabled}
					onChange={(admin) => setB({ admin })}
				/>
				<div className="row mt-2">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-b-mode">
							<T id="npmos.crowdsec.bouncer.mode" />
						</label>
						<select
							id="cs-b-mode"
							className="form-select"
							disabled={!manage}
							value={b.mode}
							onChange={(e) => setB({ mode: e.target.value as "live" | "stream" })}
						>
							<option value="live">{t("npmos.crowdsec.bouncer.mode.live")}</option>
							<option value="stream">{t("npmos.crowdsec.bouncer.mode.stream")}</option>
						</select>
						<div className="form-hint">
							<T id={`npmos.crowdsec.bouncer.mode.${b.mode}.hint`} />
						</div>
					</div>
					{b.mode === "stream" && (
						<div className="col-md-4 mb-3">
							<label className="form-label" htmlFor="cs-b-freq">
								<T id="npmos.crowdsec.bouncer.update-frequency" />
							</label>
							{number(
								b.updateFrequency,
								1,
								3600,
								(updateFrequency) => setB({ updateFrequency }),
								"cs-b-freq",
							)}
						</div>
					)}
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-b-fallback">
							<T id="npmos.crowdsec.bouncer.fallback" />
						</label>
						<select
							id="cs-b-fallback"
							className="form-select"
							disabled={!manage}
							value={b.fallback}
							onChange={(e) => setB({ fallback: e.target.value as "ban" | "captcha" })}
						>
							{DECISION_TYPES.map((d) => (
								<option key={d} value={d}>
									{t(`npmos.crowdsec.decision.${d}`)}
								</option>
							))}
						</select>
					</div>
				</div>
				<div className="mb-3">
					<label className="form-label" htmlFor="cs-b-exclude">
						<T id="npmos.crowdsec.bouncer.exclude" />
					</label>
					<textarea
						id="cs-b-exclude"
						className="form-control font-monospace"
						rows={2}
						disabled={!manage}
						placeholder="/healthz"
						value={excluded}
						onChange={(e) => setExcluded(e.target.value)}
					/>
					<div className="form-hint">
						<T id="npmos.crowdsec.bouncer.exclude.hint" />
					</div>
				</div>
				<div className="row">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-b-captcha">
							<T id="npmos.crowdsec.captcha.provider" />
						</label>
						<select
							id="cs-b-captcha"
							className="form-select"
							disabled={!manage}
							value={b.captcha.provider}
							onChange={(e) =>
								setB({
									captcha: {
										...b.captcha,
										provider: e.target.value as CrowdsecSettings["bouncer"]["captcha"]["provider"],
									},
								})
							}
						>
							{CAPTCHA_PROVIDERS.map((p) => (
								<option key={p} value={p}>
									{t(`npmos.crowdsec.captcha.provider.${p || "none"}`)}
								</option>
							))}
						</select>
					</div>
					{b.captcha.provider && (
						<>
							<div className="col-md-4 mb-3">
								<label className="form-label" htmlFor="cs-b-site">
									<T id="npmos.crowdsec.captcha.site-key" />
								</label>
								<input
									id="cs-b-site"
									className="form-control"
									disabled={!manage}
									value={b.captcha.siteKey}
									onChange={(e) =>
										setB({ captcha: { ...b.captcha, siteKey: e.target.value.trim() } })
									}
								/>
							</div>
							<div className="col-md-4 mb-3">
								<label className="form-label" htmlFor="cs-b-secret">
									<T id="npmos.crowdsec.captcha.secret-key" />
								</label>
								<input
									id="cs-b-secret"
									type="password"
									autoComplete="off"
									className="form-control"
									disabled={!manage}
									placeholder={b.captcha.hasSecret ? t("npmos.crowdsec.secret.kept") : ""}
									value={secret}
									onChange={(e) => setSecret(e.target.value.trim())}
								/>
							</div>
						</>
					)}
				</div>
				{captchaUsed && !b.captcha.provider && (
					<div className="text-warning small">
						<T id="npmos.crowdsec.captcha.needs-provider" />
					</div>
				)}
				<div className="text-secondary small">
					<T id="npmos.crowdsec.bouncer.hosts" />
				</div>
			</Section>

			<Section heading="npmos.crowdsec.sources.title" hint="npmos.crowdsec.sources.hint">
				<Check
					label="npmos.crowdsec.sources.nginx"
					hint="npmos.crowdsec.sources.nginx.hint"
					checked={s.sources.nginx}
					disabled={!manage}
					onChange={(nginx) => setS({ ...s, sources: { ...s.sources, nginx } })}
				/>
				<Check
					label="npmos.crowdsec.sources.openappsec"
					hint="npmos.crowdsec.sources.openappsec.hint"
					checked={s.sources.openappsec}
					disabled={!manage}
					onChange={(openappsec) => setS({ ...s, sources: { ...s.sources, openappsec } })}
				/>
			</Section>

			<Section heading="npmos.crowdsec.openappsec-ban.title" hint="npmos.crowdsec.openappsec-ban.hint">
				<Check
					label="npmos.crowdsec.openappsec-ban.enabled"
					checked={s.openappsecBan.enabled}
					disabled={!manage || !s.sources.openappsec}
					onChange={(enabled) => setS({ ...s, openappsecBan: { ...s.openappsecBan, enabled } })}
				/>
				<div className="row mt-2">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-oa-events">
							<T id="npmos.crowdsec.openappsec-ban.events" />
						</label>
						{number(
							s.openappsecBan.events,
							1,
							1000,
							(events) => setS({ ...s, openappsecBan: { ...s.openappsecBan, events } }),
							"cs-oa-events",
						)}
					</div>
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-oa-minutes">
							<T id="npmos.crowdsec.openappsec-ban.minutes" />
						</label>
						{number(
							s.openappsecBan.minutes,
							1,
							1440,
							(minutes) => setS({ ...s, openappsecBan: { ...s.openappsecBan, minutes } }),
							"cs-oa-minutes",
						)}
					</div>
				</div>
				<div className="text-secondary small">
					<T id="npmos.crowdsec.openappsec-ban.profile" />
				</div>
			</Section>

			<Section heading="npmos.crowdsec.appsec.title" hint="npmos.crowdsec.appsec.hint">
				<Check
					label="npmos.crowdsec.appsec.enabled"
					checked={s.appsec.enabled}
					disabled={!manage}
					onChange={(enabled) => setS({ ...s, appsec: { ...s.appsec, enabled } })}
				/>
				<div className="row mt-2">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-as-fail">
							<T id="npmos.crowdsec.appsec.failure" />
						</label>
						<select
							id="cs-as-fail"
							className="form-select"
							disabled={!manage}
							value={s.appsec.failureAction}
							onChange={(e) =>
								setS({
									...s,
									appsec: { ...s.appsec, failureAction: e.target.value as "passthrough" | "deny" },
								})
							}
						>
							<option value="passthrough">{t("npmos.crowdsec.appsec.failure.passthrough")}</option>
							<option value="deny">{t("npmos.crowdsec.appsec.failure.deny")}</option>
						</select>
					</div>
					<div className="col-md-8 mb-3">
						<label className="form-label" htmlFor="cs-as-configs">
							<T id="npmos.crowdsec.appsec.configs" />
						</label>
						<textarea
							id="cs-as-configs"
							className="form-control font-monospace"
							rows={2}
							disabled={!manage}
							value={configs}
							onChange={(e) => setConfigs(e.target.value)}
						/>
						<div className="form-hint">
							<T id="npmos.crowdsec.appsec.configs.hint" />
						</div>
					</div>
				</div>
			</Section>

			<Section heading="npmos.crowdsec.profiles.title" hint="npmos.crowdsec.profiles.hint">
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.crowdsec.name" />
								</th>
								<th>
									<T id="npmos.crowdsec.profile.takes" />
								</th>
								<th>
									<T id="npmos.crowdsec.decision" />
								</th>
								{manage && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{profiles.map((p, i) => (
								<tr key={p.name} className={cn(!p.enabled && "text-secondary")}>
									<td>
										{p.name}
										{!p.enabled && (
											<span className="badge bg-secondary-lt ms-2">
												<T id="disabled" />
											</span>
										)}
									</td>
									<td className={styles.sub}>
										{t(`npmos.crowdsec.scope.${p.scope}`)}
										{p.scenarios.length > 0 && `, ${p.scenarios.join(", ")}`}
										{p.filter && `, ${p.filter}`}
									</td>
									<td className="text-nowrap">
										{t(`npmos.crowdsec.decision.${p.type}`)}, {durationLabel(p.duration)}
										{p.escalate && (
											<span className="badge bg-orange-lt ms-2">
												<T id="npmos.crowdsec.profile.escalates" />
											</span>
										)}
									</td>
									{manage && (
										<td className="text-nowrap">
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												aria-label={t("npmos.crowdsec.move-up")}
												disabled={i === 0}
												onClick={() => move(i, -1)}
											>
												<IconArrowUp size={16} />
											</button>
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												aria-label={t("npmos.crowdsec.move-down")}
												disabled={i === profiles.length - 1}
												onClick={() => move(i, 1)}
											>
												<IconArrowDown size={16} />
											</button>
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												aria-label={t("npmos.crowdsec.profile.edit")}
												onClick={() =>
													showProfileModal({
														profile: p,
														names: profiles.filter((x) => x !== p).map((x) => x.name),
														onSave: (np) =>
															setProfiles(profiles.map((x) => (x === p ? np : x))),
													})
												}
											>
												<IconPencil size={16} />
											</button>
											<button
												type="button"
												className="btn btn-sm btn-ghost-danger btn-icon"
												aria-label={t("action.delete")}
												onClick={() => setProfiles(profiles.filter((x) => x !== p))}
											>
												<IconTrash size={16} />
											</button>
										</td>
									)}
								</tr>
							))}
						</tbody>
					</table>
				</div>
				{!profiles.some((p) => p.enabled) && (
					<div className="text-warning small mt-2">
						<T id="npmos.crowdsec.profiles.none" />
					</div>
				)}
				{manage && (
					<button
						type="button"
						className="btn btn-sm mt-2"
						onClick={() =>
							showProfileModal({
								names: profiles.map((x) => x.name),
								onSave: (np) => setProfiles([...profiles, np]),
							})
						}
					>
						<IconPlus size={16} />
						<T id="npmos.crowdsec.profile.add" />
					</button>
				)}
			</Section>

			<Section heading="npmos.crowdsec.allowlist.title" hint="npmos.crowdsec.allowlist.hint">
				<Check
					label="npmos.crowdsec.allowlist.private"
					hint="npmos.crowdsec.allowlist.private.hint"
					checked={s.allowlist.private}
					disabled={!manage}
					onChange={(v) => setS({ ...s, allowlist: { ...s.allowlist, private: v } })}
				/>
				<div className="row mt-2">
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-al-ips">
							<T id="npmos.crowdsec.allowlist.ips" />
						</label>
						<textarea
							id="cs-al-ips"
							className="form-control font-monospace"
							rows={4}
							disabled={!manage}
							placeholder="192.0.2.10&#10;198.51.100.0/24"
							value={ips}
							onChange={(e) => setIps(e.target.value)}
						/>
						<div className="form-hint">
							<T id="npmos.crowdsec.allowlist.ips.hint" />
						</div>
					</div>
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-al-expr">
							<T id="npmos.crowdsec.allowlist.expressions" />
						</label>
						<textarea
							id="cs-al-expr"
							className="form-control font-monospace"
							rows={4}
							disabled={!manage}
							placeholder={"evt.Meta.http_path == '/healthz'"}
							value={expressions}
							onChange={(e) => setExpressions(e.target.value)}
						/>
						<div className="form-hint">
							<T id="npmos.crowdsec.allowlist.expressions.hint" />
						</div>
					</div>
				</div>
			</Section>

			<Section heading="npmos.crowdsec.simulation.title" hint="npmos.crowdsec.simulation.hint">
				<Check
					label="npmos.crowdsec.simulation.all"
					hint="npmos.crowdsec.simulation.all.hint"
					checked={s.simulation.all}
					disabled={!manage}
					onChange={(all) => setS({ ...s, simulation: { ...s.simulation, all } })}
				/>
				<label className="form-label" htmlFor="cs-simulated">
					<T id={s.simulation.all ? "npmos.crowdsec.simulation.except" : "npmos.crowdsec.simulation.only"} />
				</label>
				<textarea
					id="cs-simulated"
					className="form-control font-monospace"
					rows={3}
					disabled={!manage}
					placeholder={SCENARIO_PLACEHOLDER}
					value={simulated}
					onChange={(e) => setSimulated(e.target.value)}
				/>
				<div className="form-hint">
					<T id="npmos.crowdsec.simulation.scenarios.hint" />
				</div>
			</Section>

			<Section heading="npmos.crowdsec.other.title">
				<div className="row">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-log-level">
							<T id="npmos.crowdsec.log-level" />
						</label>
						<select
							id="cs-log-level"
							className="form-select"
							disabled={!manage}
							value={s.logLevel}
							onChange={(e) => setS({ ...s, logLevel: e.target.value as CrowdsecSettings["logLevel"] })}
						>
							{LOG_LEVELS.map((l) => (
								<option key={l} value={l}>
									{t(`npmos.crowdsec.log-level.${l}`)}
								</option>
							))}
						</select>
					</div>
				</div>
				<Check
					label="npmos.crowdsec.online-hub"
					hint="npmos.crowdsec.online-hub.hint"
					checked={s.onlineHub}
					disabled={!manage}
					onChange={(onlineHub) => setS({ ...s, onlineHub })}
				/>
				<div className="text-secondary small">
					<T id="npmos.crowdsec.capi" />
				</div>
			</Section>

			{error && (
				<Alert variant="danger" className="mb-0">
					{error}
				</Alert>
			)}
			{manage && (
				<div className="d-flex align-items-center gap-3">
					<button type="button" className="btn btn-primary" disabled={busy} onClick={save}>
						{busy && <span className="spinner-border spinner-border-sm me-2" />}
						<T id="npmos.crowdsec.settings.save" />
					</button>
					{busy && (
						<span className="text-secondary small">
							<T id="npmos.crowdsec.settings.restarting" />
						</span>
					)}
				</div>
			)}
		</>
	);
}
