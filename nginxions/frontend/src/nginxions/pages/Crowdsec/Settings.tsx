// CrowdSec → Settings: the bouncer of NginxionS, sources of logs, the rule "blocked by open-appsec N
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
import { HiddenUsername } from "../../ui/HiddenUsername";

const SCENARIO_PLACEHOLDER = "crowdsecurity/http-probing\nnginxions/openappsec-prevent";

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
			showSuccess(
				t(
					r.result?.reloaded
						? "nginxions.crowdsec.settings.reloaded"
						: r.result?.restarted
							? "nginxions.crowdsec.settings.applied"
							: "nginxions.crowdsec.settings.saved",
				),
			);
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
					<T id="nginxions.crowdsec.settings.pending" data={{ files: data.pending.join(", ") }} />
				</Alert>
			)}
			<Section heading="nginxions.crowdsec.bouncer.title" hint="nginxions.crowdsec.bouncer.hint">
				<Check
					label="nginxions.crowdsec.bouncer.enabled"
					checked={b.enabled}
					disabled={!manage}
					onChange={(enabled) => setB({ enabled })}
				/>
				<Check
					label="nginxions.crowdsec.bouncer.admin"
					hint="nginxions.crowdsec.bouncer.admin.hint"
					checked={b.admin}
					disabled={!manage || !b.enabled}
					onChange={(admin) => setB({ admin })}
				/>
				<div className="row mt-2">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-b-mode">
							<T id="nginxions.crowdsec.bouncer.mode" />
						</label>
						<select
							id="cs-b-mode"
							className="form-select"
							disabled={!manage}
							value={b.mode}
							onChange={(e) => setB({ mode: e.target.value as "live" | "stream" })}
						>
							<option value="live">{t("nginxions.crowdsec.bouncer.mode.live")}</option>
							<option value="stream">{t("nginxions.crowdsec.bouncer.mode.stream")}</option>
						</select>
						<div className="form-hint">
							<T id={`nginxions.crowdsec.bouncer.mode.${b.mode}.hint`} />
						</div>
					</div>
					{b.mode === "stream" && (
						<div className="col-md-4 mb-3">
							<label className="form-label" htmlFor="cs-b-freq">
								<T id="nginxions.crowdsec.bouncer.update-frequency" />
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
							<T id="nginxions.crowdsec.bouncer.fallback" />
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
									{t(`nginxions.crowdsec.decision.${d}`)}
								</option>
							))}
						</select>
					</div>
				</div>
				<div className="mb-3">
					<label className="form-label" htmlFor="cs-b-exclude">
						<T id="nginxions.crowdsec.bouncer.exclude" />
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
						<T id="nginxions.crowdsec.bouncer.exclude.hint" />
					</div>
				</div>
				<div className="row">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-b-captcha">
							<T id="nginxions.crowdsec.captcha.provider" />
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
									{t(`nginxions.crowdsec.captcha.provider.${p || "none"}`)}
								</option>
							))}
						</select>
					</div>
					{b.captcha.provider && (
						<>
							<div className="col-md-4 mb-3">
								<label className="form-label" htmlFor="cs-b-site">
									<T id="nginxions.crowdsec.captcha.site-key" />
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
									<T id="nginxions.crowdsec.captcha.secret-key" />
								</label>
								{/* NginxionS: inside a form with a user field, so the browser does not warn about the password */}
								<form
									style={{ display: "contents" }}
									autoComplete="off"
									onSubmit={(e) => e.preventDefault()}
								>
									<HiddenUsername />
									<input
										id="cs-b-secret"
										type="password"
										autoComplete="off"
										className="form-control"
										disabled={!manage}
										placeholder={b.captcha.hasSecret ? t("nginxions.crowdsec.secret.kept") : ""}
										value={secret}
										onChange={(e) => setSecret(e.target.value.trim())}
									/>
								</form>
							</div>
						</>
					)}
				</div>
				{captchaUsed && !b.captcha.provider && (
					<div className="text-warning small">
						<T id="nginxions.crowdsec.captcha.needs-provider" />
					</div>
				)}
				<div className="text-secondary small">
					<T id="nginxions.crowdsec.bouncer.hosts" />
				</div>
			</Section>

			<Section heading="nginxions.crowdsec.sources.title" hint="nginxions.crowdsec.sources.hint">
				<Check
					label="nginxions.crowdsec.sources.nginx"
					hint="nginxions.crowdsec.sources.nginx.hint"
					checked={s.sources.nginx}
					disabled={!manage}
					onChange={(nginx) => setS({ ...s, sources: { ...s.sources, nginx } })}
				/>
				<Check
					label="nginxions.crowdsec.sources.openappsec"
					hint="nginxions.crowdsec.sources.openappsec.hint"
					checked={s.sources.openappsec}
					disabled={!manage}
					onChange={(openappsec) => setS({ ...s, sources: { ...s.sources, openappsec } })}
				/>
			</Section>

			<Section heading="nginxions.crowdsec.openappsec-ban.title" hint="nginxions.crowdsec.openappsec-ban.hint">
				<Check
					label="nginxions.crowdsec.openappsec-ban.enabled"
					checked={s.openappsecBan.enabled}
					disabled={!manage || !s.sources.openappsec}
					onChange={(enabled) => setS({ ...s, openappsecBan: { ...s.openappsecBan, enabled } })}
				/>
				<div className="row mt-2">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-oa-events">
							<T id="nginxions.crowdsec.openappsec-ban.events" />
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
							<T id="nginxions.crowdsec.openappsec-ban.minutes" />
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
					<T id="nginxions.crowdsec.openappsec-ban.profile" />
				</div>
			</Section>

			<Section heading="nginxions.crowdsec.appsec.title" hint="nginxions.crowdsec.appsec.hint">
				<Check
					label="nginxions.crowdsec.appsec.enabled"
					checked={s.appsec.enabled}
					disabled={!manage}
					onChange={(enabled) => setS({ ...s, appsec: { ...s.appsec, enabled } })}
				/>
				<div className="row mt-2">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-as-fail">
							<T id="nginxions.crowdsec.appsec.failure" />
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
							<option value="passthrough">{t("nginxions.crowdsec.appsec.failure.passthrough")}</option>
							<option value="deny">{t("nginxions.crowdsec.appsec.failure.deny")}</option>
						</select>
					</div>
					<div className="col-md-8 mb-3">
						<label className="form-label" htmlFor="cs-as-configs">
							<T id="nginxions.crowdsec.appsec.configs" />
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
							<T id="nginxions.crowdsec.appsec.configs.hint" />
						</div>
					</div>
				</div>
			</Section>

			<Section heading="nginxions.crowdsec.profiles.title" hint="nginxions.crowdsec.profiles.hint">
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="nginxions.crowdsec.name" />
								</th>
								<th>
									<T id="nginxions.crowdsec.profile.takes" />
								</th>
								<th>
									<T id="nginxions.crowdsec.decision" />
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
										{t(`nginxions.crowdsec.scope.${p.scope}`)}
										{p.scenarios.length > 0 && `, ${p.scenarios.join(", ")}`}
										{p.filter && `, ${p.filter}`}
									</td>
									<td className="text-nowrap">
										{t(`nginxions.crowdsec.decision.${p.type}`)}, {durationLabel(p.duration)}
										{p.escalate && (
											<span className="badge bg-orange-lt ms-2">
												<T id="nginxions.crowdsec.profile.escalates" />
											</span>
										)}
									</td>
									{manage && (
										<td className="text-nowrap">
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												aria-label={t("nginxions.crowdsec.move-up")}
												disabled={i === 0}
												onClick={() => move(i, -1)}
											>
												<IconArrowUp size={16} />
											</button>
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												aria-label={t("nginxions.crowdsec.move-down")}
												disabled={i === profiles.length - 1}
												onClick={() => move(i, 1)}
											>
												<IconArrowDown size={16} />
											</button>
											<button
												type="button"
												className="btn btn-sm btn-ghost-secondary btn-icon"
												aria-label={t("nginxions.crowdsec.profile.edit")}
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
						<T id="nginxions.crowdsec.profiles.none" />
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
						<T id="nginxions.crowdsec.profile.add" />
					</button>
				)}
			</Section>

			<Section heading="nginxions.crowdsec.allowlist.title" hint="nginxions.crowdsec.allowlist.hint">
				<Check
					label="nginxions.crowdsec.allowlist.private"
					hint="nginxions.crowdsec.allowlist.private.hint"
					checked={s.allowlist.private}
					disabled={!manage}
					onChange={(v) => setS({ ...s, allowlist: { ...s.allowlist, private: v } })}
				/>
				<div className="row mt-2">
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-al-ips">
							<T id="nginxions.crowdsec.allowlist.ips" />
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
							<T id="nginxions.crowdsec.allowlist.ips.hint" />
						</div>
					</div>
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-al-expr">
							<T id="nginxions.crowdsec.allowlist.expressions" />
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
							<T id="nginxions.crowdsec.allowlist.expressions.hint" />
						</div>
					</div>
				</div>
			</Section>

			<Section heading="nginxions.crowdsec.simulation.title" hint="nginxions.crowdsec.simulation.hint">
				<Check
					label="nginxions.crowdsec.simulation.all"
					hint="nginxions.crowdsec.simulation.all.hint"
					checked={s.simulation.all}
					disabled={!manage}
					onChange={(all) => setS({ ...s, simulation: { ...s.simulation, all } })}
				/>
				<label className="form-label" htmlFor="cs-simulated">
					<T
						id={
							s.simulation.all
								? "nginxions.crowdsec.simulation.except"
								: "nginxions.crowdsec.simulation.only"
						}
					/>
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
					<T id="nginxions.crowdsec.simulation.scenarios.hint" />
				</div>
			</Section>

			<Section heading="nginxions.crowdsec.other.title">
				<div className="row">
					<div className="col-md-4 mb-3">
						<label className="form-label" htmlFor="cs-log-level">
							<T id="nginxions.crowdsec.log-level" />
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
									{t(`nginxions.crowdsec.log-level.${l}`)}
								</option>
							))}
						</select>
					</div>
				</div>
				<Check
					label="nginxions.crowdsec.online-hub"
					hint="nginxions.crowdsec.online-hub.hint"
					checked={s.onlineHub}
					disabled={!manage}
					onChange={(onlineHub) => setS({ ...s, onlineHub })}
				/>
				<div className="text-secondary small">
					<T id="nginxions.crowdsec.capi" />
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
						<T id="nginxions.crowdsec.settings.save" />
					</button>
					{busy && (
						<span className="text-secondary small">
							<T id="nginxions.crowdsec.settings.restarting" />
						</span>
					)}
				</div>
			)}
		</>
	);
}
