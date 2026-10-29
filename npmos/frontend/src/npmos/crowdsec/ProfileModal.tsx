// A profile of CrowdSec: which alerts it takes (scope, scenarios, an expression) and the decision
// it makes (ban or captcha, how long, longer for each next ban of the same address).
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { T } from "src/locale";
import { type CrowdsecProfile, DECISION_TYPES, DURATIONS, SCOPES } from "./api";
import { durationLabel, t } from "./labels";

interface Props extends InnerModalProps {
	profile?: CrowdsecProfile;
	/** names taken by the other profiles */
	names: string[];
	onSave: (profile: CrowdsecProfile) => void;
}

const NAME = /^[a-z0-9][a-z0-9_-]{0,47}$/;
/** example in the field (a name of the hub, not translated) */
const EXAMPLE_SCENARIO = "crowdsecurity/http-probing";

const ProfileModal = EasyModal.create(({ visible, remove, profile, names, onSave }: Props) => {
	const [p, setP] = useState<CrowdsecProfile>(
		profile ?? {
			name: "",
			enabled: true,
			scope: "Ip",
			scenarios: [],
			filter: "",
			type: "ban",
			duration: "4h",
			escalate: false,
		},
	);
	const [scenarios, setScenarios] = useState(p.scenarios.join("\n"));
	const set = (patch: Partial<CrowdsecProfile>) => setP({ ...p, ...patch });
	const nameError = !NAME.test(p.name) ? "format" : names.includes(p.name) ? "taken" : null;
	const durations = DURATIONS.includes(p.duration as (typeof DURATIONS)[number])
		? DURATIONS
		: [p.duration, ...DURATIONS];

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={profile ? "npmos.crowdsec.profile.edit" : "npmos.crowdsec.profile.add"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<div className="row">
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-pr-name">
							<T id="npmos.crowdsec.name" />
						</label>
						<input
							id="cs-pr-name"
							className={`form-control ${p.name && nameError ? "is-invalid" : ""}`}
							maxLength={48}
							value={p.name}
							onChange={(e) => set({ name: e.target.value.toLowerCase() })}
						/>
						{p.name && nameError && (
							<div className="invalid-feedback">
								<T id={`npmos.crowdsec.profile.name.${nameError}`} />
							</div>
						)}
					</div>
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-pr-scope">
							<T id="npmos.crowdsec.profile.scope" />
						</label>
						<select
							id="cs-pr-scope"
							className="form-select"
							value={p.scope}
							onChange={(e) => set({ scope: e.target.value as CrowdsecProfile["scope"] })}
						>
							{SCOPES.map((s) => (
								<option key={s} value={s}>
									{t(`npmos.crowdsec.scope.${s}`)}
								</option>
							))}
						</select>
					</div>
				</div>
				<div className="mb-3">
					<label className="form-label" htmlFor="cs-pr-scenarios">
						<T id="npmos.crowdsec.profile.scenarios" />
					</label>
					<textarea
						id="cs-pr-scenarios"
						className="form-control font-monospace"
						rows={3}
						placeholder={EXAMPLE_SCENARIO}
						value={scenarios}
						onChange={(e) => {
							setScenarios(e.target.value);
							set({ scenarios: e.target.value.split(/[\s,]+/).filter(Boolean) });
						}}
					/>
					<div className="form-hint">
						<T id="npmos.crowdsec.profile.scenarios.hint" />
					</div>
				</div>
				<div className="mb-3">
					<label className="form-label" htmlFor="cs-pr-filter">
						<T id="npmos.crowdsec.profile.filter" />
					</label>
					<input
						id="cs-pr-filter"
						className="form-control font-monospace"
						placeholder={'Alert.GetValue() != "198.51.100.7"'}
						value={p.filter}
						onChange={(e) => set({ filter: e.target.value })}
					/>
					<div className="form-hint">
						<T id="npmos.crowdsec.profile.filter.hint" />
					</div>
				</div>
				<div className="row">
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-pr-type">
							<T id="npmos.crowdsec.decision" />
						</label>
						<select
							id="cs-pr-type"
							className="form-select"
							value={p.type}
							onChange={(e) => set({ type: e.target.value as CrowdsecProfile["type"] })}
						>
							{DECISION_TYPES.map((d) => (
								<option key={d} value={d}>
									{t(`npmos.crowdsec.decision.${d}`)}
								</option>
							))}
						</select>
					</div>
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-pr-duration">
							<T id="npmos.crowdsec.duration" />
						</label>
						<select
							id="cs-pr-duration"
							className="form-select"
							value={p.duration}
							onChange={(e) => set({ duration: e.target.value })}
						>
							{durations.map((d) => (
								<option key={d} value={d}>
									{durationLabel(d)}
								</option>
							))}
						</select>
					</div>
				</div>
				<label className="form-check">
					<input
						type="checkbox"
						className="form-check-input"
						checked={p.escalate}
						onChange={(e) => set({ escalate: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="npmos.crowdsec.profile.escalate" />
					</span>
					<span className="form-check-description">
						<T id="npmos.crowdsec.profile.escalate.hint" data={{ duration: durationLabel(p.duration) }} />
					</span>
				</label>
				<label className="form-check">
					<input
						type="checkbox"
						className="form-check-input"
						checked={p.enabled}
						onChange={(e) => set({ enabled: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="npmos.crowdsec.profile.enabled" />
					</span>
				</label>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="cancel" />
				</Button>
				<Button
					actionType="primary"
					className="ms-auto"
					disabled={!!nameError}
					onClick={() => {
						onSave(p);
						remove();
					}}
				>
					<T id="npmos.crowdsec.profile.done" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showProfileModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(ProfileModal, props);
