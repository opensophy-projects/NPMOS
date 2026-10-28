// A notification rule: what is watched, its parameters, which channels get the messages, reminders
// while the problem lasts, a message when it is resolved.
import { useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import {
	type Channel,
	createRule,
	type Notifications,
	type Rule,
	type RuleInput,
	type RuleType,
	updateRule,
} from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

/** number parameters of rule types, with their limits */
const NUMBER_PARAMS: Partial<Record<RuleType, { name: string; min: number; max: number }[]>> = {
	attack_spike: [
		{ name: "threshold", min: 1, max: 1000000 },
		{ name: "window", min: 1, max: 1440 },
	],
	agent_down: [{ name: "minutes", min: 1, max: 1440 }],
	cert_expiry: [{ name: "days", min: 1, max: 365 }],
};

interface Props extends InnerModalProps {
	data: Notifications;
	rule?: Rule;
}

const RuleModal = EasyModal.create(({ data, rule, visible, remove }: Props) => {
	const queryClient = useQueryClient();
	const defaults = (type: RuleType) => data.ruleTypes.find((r) => r.type === type)?.defaults ?? {};
	const [form, setForm] = useState<RuleInput>(() =>
		rule
			? {
					name: rule.name,
					type: rule.type,
					enabled: rule.enabled,
					params: rule.params,
					channelIds: rule.channelIds,
					repeatMinutes: rule.repeatMinutes,
					notifyResolved: rule.notifyResolved,
				}
			: {
					name: t("npmos.notifications.rule.attack_spike"),
					type: "attack_spike",
					enabled: true,
					params: defaults("attack_spike"),
					channelIds: data.channels.filter((c) => c.enabled).map((c) => c.id),
					repeatMinutes: 0,
					notifyResolved: true,
				},
	);
	const [error, setError] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);

	const setType = (type: RuleType) =>
		setForm({
			...form,
			type,
			params: defaults(type),
			// a name the user did not change follows the type
			name:
				form.name === t(`npmos.notifications.rule.${form.type}`)
					? t(`npmos.notifications.rule.${type}`)
					: form.name,
		});
	const toggleChannel = (channel: Channel) =>
		setForm({
			...form,
			channelIds: form.channelIds.includes(channel.id)
				? form.channelIds.filter((id) => id !== channel.id)
				: [...form.channelIds, channel.id],
		});

	const save = async () => {
		setSaving(true);
		setError(null);
		try {
			const { type, ...rest } = form;
			if (rule) await updateRule(rule.id, rest);
			else await createRule(form);
			queryClient.invalidateQueries({ queryKey: ["npmos-notifications"] });
			showSuccess(t("npmos.notifications.saved"));
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setSaving(false);
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={rule ? "npmos.notifications.rule.edit" : "npmos.notifications.rule.new"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				<div className="mb-3">
					<span className="form-label">
						<T id="npmos.notifications.rule.type" />
					</span>
					<select
						className="form-select"
						value={form.type}
						disabled={!!rule}
						onChange={(e) => setType(e.target.value as RuleType)}
					>
						{data.ruleTypes.map((r) => (
							<option key={r.type} value={r.type}>
								{t(`npmos.notifications.rule.${r.type}`)}
							</option>
						))}
					</select>
					<div className="form-hint">
						<T id={`npmos.notifications.rule.${form.type}.hint`} />
					</div>
				</div>
				<div className="mb-3">
					<span className="form-label">
						<T id="npmos.notifications.name" />
					</span>
					<input
						className="form-control"
						value={form.name}
						maxLength={100}
						onChange={(e) => setForm({ ...form, name: e.target.value })}
					/>
				</div>
				{(NUMBER_PARAMS[form.type]?.length || form.type === "attack_spike") && (
					<div className="row">
						{NUMBER_PARAMS[form.type]?.map((p) => (
							<div className="col-md-4 mb-3" key={p.name}>
								<span className="form-label">
									<T id={`npmos.notifications.param.${p.name}`} />
								</span>
								<input
									type="number"
									className="form-control"
									min={p.min}
									max={p.max}
									value={form.params[p.name] ?? ""}
									onChange={(e) =>
										setForm({
											...form,
											params: {
												...form.params,
												[p.name]: Number.parseInt(e.target.value, 10) || 0,
											},
										})
									}
								/>
							</div>
						))}
						{form.type === "attack_spike" && (
							<div className="col-md-4 mb-3">
								<span className="form-label">
									<T id="npmos.notifications.param.host" />
								</span>
								<input
									className="form-control"
									value={form.params.host ?? ""}
									placeholder={t("npmos.analytics.all-hosts")}
									onChange={(e) =>
										setForm({ ...form, params: { ...form.params, host: e.target.value } })
									}
								/>
							</div>
						)}
					</div>
				)}
				<div className="mb-3">
					<span className="form-label">
						<T id="npmos.notifications.channels" />
					</span>
					{data.channels.length === 0 ? (
						<div className="text-secondary">
							<T id="npmos.notifications.channels.none" />
						</div>
					) : (
						data.channels.map((c) => (
							<label className="form-check" key={c.id}>
								<input
									type="checkbox"
									className="form-check-input"
									checked={form.channelIds.includes(c.id)}
									onChange={() => toggleChannel(c)}
								/>
								<span className="form-check-label">
									{c.name}{" "}
									<span className="text-secondary">
										· <T id={`npmos.notifications.channel.${c.type}`} />
									</span>
								</span>
							</label>
						))
					)}
				</div>
				<div className="row">
					<div className="col-md-6 mb-3">
						<span className="form-label">
							<T id="npmos.notifications.repeat" />
						</span>
						<input
							type="number"
							className="form-control"
							min={0}
							max={10080}
							value={form.repeatMinutes}
							onChange={(e) =>
								setForm({ ...form, repeatMinutes: Number.parseInt(e.target.value, 10) || 0 })
							}
						/>
						<div className="form-hint">
							<T id="npmos.notifications.repeat.hint" />
						</div>
					</div>
					<div className="col-md-6 mb-3 d-flex flex-column justify-content-center gap-2">
						<label className="form-check form-switch m-0">
							<input
								type="checkbox"
								className="form-check-input"
								checked={form.notifyResolved}
								onChange={(e) => setForm({ ...form, notifyResolved: e.target.checked })}
							/>
							<span className="form-check-label">
								<T id="npmos.notifications.resolved" />
							</span>
						</label>
						<label className="form-check form-switch m-0">
							<input
								type="checkbox"
								className="form-check-input"
								checked={form.enabled}
								onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
							/>
							<span className="form-check-label">
								<T id="npmos.notifications.enabled" />
							</span>
						</label>
					</div>
				</div>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" isLoading={saving} disabled={!form.name.trim()} onClick={save}>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showRuleModal = (data: Notifications, rule?: Rule) => EasyModal.show(RuleModal, { data, rule });
