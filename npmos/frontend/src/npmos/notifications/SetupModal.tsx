// Notifications → quick setup: three steps instead of a channel and six rules by hand. 1. where to send (the
// channels there are, or a new one), 2. what to send (a preset: recommended, failures only, attacks,
// certificates; each rule can still be ticked off), 3. the rules to create, with the defaults of each type.
import { IconMail, IconSend, IconWebhook } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { type ChannelType, createRule, getNotifications, type Notifications, type RuleType } from "./api";
import { showChannelModal } from "./ChannelModal";
import styles from "./SetupModal.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const CHANNEL_ICON: Record<ChannelType, React.ReactNode> = {
	email: <IconMail size={18} />,
	webhook: <IconWebhook size={18} />,
	telegram: <IconSend size={18} />,
};

const RULES: RuleType[] = [
	"service_down",
	"agent_down",
	"policy_error",
	"host_problem",
	"cert_expiry",
	"attack_spike",
	"learning_queue",
];

/** presets: the rules each one ticks */
export const PRESETS: Record<string, RuleType[]> = {
	recommended: RULES,
	failures: ["service_down", "agent_down", "policy_error", "host_problem"],
	attacks: ["attack_spike", "agent_down", "learning_queue"],
	certificates: ["cert_expiry"],
};

type Step = 1 | 2 | 3;

const SetupModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const queryClient = useQueryClient();
	const { data } = useQuery<Notifications, Error>({ queryKey: ["npmos-notifications"], queryFn: getNotifications });
	const [step, setStep] = useState<Step>(1);
	const [channels, setChannels] = useState<number[]>([]);
	const [preset, setPreset] = useState("recommended");
	const [rules, setRules] = useState<RuleType[]>(PRESETS.recommended);
	const [error, setError] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);

	// the enabled channels are ticked at first, and a channel created here when it appears
	const known = useRef<Set<number> | null>(null);
	useEffect(() => {
		if (!data) return;
		const ids = data.channels.filter((c) => c.enabled).map((c) => c.id);
		const added = known.current ? ids.filter((id) => !known.current?.has(id)) : ids;
		known.current = new Set(data.channels.map((c) => c.id));
		if (added.length) setChannels((current) => [...new Set([...current, ...added])]);
	}, [data]);

	const existing = new Set(data?.rules.map((r) => r.type));
	// rules of a type that is already set up are not ticked again (they can be ticked by hand)
	const choose = (name: string) => {
		setPreset(name);
		setRules(PRESETS[name].filter((type) => !existing.has(type)));
	};
	const loaded = !!data;
	// biome-ignore lint/correctness/useExhaustiveDependencies: once, when the rules are known
	useEffect(() => {
		if (loaded) choose(preset || "recommended");
	}, [loaded]);
	const toggle = (list: any[], value: any) =>
		list.includes(value) ? list.filter((v) => v !== value) : [...list, value];

	const create = async () => {
		if (!data) return;
		setSaving(true);
		setError(null);
		try {
			for (const type of rules) {
				await createRule({
					name: t(`npmos.notifications.rule.${type}`),
					type,
					enabled: true,
					params: data.ruleTypes.find((r) => r.type === type)?.defaults ?? {},
					channelIds: channels,
					repeatMinutes: 0,
					notifyResolved: true,
				});
			}
			queryClient.invalidateQueries({ queryKey: ["npmos-notifications"] });
			showSuccess(t("npmos.notifications.setup.done", { count: rules.length }));
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
					<T id="npmos.notifications.setup" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<ol className={styles.steps}>
					{([1, 2, 3] as Step[]).map((n) => (
						<li
							key={n}
							className={cn(styles.step, step === n && styles.stepOn, step > n && styles.stepDone)}
						>
							<span className={styles.stepNumber}>{n}</span>
							<T id={`npmos.notifications.setup.step${n}`} />
						</li>
					))}
				</ol>
				{error && <Alert variant="danger">{error}</Alert>}

				{step === 1 && (
					<div>
						<p className={styles.lead}>
							<T id="npmos.notifications.setup.step1.text" />
						</p>
						{data?.channels.length ? (
							<div className={styles.options}>
								{data.channels.map((c) => (
									<label
										key={c.id}
										className={cn(styles.option, channels.includes(c.id) && styles.optionOn)}
									>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={channels.includes(c.id)}
											onChange={() => setChannels(toggle(channels, c.id))}
										/>
										{CHANNEL_ICON[c.type]}
										<span>
											<span className={styles.optionTitle}>{c.name}</span>
											<span className={styles.optionText}>
												<T id={`npmos.notifications.channel.${c.type}`} />
											</span>
										</span>
									</label>
								))}
							</div>
						) : null}
						<div className={styles.newChannel}>
							<span>
								<T
									id={
										data?.channels.length
											? "npmos.notifications.setup.another"
											: "npmos.notifications.setup.first"
									}
								/>
							</span>
							{(data?.channelTypes ?? ["email", "webhook", "telegram"]).map((type) => (
								<button
									key={type}
									type="button"
									className="btn btn-sm"
									onClick={() => showChannelModal(type)}
								>
									{CHANNEL_ICON[type]}
									<T id={`npmos.notifications.channel.${type}`} />
								</button>
							))}
						</div>
						<p className={styles.hint}>
							<T id="npmos.notifications.setup.offline" />
						</p>
					</div>
				)}

				{step === 2 && (
					<div>
						<p className={styles.lead}>
							<T id="npmos.notifications.setup.step2.text" />
						</p>
						<div className={styles.presets}>
							{Object.keys(PRESETS).map((name) => (
								<button
									key={name}
									type="button"
									className={cn(styles.preset, preset === name && styles.optionOn)}
									aria-pressed={preset === name}
									onClick={() => choose(name)}
								>
									<span className={styles.optionTitle}>
										<T id={`npmos.notifications.preset.${name}`} />
									</span>
									<span className={styles.optionText}>
										<T id={`npmos.notifications.preset.${name}.text`} />
									</span>
								</button>
							))}
						</div>
						<div className={styles.rules}>
							{RULES.map((type) => (
								<label key={type} className={styles.rule}>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={rules.includes(type)}
										onChange={() => {
											setPreset("");
											setRules(toggle(rules, type));
										}}
									/>
									<span>
										<span className={styles.optionTitle}>
											<T id={`npmos.notifications.rule.${type}`} />
											{existing.has(type) && (
												<span className={styles.exists}>
													<T id="npmos.notifications.setup.exists" />
												</span>
											)}
										</span>
										<span className={styles.optionText}>
											<T id={`npmos.notifications.setup.why.${type}`} />
										</span>
									</span>
								</label>
							))}
						</div>
					</div>
				)}

				{step === 3 && data && (
					<div>
						<p className={styles.lead}>
							<T id="npmos.notifications.setup.step3.text" />
						</p>
						<ul className={styles.summary}>
							{rules.map((type) => (
								<li key={type}>
									<T id={`npmos.notifications.rule.${type}`} />
								</li>
							))}
						</ul>
						<p className={styles.hint}>
							<T
								id="npmos.notifications.setup.to"
								data={{
									channels: data.channels
										.filter((c) => channels.includes(c.id))
										.map((c) => c.name)
										.join(", "),
								}}
							/>
						</p>
					</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				{step > 1 ? (
					<Button onClick={() => setStep((step - 1) as Step)} disabled={saving}>
						<T id="npmos.notifications.setup.back" />
					</Button>
				) : (
					<Button onClick={remove}>
						<T id="cancel" />
					</Button>
				)}
				{step < 3 ? (
					<Button
						className="ms-auto btn-primary"
						disabled={step === 1 ? !channels.length : !rules.length}
						onClick={() => setStep((step + 1) as Step)}
					>
						<T id="npmos.notifications.setup.next" />
					</Button>
				) : (
					<Button className="ms-auto btn-primary" isLoading={saving} disabled={saving} onClick={create}>
						<T id="npmos.notifications.setup.create" data={{ count: rules.length }} />
					</Button>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showSetupModal = () => EasyModal.show(SetupModal, {});
