// Label of a group of the queue (or of a tuning suggestion): legitimate, attack or skip; what it applies to; what
// happens at once besides learning (an exception for the host, a ban of the sources in CrowdSec).
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { useCan } from "../rbac/hooks";
import {
	BAN_DURATIONS,
	createLabel,
	type Decision,
	getGroup,
	type QueueGroup,
	type Scope,
	type ScopeType,
	type Suggestion,
	TTL_DAYS,
} from "./api";
import styles from "./Learning.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const DECISIONS: Decision[] = ["benign", "malicious", "dismiss"];
const ONE_VALUE: ScopeType[] = ["parameterValue", "parameterName", "url"];

interface Props extends InnerModalProps {
	group?: QueueGroup;
	suggestion?: Suggestion;
	decision: Decision;
	onDone?: () => void;
}

const LabelModal = EasyModal.create(({ visible, remove, group, suggestion, decision: initial, onDone }: Props) => {
	const can = useCan();
	const [decision, setDecision] = useState<Decision>(initial);
	const details = useQuery({
		queryKey: ["npmos-learning-group", group?.key],
		queryFn: () => getGroup(group?.key ?? ""),
		enabled: !!group,
	});
	const sources = details.data?.sourceList ?? [];
	// one value per type (value, name, URL) and any number of sources
	const values: Record<string, string> = {
		parameterValue: group?.sample ?? "",
		parameterName: group?.parameter ?? "",
		url: group?.uri ?? "",
	};
	const [types, setTypes] = useState<ScopeType[]>(() => (group?.scopes ?? []).map((s) => s.type));
	const [ips, setIps] = useState<string[]>([]);
	// at once: proposed for a legitimate request (it is blocked now), left to the administrator for an attack
	const [exception, setException] = useState(initial === "benign");
	const [ttl, setTtl] = useState(14);
	const [ban, setBan] = useState(false);
	const [banDuration, setBanDuration] = useState("24h");
	const [note, setNote] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	// an attack is about who sent it: its sources are chosen at first (a legitimate request, about its parameter)
	// biome-ignore lint/correctness/useExhaustiveDependencies: when the decision or the list of sources changes
	useEffect(() => {
		if (decision === "malicious" && sources.length && !ips.length) setIps(sources.map((s) => s.ip));
		if (decision === "benign") setBan(false);
	}, [decision, sources.length]);

	const scopes: Scope[] = [
		...ONE_VALUE.filter((type) => types.includes(type) && values[type]).map((type) => ({
			type,
			value: values[type],
		})),
		...ips.map((ip) => ({ type: "source" as ScopeType, value: ip })),
	];
	const canBan = can("crowdsec", "decide");

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			if (suggestion) {
				await createLabel({ suggestion, decision });
			} else if (group) {
				await createLabel({
					key: group.key,
					eventId: group.eventId ?? undefined,
					decision,
					scopes: decision === "dismiss" ? [] : scopes,
					exception: decision !== "dismiss" && exception,
					ttlDays: ttl,
					ban: decision === "malicious" && ban,
					banDuration,
					note,
				});
			}
			showSuccess(t(`npmos.learning.done.${decision}`));
			onDone?.();
			remove();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	const toggleType = (type: ScopeType) =>
		setTypes((list) => (list.includes(type) ? list.filter((x) => x !== type) : [...list, type]));
	const toggleIp = (ip: string) =>
		setIps((list) => (list.includes(ip) ? list.filter((x) => x !== ip) : [...list, ip]));
	const empty = decision !== "dismiss" && !suggestion && !scopes.length;

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.learning.label.title" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				<dl className={styles.facts}>
					<dt>
						<T id="npmos.learning.host" />
					</dt>
					<dd>{group?.hostName ?? suggestion?.hostName}</dd>
					{group && (
						<>
							<dt>
								<T id="npmos.learning.url" />
							</dt>
							<dd className={styles.mono}>{group.uri || "/"}</dd>
							{group.parameter && (
								<>
									<dt>
										<T id="npmos.learning.parameter" />
									</dt>
									<dd className={styles.mono}>{group.parameter}</dd>
								</>
							)}
							{group.sample && (
								<>
									<dt>
										<T id="npmos.learning.value" />
									</dt>
									<dd className={styles.mono}>{group.sample}</dd>
								</>
							)}
							{group.indicators && (
								<>
									<dt>
										<T id="npmos.learning.indicators" />
									</dt>
									<dd className={styles.mono}>{group.indicators}</dd>
								</>
							)}
							<dt>
								<T id="npmos.learning.events" />
							</dt>
							<dd>
								{group.events.toLocaleString(intl.locale)} ·{" "}
								<T
									id="npmos.learning.events.value"
									data={{ sources: group.sources, blocked: group.blocked }}
								/>
								{group.incidentType ? ` · ${group.incidentType}` : ""}
							</dd>
						</>
					)}
					{suggestion && (
						<>
							<dt>
								<T id={`npmos.learning.scope.${suggestion.type}`} />
							</dt>
							<dd className={styles.mono}>{suggestion.title}</dd>
							{suggestion.attackTypes.length > 0 && (
								<>
									<dt>
										<T id="npmos.learning.attacks" />
									</dt>
									<dd>{suggestion.attackTypes.join(", ")}</dd>
								</>
							)}
						</>
					)}
				</dl>

				<div className={styles.decisions} role="radiogroup" aria-label={t("npmos.learning.decision")}>
					{DECISIONS.map((d) => (
						<button
							key={d}
							type="button"
							role="radio"
							aria-checked={decision === d}
							className={cn(styles.decision, decision === d && styles.decisionOn)}
							onClick={() => {
								setDecision(d);
								setException(d === "benign");
							}}
						>
							<span className={styles.decisionTitle}>
								<T id={`npmos.learning.decision.${d}`} />
							</span>
							<span className={styles.decisionText}>
								<T id={`npmos.learning.decision.${d}.text`} />
							</span>
						</button>
					))}
				</div>

				{group && decision !== "dismiss" && (
					<div className={styles.block}>
						<div className={styles.blockTitle}>
							<T id="npmos.learning.scopes" />
						</div>
						<div className={styles.blockText}>
							<T id="npmos.learning.scopes.text" />
						</div>
						{ONE_VALUE.filter((type) => values[type]).map((type) => (
							<label key={type} className={styles.check}>
								<input
									type="checkbox"
									className="form-check-input m-0"
									checked={types.includes(type)}
									onChange={() => toggleType(type)}
								/>
								<span>
									<T id={`npmos.learning.scope.${type}`} />
									{": "}
									<span className={styles.checkValue}>{values[type]}</span>
								</span>
							</label>
						))}
						<label className={styles.check}>
							<input
								type="checkbox"
								className="form-check-input m-0"
								checked={!!sources.length && ips.length === sources.length}
								disabled={!sources.length}
								onChange={() => setIps(ips.length === sources.length ? [] : sources.map((s) => s.ip))}
							/>
							<span>
								<T id="npmos.learning.scope.source" />
								<span className={styles.muted}>
									{" "}
									— <T id={`npmos.learning.scope.source.${decision}`} />
								</span>
							</span>
						</label>
						{sources.length > 0 && (
							<div className={styles.sources}>
								{sources.map((s) => (
									<label key={s.ip} className={styles.check}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={ips.includes(s.ip)}
											onChange={() => toggleIp(s.ip)}
										/>
										<span className={styles.checkValue}>{s.ip}</span>
										<span className={styles.muted}>{s.events}</span>
									</label>
								))}
							</div>
						)}
					</div>
				)}

				{decision !== "dismiss" && (
					<div className={styles.block}>
						<div className={styles.blockTitle}>
							<T id="npmos.learning.effects" />
						</div>
						<div className={styles.blockText}>
							<T
								id={suggestion ? "npmos.learning.effects.tuning" : `npmos.learning.effects.${decision}`}
							/>
						</div>
						{group && (
							<>
								<label className={styles.check}>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={exception}
										onChange={() => setException(!exception)}
									/>
									<span>
										<T id={`npmos.learning.exception.${decision}`} />
										<span className={styles.muted}>
											{" "}
											— <T id={`npmos.learning.exception.${decision}.text`} />
										</span>
									</span>
								</label>
								{exception && decision === "benign" && (
									<div className={styles.inline}>
										<T id="npmos.learning.ttl" />
										<select
											className="form-select form-select-sm"
											value={ttl}
											onChange={(e) => setTtl(Number(e.target.value))}
										>
											{TTL_DAYS.map((d) => (
												<option key={d} value={d}>
													{d
														? t("npmos.learning.ttl.days", { days: d })
														: t("npmos.learning.ttl.none")}
												</option>
											))}
										</select>
									</div>
								)}
								{decision === "malicious" && canBan && (
									<>
										<label className={styles.check}>
											<input
												type="checkbox"
												className="form-check-input m-0"
												checked={ban}
												disabled={!ips.length}
												onChange={() => setBan(!ban)}
											/>
											<span>
												<T id="npmos.learning.ban" data={{ count: ips.length }} />
											</span>
										</label>
										{ban && (
											<div className={styles.inline}>
												<T id="npmos.learning.ban.duration" />
												<select
													className="form-select form-select-sm"
													value={banDuration}
													onChange={(e) => setBanDuration(e.target.value)}
												>
													{BAN_DURATIONS.map((d) => (
														<option key={d} value={d}>
															{t(`npmos.learning.duration.${d}`)}
														</option>
													))}
												</select>
											</div>
										)}
									</>
								)}
							</>
						)}
					</div>
				)}

				{group && (
					<div className={styles.block}>
						<label className="form-label" htmlFor="npmos-learning-note">
							<T id="npmos.learning.note" />
						</label>
						<textarea
							id="npmos-learning-note"
							className="form-control"
							rows={2}
							maxLength={500}
							value={note}
							onChange={(e) => setNote(e.target.value)}
						/>
					</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button className="ms-auto btn-primary" isLoading={busy} disabled={busy || empty} onClick={submit}>
					<T id={`npmos.learning.submit.${decision}`} />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showLabelModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(LabelModal, props);
