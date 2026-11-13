// Trial mode of a host (Agents → open-appsec → Learning): start a trial of blocking for some hours (nothing is
// blocked, the events are judged as blocking would), then its report with the switch to blocking.
import { useQuery } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { SimulationNote } from "../policy/Review";
import { dateTime } from "../ui/time";
import { finishWafTrial, getWafTrial, type LearningHost, startWafTrial, TRIAL_HOURS } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props extends InnerModalProps {
	host: LearningHost;
	manage: boolean;
	onDone: () => void;
}

const StartTrialModal = EasyModal.create(({ host, onDone, visible, remove }: Props) => {
	const [hours, setHours] = useState<number>(24);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			await startWafTrial(host.id, hours);
			showSuccess(t("nginxions.learning.trial.started", { name: host.name }));
			onDone();
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setBusy(false);
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="nginxions.learning.trial.start.title" data={{ name: host.name }} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
					{error}
				</Alert>
				<p className="text-secondary">
					<T id="nginxions.learning.trial.start.text" />
				</p>
				<label className="form-label" htmlFor="trial-hours">
					<T id="nginxions.learning.trial.hours" />
				</label>
				<select
					id="trial-hours"
					className="form-select"
					value={hours}
					onChange={(e) => setHours(Number(e.target.value))}
				>
					{TRIAL_HOURS.map((h) => (
						<option key={h} value={h}>
							{t(`nginxions.learning.trial.hours.${h}`)}
						</option>
					))}
				</select>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" className="ms-auto" isLoading={busy} disabled={busy} onClick={submit}>
					<T id="nginxions.learning.trial.start" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

const TrialReportModal = EasyModal.create(({ host, manage, onDone, visible, remove }: Props) => {
	const { data, isLoading, error } = useQuery({
		queryKey: ["nginxions-waf-trial", host.id],
		queryFn: () => getWafTrial(host.id),
	});
	const [failure, setFailure] = useState<string | null>(null);
	const [busy, setBusy] = useState<"enable" | "close" | null>(null);
	const trial = data?.trial ?? null;
	const running = trial?.state === "running";

	const finish = async (enable: boolean) => {
		setBusy(enable ? "enable" : "close");
		setFailure(null);
		try {
			await finishWafTrial(host.id, enable);
			showSuccess(
				t(enable ? "nginxions.learning.prevent.done" : "nginxions.learning.trial.closed", { name: host.name }),
			);
			onDone();
			remove();
		} catch (err: any) {
			setFailure(err.message);
		}
		setBusy(null);
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="nginxions.learning.trial.report.title" data={{ name: host.name }} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={!!(failure || error)} onClose={() => setFailure(null)} dismissible>
					{failure || (error as Error)?.message}
				</Alert>
				{isLoading ? (
					<LoadingPage noLogo />
				) : !trial ? (
					<p className="text-secondary mb-0">
						<T id="nginxions.learning.trial.none" />
					</p>
				) : (
					<>
						<p className="text-secondary">
							<T
								id={
									running
										? "nginxions.learning.trial.running.text"
										: "nginxions.learning.trial.finished.text"
								}
								data={{ from: dateTime(trial.startedOn), to: dateTime(trial.endsOn) }}
							/>
						</p>
						<SimulationNote simulation={data?.report} />
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={!!busy}>
					<T id="nginxions.common.close" />
				</Button>
				{trial && manage && (
					<>
						<Button
							className="ms-auto"
							isLoading={busy === "close"}
							disabled={!!busy}
							onClick={() => finish(false)}
						>
							<T id={running ? "nginxions.learning.trial.cancel" : "nginxions.learning.trial.dismiss"} />
						</Button>
						<Button
							actionType="primary"
							isLoading={busy === "enable"}
							disabled={!!busy}
							onClick={() => finish(true)}
						>
							<T id="nginxions.learning.prevent" />
						</Button>
					</>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showStartTrialModal = (props: Omit<Props, keyof InnerModalProps | "manage">) => {
	EasyModal.show(StartTrialModal, { ...props, manage: true });
};

export const showTrialReportModal = (props: Omit<Props, keyof InnerModalProps>) => {
	EasyModal.show(TrialReportModal, props);
};
