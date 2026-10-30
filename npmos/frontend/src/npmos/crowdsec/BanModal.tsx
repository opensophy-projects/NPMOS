// Ban (or captcha) by hand: one address from an event or an alert, or a list of IPs and CIDRs.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { ban, DECISION_TYPES, DURATIONS } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props extends InnerModalProps {
	values?: string[];
	reason?: string;
	/** the address is banned already: the new ban replaces the decisions it has */
	extend?: boolean;
	onDone?: () => void;
}

/** addresses separated by lines, commas or spaces */
export const splitValues = (text: string) => [...new Set(text.split(/[\s,;]+/).filter(Boolean))];

const BanModal = EasyModal.create(({ visible, remove, values = [], reason = "", extend = false, onDone }: Props) => {
	const [text, setText] = useState(values.join("\n"));
	const [type, setType] = useState<string>("ban");
	const [duration, setDuration] = useState(extend ? "24h" : "4h");
	const [why, setWhy] = useState(reason);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const list = splitValues(text);

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			// one decision per address: a ban of an address that has one replaces it (up to 100 addresses)
			const { count } = await ban({ values: list, type, duration, reason: why, replace: list.length <= 100 });
			showSuccess(t("npmos.crowdsec.ban.done", { count }));
			onDone?.();
			remove();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={extend ? "npmos.crowdsec.ban.extend" : "npmos.crowdsec.ban.title"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				<div className="mb-3">
					<label className="form-label" htmlFor="cs-ban-values">
						<T id="npmos.crowdsec.ban.values" />
					</label>
					<textarea
						id="cs-ban-values"
						className="form-control font-monospace"
						rows={Math.min(8, Math.max(2, list.length + 1))}
						placeholder="203.0.113.7&#10;198.51.100.0/24"
						value={text}
						onChange={(e) => setText(e.target.value)}
					/>
					<div className="form-hint">
						<T id="npmos.crowdsec.ban.values.hint" /> <T id="npmos.crowdsec.ban.replace.hint" />
					</div>
				</div>
				<div className="row">
					<div className="col-6 mb-3">
						<label className="form-label" htmlFor="cs-ban-type">
							<T id="npmos.crowdsec.decision" />
						</label>
						<select
							id="cs-ban-type"
							className="form-select"
							value={type}
							onChange={(e) => setType(e.target.value)}
						>
							{DECISION_TYPES.map((d) => (
								<option key={d} value={d}>
									{t(`npmos.crowdsec.decision.${d}`)}
								</option>
							))}
						</select>
					</div>
					<div className="col-6 mb-3">
						<label className="form-label" htmlFor="cs-ban-duration">
							<T id="npmos.crowdsec.duration" />
						</label>
						<select
							id="cs-ban-duration"
							className="form-select"
							value={duration}
							onChange={(e) => setDuration(e.target.value)}
						>
							{DURATIONS.map((d) => (
								<option key={d} value={d}>
									{t(`npmos.crowdsec.duration.${d}`)}
								</option>
							))}
						</select>
					</div>
				</div>
				<label className="form-label" htmlFor="cs-ban-reason">
					<T id="npmos.crowdsec.ban.reason" />
				</label>
				<input
					id="cs-ban-reason"
					className="form-control"
					maxLength={200}
					value={why}
					onChange={(e) => setWhy(e.target.value)}
				/>
				{type === "captcha" && (
					<div className="form-hint">
						<T id="npmos.crowdsec.captcha.needs-provider" />
					</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button
					actionType="primary"
					className="ms-auto btn-red"
					isLoading={busy}
					disabled={!list.length}
					onClick={submit}
				>
					<T id="npmos.crowdsec.ban.do" data={{ count: list.length }} />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showBanModal = (props: Omit<Props, keyof InnerModalProps> = {}) => EasyModal.show(BanModal, props);
