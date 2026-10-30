// Revocation of one or many certificates with a reason; the CRLs are generated again and nginx
// refuses the certificates within seconds.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { type PkiCert, REVOKE_REASONS, revokeCerts } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props extends InnerModalProps {
	certs: PkiCert[];
	onDone: () => void;
}

const RevokeModal = EasyModal.create(({ visible, remove, certs, onDone }: Props) => {
	const [reason, setReason] = useState<string>("unspecified");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			const { revoked } = await revokeCerts(
				certs.map((c) => c.id),
				reason,
			);
			showSuccess(t("npmos.pki.revoked-count", { count: revoked }));
			onDone();
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
					<T id="npmos.pki.revoke" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				<p>
					<T id="npmos.pki.revoke.text" data={{ count: certs.length }} />
				</p>
				<div className="small font-monospace text-secondary mb-3">
					{certs
						.slice(0, 20)
						.map((c) => c.commonName)
						.join(", ")}
					{certs.length > 20 && ` … +${certs.length - 20}`}
				</div>
				<label className="form-label" htmlFor="pki-revoke-reason">
					<T id="npmos.pki.revoke.reason" />
				</label>
				<select
					id="pki-revoke-reason"
					className="form-select"
					value={reason}
					onChange={(e) => setReason(e.target.value)}
				>
					{REVOKE_REASONS.map((r) => (
						<option key={r} value={r}>
							{t(`npmos.pki.reason.${r}`)}
						</option>
					))}
				</select>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" className="ms-auto btn-red" isLoading={busy} onClick={submit}>
					<T id="npmos.pki.revoke.do" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showRevokeModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(RevokeModal, props);
