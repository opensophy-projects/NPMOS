// Actions that hand out a private key: the key of a CA (encrypted with a password), the .p12 of a
// certificate whose key NPMOS keeps, a one-time link to it.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { createLink, downloadCert, exportCa, type OneTimeLink, saveFile } from "./api";
import { LinkBox, PasswordBox } from "./Delivery";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

type Action = "ca-key" | "p12" | "link";

interface Props extends InnerModalProps {
	action: Action;
	/** the CA (ca-key) or the certificate */
	objectId: number;
	name: string;
	publicUrl: string;
	compatible: boolean;
}

const MIN: Record<Action, number> = { "ca-key": 8, p12: 4, link: 0 };

const SecretModal = EasyModal.create(
	({ visible, remove, action, objectId: id, name, publicUrl, compatible: c }: Props) => {
		const [password, setPassword] = useState("");
		const [compatible, setCompatible] = useState(c);
		const [hours, setHours] = useState(24);
		const [busy, setBusy] = useState(false);
		const [error, setError] = useState<string | null>(null);
		const [link, setLink] = useState<{ link: OneTimeLink; password: string } | null>(null);

		const submit = async () => {
			setBusy(true);
			setError(null);
			try {
				if (action === "ca-key") {
					saveFile(await exportCa(id, "key", password));
					remove();
				} else if (action === "p12") {
					saveFile(await downloadCert(id, "p12", { password, compatible }));
					remove();
				} else {
					setLink(await createLink(id, { hours, password: password || undefined, compatible }));
				}
			} catch (err: any) {
				setError(err.message);
			} finally {
				setBusy(false);
			}
		};

		return (
			<Modal show={visible} onHide={remove}>
				<Modal.Header closeButton>
					<Modal.Title>
						<T id={`npmos.pki.secret.${action}`} />
						<span className="text-secondary ms-2">{name}</span>
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					{error && <Alert variant="danger">{error}</Alert>}
					{link ? (
						<>
							<PasswordBox password={link.password} />
							<LinkBox link={link.link} publicUrl={publicUrl} />
						</>
					) : (
						<>
							<p className="text-secondary">
								<T id={`npmos.pki.secret.${action}.hint`} />
							</p>
							{action === "link" && (
								<div className="mb-3">
									<label className="form-label" htmlFor="pki-secret-hours">
										<T id="npmos.pki.link.lifetime" />
									</label>
									<select
										id="pki-secret-hours"
										className="form-select"
										value={hours}
										onChange={(e) => setHours(Number(e.target.value))}
									>
										{[1, 24, 72, 168, 336].map((h) => (
											<option key={h} value={h}>
												{t("npmos.pki.link.hours", { hours: h })}
											</option>
										))}
									</select>
								</div>
							)}
							<div className="mb-3">
								<label className="form-label" htmlFor="pki-secret-password">
									<T
										id={
											action === "ca-key" ? "npmos.pki.secret.password" : "npmos.pki.p12.password"
										}
									/>
								</label>
								<input
									id="pki-secret-password"
									type={action === "link" ? "text" : "password"}
									className="form-control"
									autoComplete="new-password"
									placeholder={action === "link" ? t("npmos.pki.p12.password.generate") : undefined}
									value={password}
									onChange={(e) => setPassword(e.target.value)}
								/>
								{MIN[action] > 0 && (
									<div className="form-hint">
										<T id="npmos.pki.secret.min" data={{ count: MIN[action] }} />
									</div>
								)}
							</div>
							{action !== "ca-key" && (
								<label className="form-check mb-0">
									<input
										type="checkbox"
										className="form-check-input"
										checked={compatible}
										onChange={(e) => setCompatible(e.target.checked)}
									/>
									<span className="form-check-label">
										<T id="npmos.pki.p12.compatible" />
									</span>
								</label>
							)}
						</>
					)}
				</Modal.Body>
				<Modal.Footer>
					{link ? (
						<Button actionType="primary" onClick={remove}>
							<T id="npmos.pki.done" />
						</Button>
					) : (
						<>
							<Button onClick={remove} disabled={busy}>
								<T id="cancel" />
							</Button>
							<Button
								actionType="primary"
								isLoading={busy}
								disabled={password.length < MIN[action]}
								onClick={submit}
							>
								<T id={action === "link" ? "npmos.pki.link.create-do" : "npmos.pki.download"} />
							</Button>
						</>
					)}
				</Modal.Footer>
			</Modal>
		);
	},
);

export const showSecretModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(SecretModal, props);
