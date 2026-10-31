// mTLS → an access certificate: a client certificate for a protected host in a few fields (name,
// e-mail, lifetime). It is issued by the trust domain of the host and handed out as .p12 with its
// password, PEM files or a one-time link (Delivery).
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { useCan } from "../rbac/hooks";
import { type HostRef, hostKey, type IssueResult, issueCert, issuersFor, type PkiOverview } from "./api";
import { Delivery } from "./Delivery";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props extends InnerModalProps {
	data: PkiOverview;
	/** the host the certificate is for (the menu of a host) */
	host?: HostRef;
	onDone: () => void;
}

const AccessModal = EasyModal.create(({ visible, remove, data, host, onDone }: Props) => {
	const can = useCan();
	const hosts = useMemo(
		() =>
			data.protected.filter((h) => issuersFor(h, data.cas).length > 0 || (host && hostKey(h) === hostKey(host))),
		[data, host],
	);
	const [target, setTarget] = useState(host ? hostKey(host) : hosts[0] ? hostKey(hosts[0]) : "");
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [days, setDays] = useState(data.settings.clientDays);
	const [notes, setNotes] = useState("");
	// empty: NPMOS generates the password of the .p12 and shows it once
	const [password, setPassword] = useState("");
	const keepAllowed = can("pki", "export_key");
	const [keep, setKeep] = useState(keepAllowed);
	const [link, setLink] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<IssueResult | null>(null);

	const chosen = data.protected.find((h) => hostKey(h) === target);
	const issuers = chosen ? issuersFor(chosen, data.cas) : [];
	// the issuing CA must be accepted by the host: its trust domain, or a domain of its root
	const issuer = issuers[0];
	// a root the host trusts: a person can get a CA of their own under it (deleting it cuts them off)
	const root = chosen
		? data.cas.find((ca) => chosen.caIds.includes(ca.id) && ca.kind === "root" && ca.hasKey)
		: undefined;
	const [ownCa, setOwnCa] = useState(false);

	const submit = async () => {
		if (!issuer) return;
		setBusy(true);
		setError(null);
		try {
			const issued = await issueCert({
				...(ownCa && root ? { caId: root.id, ownCa: true } : { caId: issuer.id }),
				profile: "client",
				subject: { commonName: name.trim(), ...(email.trim() ? { email: email.trim() } : {}) },
				...(email.trim() ? { sans: { dns: [], ip: [], email: [email.trim()] } } : {}),
				days,
				notes: notes.trim(),
				storeKey: keep && keepAllowed,
				password: password || undefined,
				linkHours: link ? 24 : undefined,
			});
			setResult(issued);
			onDone();
		} catch (err: any) {
			setError(err.message);
		}
		setBusy(false);
	};

	return (
		<Modal show={visible} onHide={remove} size={result ? "lg" : undefined}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.mtls.access.title" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				{result ? (
					<>
						<Alert variant="success">
							<T
								id="npmos.mtls.access.issued"
								data={{ name: result.certificate.commonName, host: chosen?.name ?? "" }}
							/>
						</Alert>
						<Delivery result={result} publicUrl={data.settings.publicUrl} />
					</>
				) : hosts.length === 0 ? (
					<Alert variant="info" className="mb-0">
						<T id="npmos.mtls.access.no-hosts" />
					</Alert>
				) : (
					<>
						<div className="mb-3">
							<label className="form-label required" htmlFor="mtls-access-host">
								<T id="npmos.mtls.host" />
							</label>
							<select
								id="mtls-access-host"
								className="form-select"
								value={target}
								disabled={!!host}
								onChange={(e) => setTarget(e.target.value)}
							>
								{hosts.map((h) => (
									<option key={hostKey(h)} value={hostKey(h)}>
										{h.name}
									</option>
								))}
							</select>
							{chosen && !issuer && (
								<div className="text-danger small mt-1">
									<T id="npmos.mtls.access.no-issuer" />
								</div>
							)}
							{chosen && chosen.rules > 0 && (
								<div className="form-hint">
									<T id="npmos.mtls.access.rules" />
								</div>
							)}
						</div>
						<div className="mb-3">
							<label className="form-label required" htmlFor="mtls-access-name">
								<T id="npmos.mtls.access.name" />
							</label>
							<input
								id="mtls-access-name"
								className="form-control"
								value={name}
								maxLength={64}
								placeholder={t("npmos.mtls.access.name.placeholder")}
								onChange={(e) => setName(e.target.value)}
							/>
							<div className="form-hint">
								<T id="npmos.mtls.access.name.hint" />
							</div>
						</div>
						<div className="row">
							<div className="col-sm-8 mb-3">
								<label className="form-label" htmlFor="mtls-access-email">
									<T id="npmos.mtls.access.email" />
								</label>
								<input
									id="mtls-access-email"
									type="email"
									className="form-control"
									value={email}
									onChange={(e) => setEmail(e.target.value)}
								/>
							</div>
							<div className="col-sm-4 mb-3">
								<label className="form-label" htmlFor="mtls-access-days">
									<T id="npmos.mtls.access.days" />
								</label>
								<input
									id="mtls-access-days"
									type="number"
									min={1}
									max={3650}
									className="form-control"
									value={days}
									onChange={(e) => setDays(Number(e.target.value))}
								/>
							</div>
						</div>
						<div className="mb-3">
							<label className="form-label" htmlFor="mtls-access-notes">
								<T id="npmos.mtls.notes" />
							</label>
							<input
								id="mtls-access-notes"
								className="form-control"
								value={notes}
								maxLength={500}
								placeholder={t("npmos.mtls.notes.placeholder")}
								onChange={(e) => setNotes(e.target.value)}
							/>
						</div>
						<div className="mb-3">
							<label className="form-label" htmlFor="mtls-access-password">
								<T id="npmos.pki.p12.password" />
							</label>
							<input
								id="mtls-access-password"
								className="form-control"
								autoComplete="new-password"
								placeholder={t("npmos.pki.p12.password.generate")}
								value={password}
								onChange={(e) => setPassword(e.target.value)}
							/>
						</div>
						{root && can("pki", "manage") && (
							<label className="form-check">
								<input
									type="checkbox"
									className="form-check-input"
									checked={ownCa}
									onChange={(e) => setOwnCa(e.target.checked)}
								/>
								<span className="form-check-label">
									<T id="npmos.mtls.access.own-ca" />
								</span>
								<span className="form-hint d-block">
									<T id="npmos.mtls.access.own-ca.hint" data={{ root: root.name }} />
								</span>
							</label>
						)}
						<label className="form-check">
							<input
								type="checkbox"
								className="form-check-input"
								checked={keep && keepAllowed}
								disabled={!keepAllowed}
								onChange={(e) => setKeep(e.target.checked)}
							/>
							<span className="form-check-label">
								<T id="npmos.mtls.access.keep" />
							</span>
							<span className="form-hint d-block">
								<T id="npmos.mtls.access.keep.hint" />
							</span>
						</label>
						<label className="form-check mb-0">
							<input
								type="checkbox"
								className="form-check-input"
								checked={link}
								onChange={(e) => setLink(e.target.checked)}
							/>
							<span className="form-check-label">
								<T id="npmos.mtls.access.link" />
							</span>
						</label>
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				{result ? (
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
							disabled={
								!issuer || !name.trim() || days < 1 || (password.length > 0 && password.length < 4)
							}
							onClick={submit}
						>
							<T id="npmos.mtls.access.submit" />
						</Button>
					</>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showAccessModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(AccessModal, props);
