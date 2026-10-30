// mTLS → a certificate in detail: who it is for, the hosts it opens, its fields, files and one-time
// links, notes; renewal, revocation and deletion. Opened from the mTLS page and from the menu of a
// host (Details).
import { IconDownload, IconExternalLink, IconTrash } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { useCan } from "../rbac/hooks";
import {
	deleteCertLink,
	deleteCerts,
	downloadCert,
	getCertLinks,
	type HostRef,
	type PkiCert,
	saveFile,
	updateCert,
	usePki,
} from "./api";
import { showIssueModal } from "./IssueModal";
import { showRevokeModal } from "./RevokeModal";
import { showSecretModal } from "./SecretModal";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export const EXPIRING_DAYS = 30;

export const STATUS_TONE: Record<string, string> = {
	active: "bg-green-lt",
	expiring: "bg-yellow-lt",
	expired: "bg-red-lt",
	revoked: "bg-red-lt",
	replaced: "bg-secondary-lt",
};

/** status of a certificate with "expiring" for the last 30 days */
export const certStatus = (c: PkiCert) =>
	c.status === "active" && c.daysLeft <= EXPIRING_DAYS ? "expiring" : c.status;

interface Props extends InnerModalProps {
	certId: number;
	/** opens the mTLS page filtered by a host */
	openHost?: (host: HostRef) => void;
}

function Row({ label, children }: { label: string; children: ReactNode }) {
	return (
		<div className="row py-1">
			<div className="col-sm-4 text-secondary">
				<T id={label} />
			</div>
			<div className="col-sm-8 text-break">{children}</div>
		</div>
	);
}

const CertModal = EasyModal.create(({ visible, remove, certId, openHost }: Props) => {
	const can = useCan();
	const { locale } = useLocaleState();
	const queryClient = useQueryClient();
	const pki = usePki();
	const c = pki.data?.certificates.find((x) => x.id === certId);
	const links = useQuery({
		queryKey: ["npmos-pki-links", certId],
		queryFn: () => getCertLinks(certId),
		enabled: !!c?.hasKey,
	});
	const [notes, setNotes] = useState("");
	const [busy, setBusy] = useState(false);
	useEffect(() => setNotes(c?.notes ?? ""), [c?.notes]);

	const refresh = () => {
		queryClient.invalidateQueries({ queryKey: ["npmos-pki"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-pki-links", certId] });
		queryClient.invalidateQueries({ queryKey: ["npmos-mtls-hosts"] });
	};
	const run = async (action: () => Promise<unknown>, message?: string) => {
		try {
			await action();
			if (message) showSuccess(message);
		} catch (err: any) {
			showError(err.message);
		}
		refresh();
	};

	if (!pki.data) return null;
	if (!c) {
		return (
			<Modal show={visible} onHide={remove}>
				<Modal.Body>
					<Alert variant="warning" className="mb-0">
						<T id="npmos.mtls.cert.missing" />
					</Alert>
				</Modal.Body>
			</Modal>
		);
	}

	const data = pki.data;
	const ca = data.cas.find((x) => x.id === c.caId);
	const root = ca?.parentId ? data.cas.find((x) => x.id === ca.parentId) : undefined;
	const status = certStatus(c);
	const valid = !c.revokedOn && c.status !== "expired";
	const keyActions = c.hasKey && can("pki", "export_key") && !c.revokedOn;
	const secret = (action: "p12" | "link") =>
		showSecretModal({
			action,
			objectId: c.id,
			name: c.commonName,
			publicUrl: data.settings.publicUrl,
			compatible: data.settings.p12Compatible,
		});
	const remove_ = () => {
		if (!window.confirm(t(valid ? "npmos.mtls.delete.confirm-valid" : "npmos.mtls.delete.confirm"))) return;
		setBusy(true);
		deleteCerts([c.id])
			.then(() => {
				showSuccess(t("npmos.mtls.deleted", { count: 1 }));
				refresh();
				remove();
			})
			.catch((err) => {
				showError(err.message);
				setBusy(false);
			});
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title className="d-flex align-items-center gap-2 text-break">
					{c.commonName}
					<span className={cn("badge", STATUS_TONE[status])}>
						<T id={`npmos.pki.status.${status}`} />
					</span>
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{c.revokedOn && (
					<Alert variant="danger">
						<T
							id="npmos.mtls.cert.revoked"
							data={{
								time: formatDateTime(c.revokedOn, locale),
								reason: t(`npmos.pki.reason.${c.revokeReason ?? "unspecified"}`),
							}}
						/>
					</Alert>
				)}
				<h4 className="mb-2">
					<T id="npmos.mtls.cert.access" />
				</h4>
				{c.access.length ? (
					<div className="d-flex flex-wrap gap-2 mb-3">
						{c.access.map((h) => (
							<button
								type="button"
								key={`${h.hostType}-${h.hostId}`}
								className="btn btn-sm"
								onClick={() => {
									remove();
									openHost?.(h);
								}}
							>
								{h.name}
								<IconExternalLink size={14} className="ms-1" />
							</button>
						))}
					</div>
				) : (
					<p className="text-secondary">
						<T id="npmos.mtls.cert.no-access" />
					</p>
				)}

				<h4 className="mb-2 mt-3">
					<T id="npmos.mtls.cert.details" />
				</h4>
				<Row label="npmos.pki.subject.commonName">{c.commonName}</Row>
				{c.subject.email && <Row label="npmos.pki.subject.email">{c.subject.email}</Row>}
				{c.subject.organization && <Row label="npmos.pki.subject.organization">{c.subject.organization}</Row>}
				{c.subject.organizationalUnit && (
					<Row label="npmos.pki.subject.organizationalUnit">{c.subject.organizationalUnit}</Row>
				)}
				<Row label="npmos.mtls.cert.valid">
					{formatDateTime(c.notBefore, locale)} — {formatDateTime(c.notAfter, locale)}
					<div className="text-secondary small">
						{c.daysLeft >= 0
							? t("npmos.pki.days-left", { days: c.daysLeft })
							: t("npmos.pki.expired-ago", { days: -c.daysLeft })}
					</div>
				</Row>
				<Row label="npmos.mtls.cert.issuer">
					{ca?.name ?? `#${c.caId}`}
					{root && <span className="text-secondary"> ← {root.name}</span>}
				</Row>
				<Row label="npmos.mtls.cert.serial">
					<span className="font-monospace small">{c.serial}</span>
				</Row>
				<Row label="npmos.mtls.cert.fingerprint">
					<span className="font-monospace small">{c.fingerprint}</span>
				</Row>
				<Row label="npmos.mtls.cert.key">
					{c.keyType} · <T id={c.hasKey ? "npmos.mtls.cert.key.kept" : "npmos.mtls.cert.key.not-kept"} />
				</Row>
				<Row label="npmos.mtls.cert.created">{formatDateTime(c.createdOn, locale)}</Row>

				<div className="mt-3">
					<label className="form-label" htmlFor="mtls-cert-notes">
						<T id="npmos.mtls.notes" />
					</label>
					<div className="input-group">
						<input
							id="mtls-cert-notes"
							className="form-control"
							value={notes}
							maxLength={500}
							disabled={!can("pki", "issue")}
							placeholder={t("npmos.mtls.notes.placeholder")}
							onChange={(e) => setNotes(e.target.value)}
						/>
						{can("pki", "issue") && (
							<button
								type="button"
								className="btn"
								disabled={notes === c.notes}
								onClick={() => run(() => updateCert(c.id, { notes }), t("npmos.mtls.notes.saved"))}
							>
								<T id="save" />
							</button>
						)}
					</div>
				</div>

				<h4 className="mb-2 mt-4">
					<T id="npmos.mtls.cert.files" />
				</h4>
				<div className="d-flex flex-wrap gap-2">
					{keyActions && (
						<button type="button" className="btn btn-primary btn-sm" onClick={() => secret("p12")}>
							<IconDownload size={16} className="me-1" />
							<T id="npmos.pki.download.p12" />
						</button>
					)}
					{keyActions && (
						<button type="button" className="btn btn-sm" onClick={() => secret("link")}>
							<T id="npmos.pki.link.create" />
						</button>
					)}
					<button
						type="button"
						className="btn btn-sm"
						onClick={() => run(async () => saveFile(await downloadCert(c.id, "cert")))}
					>
						<T id="npmos.pki.download.cert" />
					</button>
					<button
						type="button"
						className="btn btn-sm"
						onClick={() => run(async () => saveFile(await downloadCert(c.id, "chain")))}
					>
						<T id="npmos.pki.download.fullchain" />
					</button>
				</div>
				{!c.hasKey && !c.revokedOn && (
					<div className="form-hint mt-2">
						<T id="npmos.mtls.cert.no-key" />
					</div>
				)}
				{(links.data ?? []).length > 0 && (
					<ul className="list-unstyled small mt-3 mb-0">
						{links.data?.map((l) => (
							<li key={l.id} className="d-flex align-items-center gap-2 py-1">
								<span className={cn("badge", l.active ? "bg-green-lt" : "bg-secondary-lt")}>
									<T
										id={
											l.usedOn
												? "npmos.mtls.link.used"
												: l.active
													? "npmos.mtls.link.active"
													: "npmos.mtls.link.expired"
										}
									/>
								</span>
								<span className="text-secondary">
									<T
										id="npmos.mtls.link.times"
										data={{
											created: formatDateTime(l.createdOn, locale),
											until: formatDateTime(l.usedOn ?? l.expiresOn, locale),
										}}
									/>
								</span>
								{l.active && can("pki", "export_key") && (
									<button
										type="button"
										className="btn btn-sm btn-ghost-danger ms-auto"
										aria-label={t("npmos.mtls.link.delete")}
										title={t("npmos.mtls.link.delete")}
										onClick={() => run(() => deleteCertLink(l.id))}
									>
										<IconTrash size={14} />
									</button>
								)}
							</li>
						))}
					</ul>
				)}
			</Modal.Body>
			<Modal.Footer className="justify-content-between">
				<div className="d-flex gap-2">
					{can("pki", "revoke") && (
						<Button onClick={remove_} disabled={busy} className="btn-ghost-danger">
							<T id="npmos.mtls.delete" />
						</Button>
					)}
					{can("pki", "revoke") && !c.revokedOn && (
						<Button
							disabled={busy}
							className="btn-outline-danger"
							onClick={() => showRevokeModal({ certs: [c], onDone: refresh })}
						>
							<T id="npmos.pki.revoke" />
						</Button>
					)}
				</div>
				<div className="d-flex gap-2">
					{can("pki", "issue") && !c.revokedOn && ca?.hasKey && (
						<Button disabled={busy} onClick={() => showIssueModal({ data, renew: c, onDone: refresh })}>
							<T id="npmos.pki.renew" />
						</Button>
					)}
					<Button actionType="primary" onClick={remove}>
						<T id="action.close" />
					</Button>
				</div>
			</Modal.Footer>
		</Modal>
	);
});

export const showCertModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(CertModal, props);
