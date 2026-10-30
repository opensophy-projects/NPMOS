// mTLS → the access certificates of one host (the menu of a host in Hosts): a host may have many,
// so one is chosen first — by name, note or email, with the valid ones shown first — and then
// downloaded, opened in detail, renewed, revoked or deleted. A new one is issued from here too.
import { IconDots, IconDownload, IconKey, IconPlus } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useMemo, useState } from "react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { showConfirmModal } from "../modals/ConfirmModal";
import { useCan } from "../rbac/hooks";
import { Dropdown, type DropdownItem } from "../ui/Dropdown";
import { showAccessModal } from "./AccessModal";
import { deleteCerts, downloadCert, type HostRef, hostKey, issuersFor, type PkiCert, saveFile, usePki } from "./api";
import { SearchField } from "../ui/SearchField";
import { certStatus, STATUS_TONE, showCertModal } from "./CertModal";
import { showIssueModal } from "./IssueModal";
import { showRevokeModal } from "./RevokeModal";
import { showSecretModal } from "./SecretModal";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

/** still opens the host */
const valid = (c: PkiCert) => !c.revokedOn && c.status !== "expired" && c.status !== "replaced";

type Show = "valid" | "all";

interface Props extends InnerModalProps {
	host: HostRef;
	/** the mTLS page filtered by a host */
	openHost?: (host: HostRef) => void;
}

const HostCertsModal = EasyModal.create(({ visible, remove, host, openHost }: Props) => {
	const can = useCan();
	const { locale } = useLocaleState();
	const queryClient = useQueryClient();
	const pki = usePki();
	const [query, setQuery] = useState("");
	const [show, setShow] = useState<Show>("valid");
	const refresh = () => {
		queryClient.invalidateQueries({ queryKey: ["npmos-pki"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-mtls-hosts"] });
	};

	const all = useMemo(
		() =>
			(pki.data?.certificates ?? []).filter(
				(c) => c.profile === "client" && c.access.some((a) => hostKey(a) === hostKey(host)),
			),
		[pki.data, host],
	);
	const rows = useMemo(() => {
		const q = query.trim().toLowerCase();
		return all
			.filter((c) => show === "all" || valid(c))
			.filter(
				(c) =>
					!q ||
					[c.commonName, c.subject.email, c.notes, c.serial]
						.filter(Boolean)
						.some((v) => String(v).toLowerCase().includes(q)),
			)
			.sort((a, b) => Number(valid(b)) - Number(valid(a)) || a.commonName.localeCompare(b.commonName));
	}, [all, query, show]);

	const data = pki.data;
	if (!data) return null;
	const settings = data.settings;
	const protectedHost = data.protected.find((h) => hostKey(h) === hostKey(host));
	const canIssue = can("pki", "issue") && !!protectedHost && issuersFor(protectedHost, data.cas).length > 0;
	const keyActions = (c: PkiCert) => c.hasKey && can("pki", "export_key") && !c.revokedOn;
	const p12 = (c: PkiCert) =>
		showSecretModal({
			action: "p12",
			objectId: c.id,
			name: c.commonName,
			publicUrl: settings.publicUrl,
			compatible: settings.p12Compatible,
		});
	const run = async (action: () => Promise<unknown>) => {
		try {
			await action();
		} catch (err: any) {
			showError(err.message);
		}
	};

	const actions = (c: PkiCert): DropdownItem[] => [
		{
			key: "details",
			label: <T id="npmos.mtls.details" />,
			onSelect: () => showCertModal({ certId: c.id, openHost }),
		},
		...(keyActions(c)
			? [
					{ key: "p12", label: <T id="npmos.pki.download.p12" />, onSelect: () => p12(c) },
					{
						key: "link",
						label: <T id="npmos.pki.link.create" />,
						onSelect: () =>
							showSecretModal({
								action: "link",
								objectId: c.id,
								name: c.commonName,
								publicUrl: settings.publicUrl,
								compatible: settings.p12Compatible,
							}),
					},
				]
			: []),
		{
			key: "cert",
			label: <T id="npmos.pki.download.cert" />,
			onSelect: () => run(async () => saveFile(await downloadCert(c.id, "cert"))),
		},
		...(can("pki", "issue") && !c.revokedOn
			? [
					{
						key: "renew",
						divider: true,
						label: <T id="npmos.pki.renew" />,
						onSelect: () => showIssueModal({ data, renew: c, onDone: refresh }),
					},
				]
			: []),
		...(can("pki", "revoke") && valid(c)
			? [
					{
						key: "revoke",
						label: <span className="text-danger">{t("npmos.pki.revoke")}</span>,
						onSelect: () => showRevokeModal({ certs: [c], onDone: refresh }),
					},
				]
			: []),
		...(can("pki", "revoke")
			? [
					{
						key: "delete",
						label: <span className="text-danger">{t("npmos.mtls.delete")}</span>,
						onSelect: () =>
							showConfirmModal({
								tTitle: "npmos.mtls.delete",
								tConfirm: "npmos.mtls.delete",
								danger: true,
								onConfirm: async () => {
									await deleteCerts([c.id]);
									showSuccess(t("npmos.mtls.deleted", { count: 1 }));
									refresh();
								},
								children: <T id="npmos.mtls.delete.text" data={{ count: 1 }} />,
							}),
					},
				]
			: []),
	];

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title className="text-break">
					<T id="npmos.mtls.host-certs.title" data={{ name: host.name }} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<div className="d-flex flex-wrap gap-2 mb-3">
					<SearchField
						variant="inset"
						value={query}
						onChange={setQuery}
						placeholder={t("npmos.mtls.host-certs.search")}
					/>
					<select
						className="form-select w-auto"
						aria-label={t("npmos.pki.status")}
						value={show}
						onChange={(e) => setShow(e.target.value as Show)}
					>
						<option value="valid">
							{t("npmos.mtls.host-certs.valid", { count: all.filter(valid).length })}
						</option>
						<option value="all">{t("npmos.mtls.host-certs.all", { count: all.length })}</option>
					</select>
				</div>
				{rows.length === 0 ? (
					<p className="text-secondary mb-0">
						<T id={all.length ? "npmos.pki.none-found" : "npmos.mtls.host-certs.none"} />
					</p>
				) : (
					<div className="list-group" style={{ maxHeight: "55vh", overflowY: "auto" }}>
						{rows.map((c) => {
							const s = certStatus(c);
							return (
								<div key={c.id} className="list-group-item d-flex align-items-center gap-3">
									<button
										type="button"
										className="flex-fill text-start text-reset bg-transparent border-0 p-0"
										style={{ minWidth: 0 }}
										title={t("npmos.mtls.details")}
										onClick={() => showCertModal({ certId: c.id, openHost })}
									>
										<div className="fw-medium text-truncate">
											{c.commonName}
											{c.hasKey && (
												<IconKey
													size={14}
													className="ms-1 text-secondary"
													aria-label={t("npmos.mtls.cert.key.kept")}
												/>
											)}
										</div>
										<div className="small text-secondary text-truncate">
											{[c.subject.email, c.notes].filter(Boolean).join(" · ") ||
												t("npmos.mtls.host-certs.issued", {
													time: formatDateTime(c.createdOn, locale),
												})}
										</div>
									</button>
									<div className="text-end text-nowrap d-none d-sm-block">
										<span className={cn("badge", STATUS_TONE[s])}>
											<T id={`npmos.pki.status.${s}`} />
										</span>
										<div className="small text-secondary">
											{c.daysLeft >= 0
												? t("npmos.pki.days-left", { days: c.daysLeft })
												: t("npmos.pki.expired-ago", { days: -c.daysLeft })}
										</div>
									</div>
									{keyActions(c) ? (
										<button
											type="button"
											className="btn btn-sm"
											title={t("npmos.pki.download.p12")}
											aria-label={t("npmos.pki.download.p12")}
											onClick={() => p12(c)}
										>
											<IconDownload size={16} />
											<span className="ms-1 d-none d-md-inline">.p12</span>
										</button>
									) : (
										<span
											className="btn btn-sm disabled"
											title={t(
												c.revokedOn ? "npmos.pki.status.revoked" : "npmos.mtls.cert.no-key",
											)}
										>
											<IconDownload size={16} />
										</span>
									)}
									<Dropdown
										floating
										inline
										ariaLabel={t("npmos.pki.actions")}
										triggerClassName="btn btn-sm btn-ghost-secondary"
										trigger={<IconDots size={16} />}
										items={actions(c)}
									/>
								</div>
							);
						})}
					</div>
				)}
			</Modal.Body>
			<Modal.Footer className="justify-content-between">
				{openHost ? (
					<Button
						onClick={() => {
							remove();
							openHost(host);
						}}
					>
						<T id="npmos.mtls.host-certs.page" />
					</Button>
				) : (
					<span />
				)}
				{canIssue && (
					<Button
						actionType="primary"
						onClick={() => showAccessModal({ data, host: protectedHost ?? host, onDone: refresh })}
					>
						<IconPlus size={16} className="me-1" />
						<T id="npmos.mtls.access.issue" />
					</Button>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showHostCertsModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(HostCertsModal, props);
