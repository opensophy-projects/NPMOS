// Certificates → mTLS: hosts protected by client certificates and the access certificates that open
// them. A host is protected in one step (its own trust domain is created when needed), a
// certificate is issued for a host in a few fields and managed here: details, files, one-time
// links, renewal, revocation, deletion. The CAs and settings behind it stay in PKI.
// ?host=proxy_host-5 filters by a host, ?cert=12 opens a certificate.
import { IconDots, IconLock, IconPlus } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useNavigate, useSearchParams } from "react-router-dom";
import { HasPermission, LoadingPage } from "src/components";
import { useLocaleState } from "src/context";
import { useProxyHosts, useStreams } from "src/hooks";
import { formatDateTime, intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { showAccessModal } from "../../pki/AccessModal";
import {
	deleteCerts,
	enableMtlsHost,
	getMtlsHost,
	type HostRef,
	hostKey,
	issuersFor,
	type MtlsHostType,
	type PkiCert,
	type PkiOverview,
	type ProtectedHost,
	setMtlsHost,
	usePki,
} from "../../pki/api";
import { certStatus, STATUS_TONE, showCertModal } from "../../pki/CertModal";
import { showHostCertsModal } from "../../pki/HostCertsModal";
import { showMtlsModal } from "../../pki/MtlsModal";
import { showRevokeModal } from "../../pki/RevokeModal";
import { showSecretModal } from "../../pki/SecretModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown, type DropdownItem } from "../../ui/Dropdown";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../Pki/Pki.module.css";
import { SearchField } from "../../ui/SearchField";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

type StatusFilter = "" | "active" | "expiring" | "expired" | "revoked";

const attempt = async (action: () => Promise<unknown>, refresh: () => void, message?: string) => {
	try {
		await action();
		if (message) showSuccess(message);
	} catch (err: any) {
		showError(err.message);
	}
	refresh();
};

/** mTLS of a host off (its settings are kept for the next switch on) */
export const disableMtls = async (type: MtlsHostType, id: number) => {
	const {
		name: _n,
		hasCertificate: _c,
		paths: _p,
		issuerCheck: _i,
		upstreamCaCertificateId: _u,
		nginx: _x,
		...binding
	} = await getMtlsHost(type, id);
	return setMtlsHost(type, id, { ...binding, enabled: false });
};

function Summary({ data, certs }: { data: PkiOverview; certs: PkiCert[] }) {
	const counts = { active: 0, expiring: 0, revoked: 0 };
	for (const c of certs) {
		const s = certStatus(c);
		if (s in counts) counts[s as keyof typeof counts]++;
	}
	const items: [string, number, string?][] = [
		["npmos.mtls.summary.hosts", data.protected.length],
		["npmos.mtls.summary.active", counts.active],
		["npmos.mtls.summary.expiring", counts.expiring, counts.expiring ? "text-yellow" : undefined],
		["npmos.mtls.summary.revoked", counts.revoked],
	];
	return (
		<div className={styles.summary}>
			{items.map(([label, value, tone]) => (
				<div className={cn("card", styles.stat)} key={label}>
					<div className={cn(styles.statValue, tone)}>{value}</div>
					<div className={styles.statLabel}>
						<T id={label} />
					</div>
				</div>
			))}
		</div>
	);
}

function HostsCard({
	data,
	certs,
	refresh,
	filter,
}: {
	data: PkiOverview;
	certs: PkiCert[];
	refresh: () => void;
	filter: (host: HostRef) => void;
}) {
	const can = useCan();
	const caNames = (ids: number[]) =>
		ids.map((id) => data.cas.find((ca) => ca.id === id)?.name ?? `#${id}`).join(", ");
	const actions = (h: ProtectedHost): DropdownItem[] => [
		...(can("pki", "issue") && issuersFor(h, data.cas).length
			? [
					{
						key: "issue",
						label: <T id="npmos.mtls.access.issue" />,
						onSelect: () => showAccessModal({ data, host: h, onDone: refresh }),
					},
				]
			: []),
		{
			key: "pick",
			label: <T id="npmos.mtls.host.pick" />,
			onSelect: () => showHostCertsModal({ host: h, openHost: filter }),
		},
		{ key: "certs", label: <T id="npmos.mtls.host.certs" />, onSelect: () => filter(h) },
		{
			key: "settings",
			label: <T id="npmos.mtls.host.settings" />,
			onSelect: () => showMtlsModal({ type: h.hostType, hostId: h.hostId, onDone: refresh }),
		},
		{
			key: "off",
			divider: true,
			label: <span className="text-danger">{t("npmos.mtls.host.disable")}</span>,
			onSelect: () =>
				showConfirmModal({
					tTitle: "npmos.mtls.host.disable",
					tConfirm: "npmos.mtls.host.disable",
					danger: true,
					onConfirm: async () => {
						await disableMtls(h.hostType, h.hostId);
						showSuccess(t("npmos.mtls.host.disabled", { name: h.name }));
						refresh();
					},
					children: <T id="npmos.mtls.host.disable.text" data={{ name: h.name }} />,
				}),
		},
	];

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<h3 className="card-title m-0">
					<T id="npmos.mtls.hosts" />
				</h3>
			</div>
			{data.protected.length === 0 ? (
				<p className={styles.empty}>
					<T id="npmos.mtls.hosts.none" />
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.mtls.host" />
								</th>
								<th>
									<T id="npmos.mtls.mode" />
								</th>
								<th>
									<T id="npmos.mtls.trust" />
								</th>
								<th>
									<T id="npmos.mtls.certs" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{data.protected.map((h) => {
								const count = certs.filter(
									(c) =>
										certStatus(c) !== "revoked" &&
										c.status !== "expired" &&
										c.access.some((a) => hostKey(a) === hostKey(h)),
								).length;
								return (
									<tr key={hostKey(h)}>
										<td>
											<button
												type="button"
												className="btn btn-link p-0 fw-medium"
												onClick={() => filter(h)}
											>
												{h.name}
											</button>
											{!h.active && (
												<div className={styles.sub}>
													<T id="npmos.mtls.host.inactive" />
												</div>
											)}
										</td>
										<td>
											<span className="badge bg-azure-lt">
												<T
													id={
														h.mode === "optional"
															? "npmos.hosts.mtls.optional"
															: "npmos.hosts.mtls.required"
													}
												/>
											</span>
											{h.rules > 0 && (
												<div className={styles.sub}>
													<T id="npmos.mtls.rules.count" data={{ count: h.rules }} />
												</div>
											)}
										</td>
										<td className={styles.used}>{caNames(h.caIds)}</td>
										<td>{count}</td>
										<td>
											<Dropdown
												floating
												inline
												ariaLabel={t("npmos.pki.actions")}
												triggerClassName="btn btn-sm btn-ghost-secondary"
												trigger={<IconDots size={16} />}
												items={actions(h)}
											/>
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

function CertsCard({
	data,
	certs,
	refresh,
	host,
	setHost,
	openHost,
}: {
	data: PkiOverview;
	certs: PkiCert[];
	refresh: () => void;
	host: string;
	setHost: (key: string) => void;
	openHost: (host: HostRef) => void;
}) {
	const can = useCan();
	const { locale } = useLocaleState();
	const [query, setQuery] = useState("");
	const [status, setStatus] = useState<StatusFilter>("");
	const [selected, setSelected] = useState<number[]>([]);

	const rows = useMemo(() => {
		const q = query.trim().toLowerCase();
		return certs.filter((c) => {
			if (host && !c.access.some((a) => hostKey(a) === host)) return false;
			if (status && certStatus(c) !== status) return false;
			if (!q) return true;
			return [c.commonName, c.subject.email, c.notes, c.serial, ...c.access.map((a) => a.name)]
				.filter(Boolean)
				.some((v) => String(v).toLowerCase().includes(q));
		});
	}, [certs, host, status, query]);
	const chosen = rows.filter((c) => selected.includes(c.id));
	const publicUrl = data.settings.publicUrl;
	const compatible = data.settings.p12Compatible;
	const open = (c: PkiCert) => showCertModal({ certId: c.id, openHost });
	const remove = (list: PkiCert[]) =>
		showConfirmModal({
			tTitle: "npmos.mtls.delete",
			tConfirm: "npmos.mtls.delete",
			danger: true,
			onConfirm: async () => {
				const r = await deleteCerts(list.map((c) => c.id));
				showSuccess(t("npmos.mtls.deleted", { count: r.deleted }));
				setSelected([]);
				refresh();
			},
			children: (
				<>
					<T id="npmos.mtls.delete.text" data={{ count: list.length }} />
					<div className="small font-monospace text-secondary mt-2">
						{list
							.slice(0, 20)
							.map((c) => c.commonName)
							.join(", ")}
					</div>
				</>
			),
		});

	const actions = (c: PkiCert): DropdownItem[] => {
		const live = !c.revokedOn && c.status !== "expired";
		return [
			{ key: "details", label: <T id="npmos.mtls.details" />, onSelect: () => open(c) },
			...(c.hasKey && can("pki", "export_key") && !c.revokedOn
				? [
						{
							key: "p12",
							label: <T id="npmos.pki.download.p12" />,
							onSelect: () =>
								showSecretModal({
									action: "p12",
									objectId: c.id,
									name: c.commonName,
									publicUrl,
									compatible,
								}),
						},
						{
							key: "link",
							label: <T id="npmos.pki.link.create" />,
							onSelect: () =>
								showSecretModal({
									action: "link",
									objectId: c.id,
									name: c.commonName,
									publicUrl,
									compatible,
								}),
						},
					]
				: []),
			...(can("pki", "revoke") && live
				? [
						{
							key: "revoke",
							divider: true,
							label: <span className="text-danger">{t("npmos.pki.revoke")}</span>,
							onSelect: () => showRevokeModal({ certs: [c], onDone: refresh }),
						},
					]
				: []),
			...(can("pki", "revoke")
				? [
						{
							key: "delete",
							divider: !live,
							label: <span className="text-danger">{t("npmos.mtls.delete")}</span>,
							onSelect: () => remove([c]),
						},
					]
				: []),
		];
	};

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<h3 className="card-title m-0">
					<T id="npmos.mtls.certs.title" />
				</h3>
			</div>
			<div className={styles.filters}>
				<SearchField
					variant="inset"
					value={query}
					onChange={(value) => setQuery(value)}
					placeholder={t("npmos.mtls.search")}
				/>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.mtls.host")}
					value={host}
					onChange={(e) => setHost(e.target.value)}
				>
					<option value="">{t("npmos.mtls.all-hosts")}</option>
					{data.protected.map((h) => (
						<option key={hostKey(h)} value={hostKey(h)}>
							{h.name}
						</option>
					))}
				</select>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.pki.status")}
					value={status}
					onChange={(e) => setStatus(e.target.value as StatusFilter)}
				>
					<option value="">{t("npmos.pki.status.all")}</option>
					{["active", "expiring", "expired", "revoked"].map((s) => (
						<option key={s} value={s}>
							{t(`npmos.pki.status.${s}`)}
						</option>
					))}
				</select>
				{chosen.length > 0 && can("pki", "revoke") && (
					<>
						<button
							type="button"
							className="btn btn-sm btn-outline-danger"
							disabled={!chosen.some((c) => !c.revokedOn)}
							onClick={() =>
								showRevokeModal({
									certs: chosen.filter((c) => !c.revokedOn),
									onDone: () => {
										setSelected([]);
										refresh();
									},
								})
							}
						>
							<T
								id="npmos.pki.revoke.selected"
								data={{ count: chosen.filter((c) => !c.revokedOn).length }}
							/>
						</button>
						<button type="button" className="btn btn-sm btn-ghost-danger" onClick={() => remove(chosen)}>
							<T id="npmos.mtls.delete.selected" data={{ count: chosen.length }} />
						</button>
					</>
				)}
			</div>
			{rows.length === 0 ? (
				<p className={styles.empty}>
					<T id={certs.length ? "npmos.pki.none-found" : "npmos.mtls.certs.none"} />
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th className="w-1">
									<input
										type="checkbox"
										className="form-check-input"
										aria-label={t("npmos.pki.select-all")}
										checked={rows.every((c) => selected.includes(c.id))}
										onChange={(e) => setSelected(e.target.checked ? rows.map((c) => c.id) : [])}
									/>
								</th>
								<th>
									<T id="npmos.mtls.access.name" />
								</th>
								<th>
									<T id="npmos.mtls.opens" />
								</th>
								<th>
									<T id="npmos.pki.status" />
								</th>
								<th>
									<T id="npmos.pki.expires" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{rows.map((c) => {
								const s = certStatus(c);
								return (
									<tr key={c.id}>
										<td>
											<input
												type="checkbox"
												className="form-check-input"
												aria-label={c.commonName}
												checked={selected.includes(c.id)}
												onChange={(e) =>
													setSelected(
														e.target.checked
															? [...selected, c.id]
															: selected.filter((x) => x !== c.id),
													)
												}
											/>
										</td>
										<td>
											<button
												type="button"
												className="btn btn-link p-0 fw-medium"
												onClick={() => open(c)}
											>
												{c.commonName}
											</button>
											<div className={styles.sub}>
												{[c.subject.email, c.notes].filter(Boolean).join(" · ") || c.serial}
											</div>
										</td>
										<td className={styles.used}>
											{c.access.length ? (
												<span title={c.access.map((a) => a.name).join(", ")}>
													{c.access
														.slice(0, 2)
														.map((a) => a.name)
														.join(", ")}
													{c.access.length > 2 && ` +${c.access.length - 2}`}
												</span>
											) : (
												<span className="text-secondary">—</span>
											)}
										</td>
										<td>
											<span className={cn("badge", STATUS_TONE[s])}>
												<T id={`npmos.pki.status.${s}`} />
											</span>
										</td>
										<td className="text-nowrap">
											<div>{formatDateTime(c.notAfter, locale)}</div>
											<div className={styles.sub}>
												{c.daysLeft >= 0
													? t("npmos.pki.days-left", { days: c.daysLeft })
													: t("npmos.pki.expired-ago", { days: -c.daysLeft })}
											</div>
										</td>
										<td>
											<Dropdown
												floating
												inline
												ariaLabel={t("npmos.pki.actions")}
												triggerClassName="btn btn-sm btn-ghost-secondary"
												trigger={<IconDots size={16} />}
												items={actions(c)}
											/>
										</td>
									</tr>
								);
							})}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

/** hosts with TLS and without mTLS: what the "Protect a host" menu offers */
function useUnprotected(data: PkiOverview | undefined) {
	const proxy = useProxyHosts(["certificate"]);
	const stream = useStreams(["certificate"]);
	return useMemo(() => {
		if (!data) return [];
		const on = new Set(data.protected.map(hostKey));
		const list: HostRef[] = [
			...(proxy.data ?? [])
				.filter((h) => h.certificateId)
				.map((h) => ({ hostType: "proxy_host" as const, hostId: h.id, name: h.domainNames.join(", ") })),
			...(stream.data ?? [])
				.filter((h) => h.certificateId)
				.map((h) => ({ hostType: "stream" as const, hostId: h.id, name: `:${h.incomingPort}` })),
		];
		return list.filter((h) => !on.has(hostKey(h)));
	}, [data, proxy.data, stream.data]);
}

function MtlsPage() {
	const can = useCan();
	const navigate = useNavigate();
	const queryClient = useQueryClient();
	const [params, setParams] = useSearchParams();
	const { data, isLoading, isError, error } = usePki({ refetchInterval: 30000 });
	const unprotected = useUnprotected(data);
	const refresh = () => {
		queryClient.invalidateQueries({ queryKey: ["npmos-pki"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-mtls-hosts"] });
	};
	const host = params.get("host") ?? "";
	const setHost = (key: string) => {
		const next = new URLSearchParams(params);
		if (key) next.set("host", key);
		else next.delete("host");
		setParams(next, { replace: true });
	};
	const openHost = (h: HostRef) => setHost(hostKey(h));

	// ?cert=12: the certificate opens once the data is there
	const certParam = Number(params.get("cert")) || 0;
	// biome-ignore lint/correctness/useExhaustiveDependencies: once per ?cert
	useEffect(() => {
		if (!certParam || !data) return;
		showCertModal({ certId: certParam, openHost });
		const next = new URLSearchParams(params);
		next.delete("cert");
		setParams(next, { replace: true });
	}, [certParam, data]);

	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;

	const certs = data.certificates.filter((c) => c.profile === "client");
	const protect = (h: HostRef) =>
		attempt(() => enableMtlsHost(h.hostType, h.hostId), refresh, t("npmos.mtls.host.enabled", { name: h.name }));

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>mTLS</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.mtls.subtitle" />
					</p>
				</div>
				<div className={hostStyles.toolbar}>
					{unprotected.length > 0 && (
						<Dropdown
							floating
							ariaLabel={t("npmos.mtls.protect")}
							triggerClassName={hostStyles.tool}
							trigger={
								<>
									<IconLock size={16} />
									<span className={hostStyles.toolText}>
										<T id="npmos.mtls.protect" />
									</span>
								</>
							}
							items={unprotected.map((h) => ({
								key: hostKey(h),
								label: h.name,
								onSelect: () => protect(h),
							}))}
						/>
					)}
					{can("pki", "issue") && (
						<button
							type="button"
							className={cn("btn btn-primary btn-sm", hostStyles.add)}
							disabled={!data.protected.length}
							title={data.protected.length ? undefined : t("npmos.mtls.access.no-hosts")}
							onClick={() =>
								showAccessModal({
									data,
									host: data.protected.find((h) => hostKey(h) === host),
									onDone: refresh,
								})
							}
						>
							<IconPlus size={16} />
							<T id="npmos.mtls.access.issue" />
						</button>
					)}
				</div>
			</div>

			{!data.protected.length && (
				<Alert variant="info" className="mb-0">
					<T id="npmos.mtls.start" />
				</Alert>
			)}

			<Summary data={data} certs={certs} />
			<HostsCard data={data} certs={certs} refresh={refresh} filter={openHost} />
			<CertsCard data={data} certs={certs} refresh={refresh} host={host} setHost={setHost} openHost={openHost} />
			<p className="text-secondary small m-0">
				<T id="npmos.mtls.pki-hint" />{" "}
				<button
					type="button"
					className="btn btn-link btn-sm p-0 align-baseline"
					onClick={() => navigate("/pki")}
				>
					<T id="npmos.pki" />
				</button>
			</p>
		</div>
	);
}

const Mtls = () => (
	<HasPermission rbac="pki" permission={VIEW} pageLoading loadingNoLogo>
		<MtlsPage />
	</HasPermission>
);

export default Mtls;
