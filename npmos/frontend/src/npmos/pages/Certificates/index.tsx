// Certificates → All certificates: one registry of every certificate the system has (TLS of the hosts, CAs and
// issued certificates of the PKI, certificate files on disk no record describes) with pages from the server,
// search, the soonest expiry first, filters by source, status, type and use. TLS rows keep the actions of
// NPMplus (renew, download, edit, test, delete), PKI rows open their card or the PKI page.
import {
	IconChevronLeft,
	IconChevronRight,
	IconDots,
	IconFilter,
	IconPlus,
	IconSortDescending,
} from "@tabler/icons-react";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useNavigate, useSearchParams } from "react-router-dom";
import { deleteCertificate, downloadCertificate, getCertificate } from "src/api/backend";
import { LoadingPage } from "src/components";
import { useUser } from "src/hooks";
import { formatDateTime, intl, T } from "src/locale";
import {
	showCustomCertificateModal,
	showDeleteConfirmModal,
	showDNSCertificateModal,
	showHTTPCertificateModal,
	showReachabilityModal,
	showRenewCertificateModal,
} from "src/modals";
import { CERTIFICATES, hasPermission, MANAGE } from "src/modules/Permissions";
import { showError, showObjectSuccess } from "src/notifications";
import type { CertSource, CertStatus, EventQuery, RegistryCert } from "../../api";
import { useCertificateRegistry } from "../../hooks";
import { showCertModal } from "../../pki/CertModal";
import { Dropdown, type DropdownItem } from "../../ui/Dropdown";
import { Popover } from "../../ui/Popover";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../WafEvents/Events.module.css";
import own from "./Certificates.module.css";
import { SearchField } from "../../ui/SearchField";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const PAGE_SIZE = 25;
const SOURCES: CertSource[] = ["tls", "ca", "pki", "file"];
const STATUSES: CertStatus[] = ["expiring", "expired", "revoked"];
const SORTS = ["expires", "-expires", "name", "-created"] as const;
const DAY = 86400000;

const STATUS_TONE: Record<CertStatus, string> = {
	valid: "bg-green-lt",
	expiring: "bg-yellow-lt",
	expired: "bg-red-lt",
	revoked: "bg-red-lt",
};

/** what the certificate is, in the words of the interface */
const kindLabel = (c: Pick<RegistryCert, "source" | "kind" | "dnsProvider">) => {
	const ids: Record<string, string> = {
		"tls:letsencrypt": "lets-encrypt",
		"tls:other": "certificates.custom",
		"ca:root": "npmos.certs.kind.root",
		"ca:intermediate": "npmos.certs.kind.intermediate",
		"ca:external": "npmos.certs.kind.external",
		"pki:client": "npmos.pki.profile.client",
		"pki:server": "npmos.pki.profile.server",
		"file:ca": "npmos.certs.kind.file-ca",
		"file:file": "npmos.certs.kind.file",
		"file:dummy": "npmos.certs.kind.dummy",
	};
	const id = ids[`${c.source}:${c.kind}`];
	const name = id ? t(id) : c.kind;
	return c.dnsProvider ? `${name} – ${c.dnsProvider}` : name;
};

/** a type of the filter: the kinds of different sources have different names */
const kindName = (kind: string) =>
	SOURCES.map((source) => kindLabel({ source, kind })).find((label) => label !== kind) ?? kind;

function Expiry({ value, status }: { value: string | null; status: CertStatus }) {
	if (!value) return <span className="text-secondary">—</span>;
	const days = Math.floor((new Date(value).getTime() - Date.now()) / DAY);
	return (
		<>
			<div>{formatDateTime(value, intl.locale)}</div>
			<div className={cn(own.left, (status === "expiring" || status === "expired") && own[status])}>
				{days < 0 ? (
					<T id="npmos.certs.expired-ago" data={{ days: -days }} />
				) : (
					<T id="npmos.certs.days-left" data={{ days }} />
				)}
			</div>
		</>
	);
}

function UsedBy({ cert }: { cert: RegistryCert }) {
	if (!cert.usedBy.length) return <span className="text-secondary">—</span>;
	if (cert.usedBy[0].type === "default") return <T id="npmos.certs.default-server" />;
	const [first, ...rest] = cert.usedBy;
	return (
		<span title={cert.usedBy.map((u) => u.name).join("\n")}>
			{first.name}
			{rest.length > 0 && <span className="text-secondary"> +{rest.length}</span>}
		</span>
	);
}

function CertificatesPage() {
	const navigate = useNavigate();
	const [params, setParams] = useSearchParams();
	const { data: me } = useUser("me");
	const canManageTls = hasPermission(CERTIFICATES, MANAGE, me?.permissions, me?.roles);
	const source = (SOURCES as string[]).includes(params.get("source") || "")
		? (params.get("source") as CertSource)
		: "";
	const status = (STATUSES as string[]).includes(params.get("status") || "")
		? (params.get("status") as CertStatus)
		: "";
	const kinds = (params.get("kind") || "").split(",").filter(Boolean);
	const used = params.get("used") === "yes" || params.get("used") === "no" ? params.get("used") || "" : "";
	const sort = (SORTS as readonly string[]).includes(params.get("sort") || "") ? params.get("sort") || "" : "expires";
	const q = params.get("q") || "";
	const page = Math.max(Number.parseInt(params.get("page") || "0", 10) || 0, 0);
	const [search, setSearch] = useState(q);

	const update = (changes: Record<string, string>) => {
		const next = new URLSearchParams(params);
		for (const [key, value] of Object.entries(changes)) {
			if (value) next.set(key, value);
			else next.delete(key);
		}
		if (!("page" in changes)) next.delete("page");
		// the types belong to a source
		if ("source" in changes) next.delete("kind");
		setParams(next, { replace: true });
	};

	useEffect(() => setSearch(q), [q]);
	// biome-ignore lint/correctness/useExhaustiveDependencies: runs when the typed text changes
	useEffect(() => {
		if (search === q) return;
		const timer = setTimeout(() => update({ q: search }), 300);
		return () => clearTimeout(timer);
	}, [search]);

	const query: EventQuery = {
		source: source || undefined,
		status: status || undefined,
		kind: kinds.join(",") || undefined,
		used: used || undefined,
		q: q || undefined,
		sort,
		limit: PAGE_SIZE,
		offset: page * PAGE_SIZE,
	};
	const { data, isLoading, isError, error, isFetching } = useCertificateRegistry(query);
	const pages = data ? Math.max(Math.ceil(data.total / PAGE_SIZE), 1) : 1;
	const filterCount = kinds.length + (used ? 1 : 0);
	const allCount = data ? Object.values(data.counts.source).reduce((a, b) => a + (b || 0), 0) : 0;
	const anyStatusCount = data ? Object.values(data.counts.status).reduce((a, b) => a + (b || 0), 0) : 0;

	const remove = (id: number) =>
		showDeleteConfirmModal({
			title: <T id="object.delete" tData={{ object: "certificate" }} />,
			onConfirm: async () => {
				await deleteCertificate(id);
				showObjectSuccess("certificate", "deleted");
			},
			invalidations: [["certificates"], ["certificate", id]],
			children: <T id="object.delete.content" tData={{ object: "certificate" }} />,
		});

	const edit = async (id: number) => {
		try {
			showCustomCertificateModal(await getCertificate(id));
		} catch (err: any) {
			showError(err.message);
		}
	};

	const actions = (c: RegistryCert): DropdownItem[] => {
		const items: DropdownItem[] = [];
		if (c.source === "tls" && typeof c.id === "number") {
			const id = c.id;
			if (c.pkiId) {
				const pkiId = c.pkiId;
				items.push({
					key: "pki",
					label: <T id="npmos.certs.open-pki" />,
					onSelect: () => showCertModal({ certId: pkiId }),
				});
			}
			if (c.kind === "letsencrypt" && !c.dnsProvider) {
				items.push({ key: "test", label: <T id="test" />, onSelect: () => showReachabilityModal(c.subjects) });
			}
			if (canManageTls) {
				if (c.kind === "letsencrypt") {
					items.push(
						{ key: "renew", label: <T id="action.renew" />, onSelect: () => showRenewCertificateModal(id) },
						{
							key: "download",
							label: <T id="action.download" />,
							onSelect: () => downloadCertificate(id).catch((err) => showError(err.message)),
						},
					);
				}
				if (c.kind === "other") {
					items.push({ key: "edit", label: <T id="action.edit" />, onSelect: () => edit(id) });
				}
				if (!c.usedBy.length) {
					items.push({
						key: "delete",
						divider: true,
						label: <T id="action.delete" />,
						onSelect: () => remove(id),
					});
				}
			}
		}
		if (c.source === "pki" && typeof c.id === "number") {
			const id = c.id;
			items.push({
				key: "open",
				label: <T id="npmos.certs.details" />,
				onSelect: () => showCertModal({ certId: id }),
			});
			if (c.kind === "client") {
				items.push({
					key: "mtls",
					label: <T id="npmos.certs.open-mtls" />,
					onSelect: () => navigate(`/mtls?cert=${id}`),
				});
			}
		}
		if (c.source === "ca") {
			items.push({
				key: "cas",
				label: <T id="npmos.certs.open-cas" />,
				onSelect: () => navigate("/pki?tab=cas"),
			});
			if (c.tlsId && canManageTls) {
				const tlsId = c.tlsId;
				items.push({ key: "edit", label: <T id="action.edit" />, onSelect: () => edit(tlsId) });
				if (!c.usedBy.length) {
					items.push({
						key: "delete",
						divider: true,
						label: <T id="action.delete" />,
						onSelect: () => remove(tlsId),
					});
				}
			}
		}
		if (c.source === "file" && c.path) {
			const path = c.path;
			items.push({
				key: "copy",
				label: <T id="npmos.certs.copy-path" />,
				onSelect: () => navigator.clipboard?.writeText(path),
			});
		}
		return items;
	};

	const segment = (active: boolean, onClick: () => void, label: React.ReactNode, n?: number) => (
		<button
			type="button"
			className={cn(styles.period, active && styles.periodOn)}
			aria-pressed={active}
			onClick={onClick}
		>
			{label}
			{n !== undefined && <span className={own.n}>{n}</span>}
		</button>
	);

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.certs.title" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.certs.description" />
					</p>
				</div>
				{canManageTls && (
					<Dropdown
						floating
						inline
						ariaLabel={t("npmos.certs.add")}
						triggerClassName="btn btn-primary"
						trigger={
							<>
								<IconPlus size={16} className="me-1" />
								<T id="npmos.certs.add" />
							</>
						}
						items={[
							{
								key: "http",
								label: <T id="lets-encrypt-via-http" />,
								onSelect: () => showHTTPCertificateModal(),
							},
							{
								key: "dns",
								label: <T id="lets-encrypt-via-dns" />,
								onSelect: () => showDNSCertificateModal(),
							},
							{
								key: "custom",
								divider: true,
								label: <T id="certificates.custom" />,
								onSelect: () => showCustomCertificateModal(),
							},
							{
								key: "mtls",
								label: <T id="npmos.certificates.mtls" />,
								onSelect: () => showCustomCertificateModal(undefined, "mtls"),
							},
						]}
					/>
				)}
			</div>

			<div className={hostStyles.toolbar}>
				<SearchField value={search} onChange={setSearch} placeholder={t("npmos.certs.search")} />
				<div className={styles.periods} role="group" aria-label={t("npmos.certs.status")}>
					{segment(!status, () => update({ status: "" }), <T id="npmos.certs.status.any" />, anyStatusCount)}
					{STATUSES.map((s) =>
						segment(
							status === s,
							() => update({ status: status === s ? "" : s }),
							<T id={`npmos.certs.status.${s}`} />,
							data?.counts.status[s] ?? 0,
						),
					)}
				</div>
				<Popover
					ariaLabel={t("npmos.events.filters")}
					title={<T id="npmos.events.filters" />}
					titleAction={
						filterCount > 0 ? (
							<button
								type="button"
								className={hostStyles.reset}
								onClick={() => update({ kind: "", used: "" })}
							>
								<T id="npmos.events.filters.reset" />
							</button>
						) : undefined
					}
					width="22rem"
					triggerClassName={hostStyles.tool}
					activeClassName={hostStyles.toolOn}
					trigger={
						<>
							<IconFilter size={16} />
							<span className={hostStyles.toolText}>
								<T id="npmos.events.filters" />
							</span>
							{filterCount > 0 && <span className={hostStyles.count}>{filterCount}</span>}
						</>
					}
				>
					{() => (
						<div>
							<div className={styles.section}>
								<div className={styles.sectionTitle}>
									<T id="npmos.certs.kind" />
								</div>
								<div className={styles.options}>
									{(data?.kinds ?? []).map((k) => (
										<label key={k}>
											<input
												type="checkbox"
												className="form-check-input m-0"
												checked={kinds.includes(k)}
												onChange={() =>
													update({
														kind: (kinds.includes(k)
															? kinds.filter((x) => x !== k)
															: [...kinds, k]
														).join(","),
													})
												}
											/>
											{kindName(k)}
										</label>
									))}
								</div>
							</div>
							<div className={styles.section}>
								<div className={styles.sectionTitle}>
									<T id="npmos.certs.used" />
								</div>
								<div className={styles.options}>
									{(["", "yes", "no"] as const).map((u) => (
										<label key={u || "any"}>
											<input
												type="radio"
												name="npmos-certs-used"
												className="form-check-input m-0"
												checked={used === u}
												onChange={() => update({ used: u })}
											/>
											<T id={`npmos.certs.used.${u || "any"}`} />
										</label>
									))}
								</div>
							</div>
						</div>
					)}
				</Popover>
			</div>

			<div className={cn("card", hostStyles.tableCard)}>
				<div className={hostStyles.summary}>
					<div className={styles.kinds}>
						{segment(!source, () => update({ source: "" }), <T id="npmos.certs.source.all" />, allCount)}
						{SOURCES.filter((s) => s !== "file" || data?.counts.source.file).map((s) =>
							segment(
								source === s,
								() => update({ source: source === s ? "" : s }),
								<T id={`npmos.certs.source.${s}`} />,
								data?.counts.source[s] ?? 0,
							),
						)}
					</div>
					{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
					<Dropdown
						floating
						inline
						ariaLabel={t("npmos.certs.sort")}
						title={t("npmos.certs.sort")}
						triggerClassName={hostStyles.tool}
						trigger={
							<>
								<IconSortDescending size={16} />
								<span className={hostStyles.toolText}>
									<T id={`npmos.certs.sort.${sort}`} />
								</span>
							</>
						}
						items={SORTS.map((s) => ({
							key: s,
							active: sort === s,
							label: <T id={`npmos.certs.sort.${s}`} />,
							onSelect: () => update({ sort: s === "expires" ? "" : s }),
						}))}
					/>
				</div>
				{isLoading ? (
					<LoadingPage noLogo />
				) : isError || !data ? (
					<div className="card-body">
						<Alert variant="danger" className="mb-0">
							{error?.message || <T id="npmos.common.unknown-error" />}
						</Alert>
					</div>
				) : (
					<>
						{source === "file" && (
							<div className={own.note}>
								<T id="npmos.certs.files-hint" />
							</div>
						)}
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter card-table", hostStyles.table)}>
								<thead>
									<tr>
										<th>
											<T id="npmos.certs.name" />
										</th>
										<th>
											<T id="npmos.certs.kind" />
										</th>
										<th>
											<T id="npmos.certs.issuer" />
										</th>
										<th>
											<T id="npmos.certs.expires" />
										</th>
										<th>
											<T id="npmos.certs.used-by" />
										</th>
										<th />
									</tr>
								</thead>
								<tbody>
									{data.items.length === 0 ? (
										<tr>
											<td colSpan={6} className={hostStyles.empty}>
												<T id="npmos.certs.empty" />
											</td>
										</tr>
									) : (
										data.items.map((c) => {
											const items = actions(c);
											return (
												<tr key={c.key}>
													<td className={own.name}>
														<div className={own.title}>
															<span>{c.name || "—"}</span>
															{c.status !== "valid" && (
																<span className={cn("badge", STATUS_TONE[c.status])}>
																	<T id={`npmos.certs.badge.${c.status}`} />
																</span>
															)}
														</div>
														{c.path ? (
															<div className={own.sub}>{c.path}</div>
														) : c.subjects.filter((s) => s !== c.name).length > 0 ? (
															<div className={own.sub}>
																{c.subjects.slice(0, 3).join(", ")}
																{c.subjects.length > 3 && ` +${c.subjects.length - 3}`}
															</div>
														) : null}
													</td>
													<td>
														<div>{kindLabel(c)}</div>
														<div className={own.sub}>
															<T id={`npmos.certs.source.${c.source}`} />
														</div>
													</td>
													<td>{c.issuer || <span className="text-secondary">—</span>}</td>
													<td>
														<Expiry value={c.notAfter} status={c.status} />
													</td>
													<td className={own.used}>
														<UsedBy cert={c} />
													</td>
													<td className="text-end">
														{items.length > 0 && (
															<Dropdown
																floating
																inline
																ariaLabel={t("npmos.pki.actions")}
																triggerClassName="btn btn-sm btn-ghost-secondary"
																trigger={<IconDots size={16} />}
																items={items}
															/>
														)}
													</td>
												</tr>
											);
										})
									)}
								</tbody>
							</table>
						</div>
						<div className={styles.pager}>
							<span>
								<T id="npmos.certs.total" data={{ total: data.total }} />
							</span>
							<div className={styles.pagerButtons}>
								<span>
									<T id="npmos.audit.page" data={{ page: page + 1, pages }} />
								</span>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page === 0}
									aria-label={t("npmos.certs.prev")}
									onClick={() => update({ page: page > 1 ? String(page - 1) : "" })}
								>
									<IconChevronLeft size={16} />
								</button>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page + 1 >= pages}
									aria-label={t("npmos.certs.next")}
									onClick={() => update({ page: String(page + 1) })}
								>
									<IconChevronRight size={16} />
								</button>
							</div>
						</div>
					</>
				)}
			</div>
		</div>
	);
}

export default CertificatesPage;
