// Certificates → PKI and mTLS (docs/ROADMAP.md, phase 6; ADR-0009): certificates issued by the
// own CAs as a table (status, expiry, where used, filters, bulk revocation), the CAs (roots, trust
// domains, external ones), templates of certificates and settings (public address for CRLs and
// links, lifetimes).
import { IconDots, IconPlus, IconSearch } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { HasPermission, LoadingPage } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { showConfirmModal } from "../../modals/ConfirmModal";
import {
	deleteCa,
	downloadCert,
	exportCa,
	KEY_TYPES,
	type PkiCa,
	type PkiCert,
	type PkiOverview,
	type PkiSettings,
	saveFile,
	setPkiSettings,
	usePki,
} from "../../pki/api";
import { showCaModal } from "../../pki/CaModal";
import { showIssueModal } from "../../pki/IssueModal";
import { showRevokeModal } from "../../pki/RevokeModal";
import { showSecretModal } from "../../pki/SecretModal";
import { showTemplateModal } from "../../pki/TemplateModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown, type DropdownItem } from "../../ui/Dropdown";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "./Pki.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

type Tab = "certificates" | "cas" | "templates" | "settings";
type StatusFilter = "" | "active" | "expiring" | "expired" | "revoked" | "replaced";

const EXPIRING = 30;

const STATUS_TONE: Record<string, string> = {
	active: "bg-green-lt",
	expiring: "bg-yellow-lt",
	expired: "bg-red-lt",
	revoked: "bg-red-lt",
	replaced: "bg-secondary-lt",
};

const certStatus = (c: PkiCert) => (c.status === "active" && c.daysLeft <= EXPIRING ? "expiring" : c.status);

const run = async (action: () => Promise<unknown>, refresh: () => void, message?: string) => {
	try {
		await action();
		if (message) showSuccess(message);
	} catch (err: any) {
		showError(err.message);
	}
	refresh();
};

function Summary({ data }: { data: PkiOverview }) {
	const counts = { active: 0, expiring: 0, expired: 0, revoked: 0 };
	for (const c of data.certificates) {
		const s = certStatus(c);
		if (s in counts) counts[s as keyof typeof counts]++;
	}
	const hosts = new Set(data.cas.flatMap((ca) => ca.hosts)).size;
	const items: [string, number, string?][] = [
		["npmos.pki.summary.active", counts.active],
		["npmos.pki.summary.expiring", counts.expiring, counts.expiring ? "text-yellow" : undefined],
		["npmos.pki.summary.expired", counts.expired, counts.expired ? "text-red" : undefined],
		["npmos.pki.summary.revoked", counts.revoked],
		["npmos.pki.summary.cas", data.cas.length],
		["npmos.pki.summary.hosts", hosts],
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

function CertificatesTab({ data, refresh }: { data: PkiOverview; refresh: () => void }) {
	const can = useCan();
	const { locale } = useLocaleState();
	const [query, setQuery] = useState("");
	const [status, setStatus] = useState<StatusFilter>("");
	const [caId, setCaId] = useState(0);
	const [profile, setProfile] = useState("");
	const [selected, setSelected] = useState<number[]>([]);
	const caName = (id: number) => data.cas.find((ca) => ca.id === id)?.name ?? `#${id}`;

	const rows = useMemo(() => {
		const q = query.trim().toLowerCase();
		return data.certificates.filter((c) => {
			if (status && certStatus(c) !== status) return false;
			if (caId && c.caId !== caId) return false;
			if (profile && c.profile !== profile) return false;
			if (!q) return true;
			return [
				c.commonName,
				c.serial,
				c.template,
				c.notes,
				...c.sans.dns,
				...c.sans.email,
				...c.sans.ip,
				...c.hosts,
			]
				.join(" ")
				.toLowerCase()
				.includes(q);
		});
	}, [data.certificates, query, status, caId, profile]);

	const selectable = rows.filter((c) => !c.revokedOn);
	const chosen = data.certificates.filter((c) => selected.includes(c.id) && !c.revokedOn);
	const publicUrl = data.settings.publicUrl;
	const compatible = data.settings.p12Compatible;

	const actions = (c: PkiCert): DropdownItem[] => [
		{
			key: "cert",
			label: <T id="npmos.pki.download.cert" />,
			onSelect: () => run(async () => saveFile(await downloadCert(c.id, "cert")), refresh),
		},
		{
			key: "chain",
			label: <T id="npmos.pki.download.fullchain" />,
			onSelect: () => run(async () => saveFile(await downloadCert(c.id, "chain")), refresh),
		},
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
						key: "key",
						label: <T id="npmos.pki.download.key" />,
						onSelect: () => run(async () => saveFile(await downloadCert(c.id, "key")), refresh),
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
		...(can("pki", "revoke") && !c.revokedOn
			? [
					{
						key: "revoke",
						label: <span className="text-danger">{t("npmos.pki.revoke")}</span>,
						onSelect: () => showRevokeModal({ certs: [c], onDone: refresh }),
					},
				]
			: []),
	];

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.filters}>
				<label className={hostStyles.search}>
					<IconSearch size={16} />
					<input
						value={query}
						placeholder={t("npmos.pki.search")}
						aria-label={t("npmos.pki.search")}
						onChange={(e) => setQuery(e.target.value)}
					/>
				</label>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.pki.status")}
					value={status}
					onChange={(e) => setStatus(e.target.value as StatusFilter)}
				>
					<option value="">{t("npmos.pki.status.all")}</option>
					{["active", "expiring", "expired", "revoked", "replaced"].map((s) => (
						<option key={s} value={s}>
							{t(`npmos.pki.status.${s}`)}
						</option>
					))}
				</select>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.pki.issuer")}
					value={caId}
					onChange={(e) => setCaId(Number(e.target.value))}
				>
					<option value={0}>{t("npmos.pki.all-cas")}</option>
					{data.cas
						.filter((ca) => ca.kind === "intermediate")
						.map((ca) => (
							<option key={ca.id} value={ca.id}>
								{ca.name}
							</option>
						))}
				</select>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.pki.profile")}
					value={profile}
					onChange={(e) => setProfile(e.target.value)}
				>
					<option value="">{t("npmos.pki.profile.all")}</option>
					<option value="client">{t("npmos.pki.profile.client")}</option>
					<option value="server">{t("npmos.pki.profile.server")}</option>
				</select>
				{chosen.length > 0 && can("pki", "revoke") && (
					<button
						type="button"
						className="btn btn-sm btn-outline-danger"
						onClick={() =>
							showRevokeModal({
								certs: chosen,
								onDone: () => {
									setSelected([]);
									refresh();
								},
							})
						}
					>
						<T id="npmos.pki.revoke.selected" data={{ count: chosen.length }} />
					</button>
				)}
			</div>
			{rows.length === 0 ? (
				<p className={styles.empty}>
					<T id={data.certificates.length ? "npmos.pki.none-found" : "npmos.pki.none"} />
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
										checked={
											selectable.length > 0 && selectable.every((c) => selected.includes(c.id))
										}
										onChange={(e) =>
											setSelected(e.target.checked ? selectable.map((c) => c.id) : [])
										}
									/>
								</th>
								<th>
									<T id="npmos.pki.name" />
								</th>
								<th>
									<T id="npmos.pki.status" />
								</th>
								<th>
									<T id="npmos.pki.expires" />
								</th>
								<th>
									<T id="npmos.pki.issuer" />
								</th>
								<th>
									<T id="npmos.pki.used" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{rows.map((c) => {
								const s = certStatus(c);
								const sans = [...c.sans.dns, ...c.sans.ip, ...c.sans.email];
								const ca = data.cas.find((x) => x.id === c.caId);
								const used = c.profile === "server" ? c.hosts : (ca?.hosts ?? []);
								return (
									<tr key={c.id}>
										<td>
											<input
												type="checkbox"
												className="form-check-input"
												aria-label={c.commonName}
												disabled={!!c.revokedOn}
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
											<div className="fw-medium">
												{c.commonName}
												<span className="badge bg-secondary-lt ms-2">
													<T id={`npmos.pki.profile.${c.profile}`} />
												</span>
											</div>
											<div className={styles.sub}>
												{[
													c.subject.organizationalUnit,
													c.subject.organization,
													sans.join(", "),
													c.template,
												]
													.filter(Boolean)
													.join(" · ") || c.serial}
											</div>
										</td>
										<td>
											<span className={cn("badge", STATUS_TONE[s])}>
												<T id={`npmos.pki.status.${s}`} />
											</span>
											{c.revokeReason && (
												<div className={styles.sub}>
													{t(`npmos.pki.reason.${c.revokeReason}`)}
												</div>
											)}
										</td>
										<td className="text-nowrap">
											<div>{formatDateTime(c.notAfter, locale)}</div>
											<div className={styles.sub}>
												{c.daysLeft >= 0
													? t("npmos.pki.days-left", { days: c.daysLeft })
													: t("npmos.pki.expired-ago", { days: -c.daysLeft })}
											</div>
										</td>
										<td>{caName(c.caId)}</td>
										<td className={styles.used}>
											{used.length ? (
												<span title={used.join(", ")}>
													{used.slice(0, 2).join(", ")}
													{used.length > 2 && ` +${used.length - 2}`}
												</span>
											) : (
												<span className="text-secondary">—</span>
											)}
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

function CasTab({ data, refresh }: { data: PkiOverview; refresh: () => void }) {
	const can = useCan();
	const { locale } = useLocaleState();
	const manage = can("pki", "manage");
	const ordered = [
		...data.cas
			.filter((ca) => ca.kind === "root")
			.flatMap((root) => [root, ...data.cas.filter((ca) => ca.parentId === root.id)]),
		...data.cas.filter((ca) => ca.kind === "external"),
	];
	const exportItem = (ca: PkiCa, format: "cert" | "chain" | "crl"): DropdownItem => ({
		key: format,
		label: <T id={`npmos.pki.ca.export.${format}`} />,
		onSelect: () => run(async () => saveFile(await exportCa(ca.id, format)), refresh),
	});
	const actions = (ca: PkiCa): DropdownItem[] => [
		exportItem(ca, "cert"),
		...(ca.kind !== "external" ? [exportItem(ca, "chain")] : []),
		...(ca.hasCrl ? [exportItem(ca, "crl")] : []),
		...(ca.hasKey && can("pki", "export_key")
			? [
					{
						key: "key",
						label: <T id="npmos.pki.ca.export.key" />,
						onSelect: () =>
							showSecretModal({
								action: "ca-key",
								objectId: ca.id,
								name: ca.name,
								publicUrl: data.settings.publicUrl,
								compatible: true,
							}),
					},
				]
			: []),
		...(manage && ca.kind === "root" && ca.hasKey
			? [
					{
						key: "domain",
						divider: true,
						label: <T id="npmos.pki.ca.new-domain" />,
						onSelect: () => showCaModal({ data, mode: "intermediate", parentId: ca.id, onDone: refresh }),
					},
				]
			: []),
		...(can("pki", "issue") && ca.kind === "intermediate" && ca.hasKey
			? [
					{
						key: "issue",
						divider: true,
						label: <T id="npmos.pki.issue" />,
						onSelect: () => showIssueModal({ data, preset: { caId: ca.id }, onDone: refresh }),
					},
				]
			: []),
		...(manage && !ca.upstreamCertificateId
			? [
					{
						key: "edit",
						divider: true,
						label: <T id="npmos.pki.ca.edit" />,
						onSelect: () => showCaModal({ data, edit: ca, onDone: refresh }),
					},
					{
						key: "delete",
						label: <span className="text-danger">{t("npmos.pki.ca.delete")}</span>,
						onSelect: () =>
							showConfirmModal({
								tTitle: "npmos.pki.ca.delete",
								tConfirm: "npmos.pki.ca.delete",
								danger: true,
								children: (
									<p>
										<T id="npmos.pki.ca.delete.text" data={{ name: ca.name }} />
									</p>
								),
								onConfirm: async () => {
									await deleteCa(ca.id);
									refresh();
								},
							}),
					},
				]
			: []),
	];
	return (
		<section className={cn("card", styles.card)}>
			{ordered.length === 0 ? (
				<div className={styles.empty}>
					<p className="mb-2">
						<T id="npmos.pki.ca.none" />
					</p>
					{manage && (
						<button
							type="button"
							className="btn btn-primary btn-sm"
							onClick={() => showCaModal({ data, mode: "root", onDone: refresh })}
						>
							<T id="npmos.pki.ca.create-root" />
						</button>
					)}
				</div>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.pki.ca.name" />
								</th>
								<th>
									<T id="npmos.pki.expires" />
								</th>
								<th>
									<T id="npmos.pki.ca.certificates" />
								</th>
								<th>
									<T id="npmos.pki.ca.crl" />
								</th>
								<th>
									<T id="npmos.pki.used" />
								</th>
								<th className="w-1" />
							</tr>
						</thead>
						<tbody>
							{ordered.map((ca) => (
								<tr key={ca.id}>
									<td className={ca.kind === "intermediate" ? styles.child : undefined}>
										<div className="fw-medium">
											{ca.name}
											<span className="badge bg-secondary-lt ms-2">
												<T id={`npmos.pki.ca.kind.${ca.kind}`} />
											</span>
											{ca.upstreamCertificateId && (
												<span className="badge bg-azure-lt ms-1">
													<T id="npmos.pki.ca.from-npmplus" />
												</span>
											)}
										</div>
										<div className={cn(styles.sub, "font-monospace")}>{ca.subjectDn}</div>
									</td>
									<td className="text-nowrap">{formatDateTime(ca.notAfter, locale)}</td>
									<td className="text-nowrap">
										{ca.kind === "intermediate"
											? t("npmos.pki.ca.counts", { active: ca.active, revoked: ca.revoked })
											: "—"}
									</td>
									<td className="text-nowrap">
										{ca.crlNextUpdate ? (
											<span title={t("npmos.pki.ca.crl.number", { number: ca.crlNumber })}>
												<T
													id="npmos.pki.ca.crl.until"
													data={{ time: formatDateTime(ca.crlNextUpdate, locale) }}
												/>
											</span>
										) : (
											<span className="text-secondary">
												<T id="npmos.pki.ca.crl.none" />
											</span>
										)}
									</td>
									<td className={styles.used}>
										{ca.hosts.length ? (
											<span title={ca.hosts.join(", ")}>
												{ca.hosts.slice(0, 2).join(", ")}
												{ca.hosts.length > 2 && ` +${ca.hosts.length - 2}`}
											</span>
										) : (
											<span className="text-secondary">—</span>
										)}
									</td>
									<td>
										<Dropdown
											floating
											inline
											ariaLabel={t("npmos.pki.actions")}
											triggerClassName="btn btn-sm btn-ghost-secondary"
											trigger={<IconDots size={16} />}
											items={actions(ca)}
										/>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

function TemplatesTab({ data, refresh }: { data: PkiOverview; refresh: () => void }) {
	const can = useCan();
	const manage = can("pki", "manage");
	const caName = (id: number | null) =>
		id ? (data.cas.find((ca) => ca.id === id)?.name ?? `#${id}`) : t("npmos.pki.template.any-ca");
	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<p className="text-secondary small mb-0">
					<T id="npmos.pki.templates.hint" />
				</p>
				{manage && (
					<button
						type="button"
						className="btn btn-sm"
						onClick={() => showTemplateModal({ data, onDone: refresh })}
					>
						<IconPlus size={14} className="me-1" />
						<T id="npmos.pki.template.add" />
					</button>
				)}
			</div>
			{data.settings.templates.length === 0 ? (
				<p className={styles.empty}>
					<T id="npmos.pki.templates.none" />
				</p>
			) : (
				<ul className={styles.list}>
					{data.settings.templates.map((x) => (
						<li className={styles.item} key={x.id}>
							<div className="flex-fill">
								<div className="fw-medium">{x.name}</div>
								<div className={styles.sub}>
									{[
										t(`npmos.pki.profile.${x.profile}`),
										caName(x.caId),
										t("npmos.pki.days-value", { days: x.days }),
										t(`npmos.pki.key-type.${x.keyType}`),
										x.subject.organization,
										x.subject.organizationalUnit,
									]
										.filter(Boolean)
										.join(" · ")}
								</div>
							</div>
							{can("pki", "issue") && (
								<button
									type="button"
									className="btn btn-sm"
									onClick={() =>
										showIssueModal({ data, preset: { templateId: x.id }, onDone: refresh })
									}
								>
									<T id="npmos.pki.issue" />
								</button>
							)}
							{manage && (
								<Dropdown
									floating
									inline
									ariaLabel={t("npmos.pki.actions")}
									triggerClassName="btn btn-sm btn-ghost-secondary"
									trigger={<IconDots size={16} />}
									items={[
										{
											key: "edit",
											label: <T id="npmos.pki.template.edit" />,
											onSelect: () => showTemplateModal({ data, template: x, onDone: refresh }),
										},
										{
											key: "delete",
											label: (
												<span className="text-danger">{t("npmos.pki.template.delete")}</span>
											),
											onSelect: () =>
												run(
													() =>
														setPkiSettings({
															...data.settings,
															templates: data.settings.templates.filter(
																(y) => y.id !== x.id,
															),
														}),
													refresh,
												),
										},
									]}
								/>
							)}
						</li>
					))}
				</ul>
			)}
		</section>
	);
}

function SettingsTab({ data, refresh }: { data: PkiOverview; refresh: () => void }) {
	const can = useCan();
	const manage = can("pki", "manage");
	const [value, setValue] = useState<PkiSettings>(data.settings);
	const [busy, setBusy] = useState(false);
	const number = (key: "crlDays" | "clientDays" | "serverDays") => (
		<div className="col-md-4 mb-3">
			<label className="form-label" htmlFor={`pki-set-${key}`}>
				<T id={`npmos.pki.settings.${key}`} />
			</label>
			<input
				id={`pki-set-${key}`}
				type="number"
				min={1}
				className="form-control"
				disabled={!manage}
				value={value[key]}
				onChange={(e) => setValue({ ...value, [key]: Number(e.target.value) })}
			/>
		</div>
	);
	return (
		<section className={cn("card", styles.card)}>
			<div className="mb-3">
				<label className="form-label" htmlFor="pki-set-url">
					<T id="npmos.pki.settings.public-url" />
				</label>
				<input
					id="pki-set-url"
					className="form-control"
					placeholder={t("npmos.pki.settings.public-url.placeholder")}
					disabled={!manage}
					value={value.publicUrl}
					onChange={(e) => setValue({ ...value, publicUrl: e.target.value.trim() })}
				/>
				<div className="form-hint">
					<T id="npmos.pki.settings.public-url.hint" />
				</div>
			</div>
			<div className="row">
				{number("clientDays")}
				{number("serverDays")}
				{number("crlDays")}
			</div>
			<div className="row">
				<div className="col-md-4 mb-3">
					<label className="form-label" htmlFor="pki-set-key">
						<T id="npmos.pki.key-type" />
					</label>
					<select
						id="pki-set-key"
						className="form-select"
						disabled={!manage}
						value={value.keyType}
						onChange={(e) => setValue({ ...value, keyType: e.target.value })}
					>
						{KEY_TYPES.map((k) => (
							<option key={k} value={k}>
								{t(`npmos.pki.key-type.${k}`)}
							</option>
						))}
					</select>
				</div>
				<div className="col-md-8 mb-3 d-flex align-items-end">
					<label className="form-check mb-2">
						<input
							type="checkbox"
							className="form-check-input"
							disabled={!manage}
							checked={value.p12Compatible}
							onChange={(e) => setValue({ ...value, p12Compatible: e.target.checked })}
						/>
						<span className="form-check-label">
							<T id="npmos.pki.p12.compatible" />
						</span>
						<span className="form-check-description">
							<T id="npmos.pki.p12.compatible.hint" />
						</span>
					</label>
				</div>
			</div>
			{manage && (
				<div>
					<button
						type="button"
						className="btn btn-primary"
						disabled={busy}
						onClick={async () => {
							setBusy(true);
							await run(() => setPkiSettings(value), refresh, t("npmos.pki.settings.saved"));
							setBusy(false);
						}}
					>
						<T id="save" />
					</button>
				</div>
			)}
		</section>
	);
}

function PkiPage() {
	const can = useCan();
	const queryClient = useQueryClient();
	// ?tab=cas opens a tab (links from the registry of certificates)
	const [tab, setTab] = useState<Tab>(() => {
		const asked = new URLSearchParams(window.location.search).get("tab");
		return asked === "cas" || asked === "templates" || asked === "settings" ? asked : "certificates";
	});
	const { data, isLoading, isError, error } = usePki({ refetchInterval: 30000 });
	const refresh = () => {
		queryClient.invalidateQueries({ queryKey: ["npmos-pki"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-mtls-hosts"] });
	};

	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;

	const hasIssuer = data.cas.some((ca) => ca.kind === "intermediate" && ca.hasKey);

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.pki" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.pki.subtitle" />
					</p>
				</div>
				<div className={hostStyles.toolbar}>
					{can("pki", "manage") && (
						<button
							type="button"
							className={hostStyles.tool}
							onClick={() => showCaModal({ data, onDone: refresh })}
						>
							<IconPlus size={16} />
							<span className={hostStyles.toolText}>
								<T id="npmos.pki.ca.add" />
							</span>
						</button>
					)}
					{can("pki", "issue") && hasIssuer && (
						<button
							type="button"
							className={cn("btn btn-primary btn-sm", hostStyles.add)}
							onClick={() => showIssueModal({ data, onDone: refresh })}
						>
							<IconPlus size={16} />
							<T id="npmos.pki.issue" />
						</button>
					)}
				</div>
			</div>

			{!hasIssuer && (
				<Alert variant="info" className="mb-0">
					<T id={data.cas.some((ca) => ca.kind === "root") ? "npmos.pki.start.domain" : "npmos.pki.start"} />
				</Alert>
			)}

			<Summary data={data} />

			<ul className="nav nav-tabs flex-nowrap overflow-auto">
				{(["certificates", "cas", "templates", "settings"] as Tab[]).map((x) => (
					<li className="nav-item" key={x}>
						<button
							type="button"
							className={cn("nav-link text-nowrap", { active: tab === x })}
							onClick={() => setTab(x)}
						>
							<T id={`npmos.pki.tab.${x}`} />
						</button>
					</li>
				))}
			</ul>

			{tab === "certificates" && <CertificatesTab data={data} refresh={refresh} />}
			{tab === "cas" && <CasTab data={data} refresh={refresh} />}
			{tab === "templates" && <TemplatesTab data={data} refresh={refresh} />}
			{tab === "settings" && <SettingsTab data={data} refresh={refresh} />}
		</div>
	);
}

const Pki = () => (
	<HasPermission rbac="pki" permission={VIEW} pageLoading loadingNoLogo>
		<PkiPage />
	</HasPermission>
);

export default Pki;
