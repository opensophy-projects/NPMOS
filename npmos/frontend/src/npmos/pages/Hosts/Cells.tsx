// Cells of the hosts table with quick actions (as the proxy status of a DNS record in Cloudflare).
import {
	IconCopy,
	IconCopyPlus,
	IconDots,
	IconExternalLink,
	IconHistory,
	IconPencil,
	IconPlugConnected,
	IconTrash,
} from "@tabler/icons-react";
import cn from "classnames";
import type { AccessList, Certificate } from "src/api/backend";
import { intl, T } from "src/locale";
import { showReachabilityModal } from "src/modals";
import { Dropdown, type DropdownItem } from "../../ui/Dropdown";
import { dateTime, timeAgo } from "../../ui/time";
import styles from "./Hosts.module.css";
import { EXPIRING_DAYS, type HostRow, type MtlsState, type WafState } from "./rows";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

/** what a cell may change and how (filled by the page) */
export interface CellContext {
	canManage: (row: HostRow) => boolean;
	certificates: Certificate[];
	accessLists: AccessList[];
	edit: (row: HostRow) => void;
	remove: (row: HostRow) => void;
	toggle: (row: HostRow, enabled: boolean) => void;
	setWaf: (row: HostRow, waf: WafState) => void;
	setMtls: (row: HostRow, caId: number, mode: MtlsState) => void;
	setAccess: (row: HostRow, listId: number | null) => void;
	setCertificate: (row: HostRow, certificateId: number | "new") => void;
	openCertificates: () => void;
	/** opens the create form filled from the host */
	duplicate: (row: HostRow) => void;
	/** who changed the host and when */
	history: (row: HostRow) => void;
}

/** a chip that opens the menu (hover shows the accent border) */
function Trigger({ children, tone }: { children: React.ReactNode; tone?: string }) {
	return <span className={cn(styles.chip, styles.chipButton, tone && styles[tone])}>{children}</span>;
}

export function NameCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	const [first, ...rest] = row.names;
	const tags = row.protocols.length > 0 || row.group;
	return (
		<div className={styles.name}>
			<div className={styles.nameLine}>
				<button
					type="button"
					className={styles.nameLink}
					onClick={() => ctx.edit(row)}
					title={row.names.join("\n")}
				>
					{first}
				</button>
				{rest.length > 0 && (
					<span className={styles.more} title={rest.join("\n")}>
						+{rest.length}
					</span>
				)}
			</div>
			{tags && (
				<div className={styles.nameLine}>
					{row.protocols.map((p) => (
						<span key={p} className={styles.proto}>
							{p}
						</span>
					))}
					{row.group && (
						<span className={styles.group} title={t("proxy-host.directory")}>
							{row.group}
						</span>
					)}
				</div>
			)}
		</div>
	);
}

export function TlsCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	const days = row.expiresInDays;
	const tone = days === null ? undefined : days < 0 ? "alert" : days < EXPIRING_DAYS ? "warning" : undefined;
	const label =
		row.tls === "none"
			? t("no-tls")
			: row.tls === "letsencrypt"
				? "Let's Encrypt"
				: row.certificate?.niceName || t("certificates.custom");
	const content = (
		<span className={styles.tls}>
			<span className={styles.tlsName}>{label}</span>
			{days !== null && (
				<span className={cn(styles.days, tone && styles[tone])}>
					{days < 0 ? t("npmos.hosts.tls.expired") : t("npmos.hosts.tls.days", { days })}
				</span>
			)}
		</span>
	);
	if (!ctx.canManage(row)) return content;
	const hostCerts = ctx.certificates.filter((c) => c.provider !== "mtls");
	const items: DropdownItem[] = [
		...(row.type !== "stream"
			? [
					{
						key: "new",
						label: <T id="npmos.hosts.tls.issue" />,
						onSelect: () => ctx.setCertificate(row, "new"),
					},
				]
			: []),
		{
			key: "none",
			divider: row.type !== "stream",
			label: <T id="no-tls" />,
			active: row.tls === "none",
			onSelect: () => ctx.setCertificate(row, 0),
		},
		...hostCerts.map((c) => ({
			key: `c${c.id}`,
			label: <span className={styles.ellipsis}>{c.niceName || c.domainNames.join(", ")}</span>,
			active: row.certificate?.id === c.id,
			onSelect: () => ctx.setCertificate(row, c.id),
		})),
	];
	return (
		<Dropdown
			floating
			inline
			ariaLabel={t("column.ssl")}
			triggerClassName={styles.trigger}
			trigger={<Trigger>{content}</Trigger>}
			items={items}
		/>
	);
}

const WAF_LABEL: Record<WafState, string> = {
	off: "npmos.hosts.waf.off",
	detect: "npmos.hosts.waf.detect",
	prevent: "npmos.hosts.waf.prevent",
};
const WAF_TONE: Record<WafState, string | undefined> = { off: undefined, detect: "warning", prevent: "accent" };

export function WafCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	if (row.waf === null) return <span className={styles.none}>—</span>;
	const waf = row.waf;
	const chip = <T id={WAF_LABEL[waf]} />;
	if (!ctx.canManage(row)) return <span className={cn(styles.chip, styles[WAF_TONE[waf] ?? ""])}>{chip}</span>;
	return (
		<Dropdown
			floating
			inline
			ariaLabel="WAF"
			triggerClassName={styles.trigger}
			trigger={<Trigger tone={WAF_TONE[waf]}>{chip}</Trigger>}
			items={(["off", "detect", "prevent"] as WafState[]).map((value) => ({
				key: value,
				label: (
					<span className={styles.option}>
						<T id={WAF_LABEL[value]} />
						<span className={styles.optionHint}>
							<T id={`${WAF_LABEL[value]}.hint`} />
						</span>
					</span>
				),
				active: value === waf,
				onSelect: () => ctx.setWaf(row, value),
			}))}
		/>
	);
}

export function MtlsCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	if (row.tls === "none") {
		return (
			<span className={styles.none} title={t("npmos.hosts.mtls.needs-tls")}>
				—
			</span>
		);
	}
	const cas = ctx.certificates.filter((c) => c.provider === "mtls");
	const ca = cas.find((c) => c.id === row.mtlsCaId);
	const chip = row.mtls === "off" ? <T id="npmos.hosts.mtls.off" /> : <T id={`npmos.hosts.mtls.${row.mtls}`} />;
	const tone = row.mtls === "off" ? undefined : "accent";
	const title = ca ? t("npmos.hosts.mtls.ca", { name: ca.niceName }) : undefined;
	if (!ctx.canManage(row)) {
		return (
			<span className={cn(styles.chip, tone && styles[tone])} title={title}>
				{chip}
			</span>
		);
	}
	const mode: MtlsState = row.mtls === "off" ? "required" : row.mtls;
	const items: DropdownItem[] = [
		{
			key: "off",
			label: <T id="npmos.hosts.mtls.off" />,
			active: row.mtls === "off",
			onSelect: () => ctx.setMtls(row, 0, "off"),
		},
		...cas.map((c, i) => ({
			key: `ca${c.id}`,
			divider: i === 0,
			label: <span className={styles.ellipsis}>{t("npmos.hosts.mtls.ca", { name: c.niceName })}</span>,
			active: row.mtlsCaId === c.id,
			onSelect: () => ctx.setMtls(row, c.id, mode),
		})),
		...(cas.length
			? (["required", "optional"] as MtlsState[]).map((value, i) => ({
					key: value,
					divider: i === 0,
					label: (
						<span className={styles.option}>
							<T id={`npmos.hosts.mtls.${value}`} />
							<span className={styles.optionHint}>
								<T id={`npmos.hosts.mtls.${value}.hint`} />
							</span>
						</span>
					),
					active: row.mtls === value,
					disabled: row.mtls === "off",
					onSelect: () => ctx.setMtls(row, row.mtlsCaId, value),
				}))
			: [
					{
						key: "no-ca",
						divider: true,
						label: <T id="npmos.hosts.mtls.no-ca" />,
						onSelect: ctx.openCertificates,
					},
				]),
	];
	return (
		<Dropdown
			floating
			inline
			ariaLabel="mTLS"
			title={title}
			triggerClassName={styles.trigger}
			trigger={<Trigger tone={tone}>{chip}</Trigger>}
			items={items}
		/>
	);
}

export function AccessCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	if (row.accessPublic === null) return <span className={styles.none}>—</span>;
	const names = row.accessListIds
		.map((id) => ctx.accessLists.find((l) => l.id === id)?.name)
		.filter(Boolean)
		.join(", ");
	const chip = row.accessPublic ? (
		<T id="access-list.public" />
	) : (
		<span className={styles.ellipsis}>{names || "…"}</span>
	);
	if (!ctx.canManage(row) || !ctx.accessLists.length) return <span className={styles.chip}>{chip}</span>;
	return (
		<Dropdown
			floating
			inline
			ariaLabel={t("column.access")}
			triggerClassName={styles.trigger}
			trigger={<Trigger>{chip}</Trigger>}
			items={[
				{
					key: "public",
					label: <T id="access-list.public" />,
					active: row.accessPublic,
					onSelect: () => ctx.setAccess(row, null),
				},
				...ctx.accessLists.map((list, i) => ({
					key: `l${list.id}`,
					divider: i === 0,
					label: <span className={styles.ellipsis}>{list.name}</span>,
					active: !row.accessPublic && row.accessListIds.length === 1 && row.accessListIds[0] === list.id,
					onSelect: () => ctx.setAccess(row, list.id as number),
				})),
			]}
		/>
	);
}

export function TargetCell({ row }: { row: HostRow }) {
	if (!row.target) return <span className={styles.target}>—</span>;
	const title = row.upstream === "down" ? `${row.target}\n${row.upstreamErrors.join("\n")}` : row.target;
	return (
		<span className={styles.targetLine} title={title}>
			{row.upstream && (
				<span
					className={cn(styles.dot, row.upstream === "ok" ? styles["dot-online"] : styles["dot-error"])}
					role="img"
					aria-label={t(`npmos.hosts.upstream.${row.upstream}`)}
				/>
			)}
			<span className={styles.target}>{row.target}</span>
		</span>
	);
}

/** when the host was changed last and by whom; opens the history */
export function ChangedCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	const change = row.change;
	if (!change) return <span className={styles.muted}>—</span>;
	return (
		<button
			type="button"
			className={styles.changed}
			title={dateTime(change.createdOn)}
			onClick={() => ctx.history(row)}
		>
			<span>{timeAgo(change.createdOn, Date.now(), "narrow")}</span>
			<span className={styles.changedBy}>{change.user?.name ?? t("npmos.hosts.history.system")}</span>
		</button>
	);
}

export function StatusCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	const label =
		row.status === "error" ? "npmos.hosts.status.error" : row.status === "disabled" ? "disabled" : "online";
	return (
		<label className={styles.status} title={row.error || t(label)}>
			<span className="form-check form-switch m-0">
				<input
					type="checkbox"
					className="form-check-input"
					checked={row.enabled}
					disabled={!ctx.canManage(row)}
					aria-label={t(row.enabled ? "action.disable" : "action.enable")}
					onChange={(e) => ctx.toggle(row, e.target.checked)}
				/>
			</span>
			<span className={cn(styles.dot, styles[`dot-${row.status}`])} title={row.error || t(label)} />
		</label>
	);
}

export function ActionsCell({ row, ctx }: { row: HostRow; ctx: CellContext }) {
	const web = row.type !== "stream";
	const items: DropdownItem[] = [
		{
			key: "edit",
			icon: <IconPencil size={16} />,
			label: <T id="action.edit" />,
			onSelect: () => ctx.edit(row),
		},
		...(ctx.canManage(row)
			? [
					{
						key: "duplicate",
						icon: <IconCopyPlus size={16} />,
						label: <T id="npmos.hosts.duplicate" />,
						onSelect: () => ctx.duplicate(row),
					},
				]
			: []),
		{
			key: "history",
			icon: <IconHistory size={16} />,
			label: <T id="npmos.hosts.history" />,
			onSelect: () => ctx.history(row),
		},
		...(web
			? [
					{
						key: "open",
						icon: <IconExternalLink size={16} />,
						label: <T id="npmos.hosts.open-site" />,
						onSelect: () =>
							window.open(
								`${row.tls === "none" ? "http" : "https"}://${row.names[0]}`,
								"_blank",
								"noopener",
							),
					},
					{
						key: "copy",
						icon: <IconCopy size={16} />,
						label: <T id="npmos.hosts.copy-domain" />,
						onSelect: () => navigator.clipboard?.writeText(row.names.join(" ")),
					},
					{
						key: "reach",
						icon: <IconPlugConnected size={16} />,
						label: <T id="npmos.hosts.reachability" />,
						onSelect: () => showReachabilityModal(row.names),
					},
				]
			: []),
		...(ctx.canManage(row)
			? [
					{
						key: "delete",
						divider: true,
						icon: <IconTrash size={16} />,
						label: <T id="action.delete" />,
						onSelect: () => ctx.remove(row),
					},
				]
			: []),
	];
	return (
		<Dropdown
			floating
			inline
			ariaLabel={t("npmos.hosts.actions")}
			triggerClassName={styles.iconTrigger}
			trigger={<IconDots size={18} />}
			items={items}
		/>
	);
}
