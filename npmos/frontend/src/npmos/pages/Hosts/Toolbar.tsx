// Toolbar of the hosts table: search, filters, view options, export/import, "Add", bulk actions.
import {
	IconAdjustmentsHorizontal,
	IconDownload,
	IconFilter,
	IconLayoutColumns,
	IconPlus,
	IconSearch,
	IconUpload,
	IconX,
} from "@tabler/icons-react";
import cn from "classnames";
import { forwardRef } from "react";
import type { AccessList, Certificate } from "src/api/backend";
import { intl, T } from "src/locale";
import { Dropdown } from "../../ui/Dropdown";
import styles from "./Hosts.module.css";
import { activeFilterCount, type FilterKey, type Filters, HOST_TYPES, type HostType, type WafState } from "./rows";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export const COLUMNS = ["type", "target", "tls", "waf", "mtls", "access", "status"] as const;
export type Column = (typeof COLUMNS)[number];
export const COLUMN_LABEL: Record<Column, string> = {
	type: "npmos.hosts.column.type",
	target: "column.destination",
	tls: "column.ssl",
	waf: "WAF",
	mtls: "mTLS",
	access: "column.access",
	status: "column.status",
};
export const columnLabel = (column: Column) =>
	column === "waf" || column === "mtls" ? COLUMN_LABEL[column] : t(COLUMN_LABEL[column]);

export interface View {
	hidden: Column[];
	compact: boolean;
}

export const Search = forwardRef<HTMLInputElement, { value: string; onChange: (value: string) => void }>(
	function Search({ value, onChange }, ref) {
		return (
			<label className={styles.search}>
				<IconSearch size={16} />
				<input
					ref={ref}
					type="search"
					value={value}
					placeholder={t("npmos.hosts.search")}
					aria-label={t("npmos.hosts.search")}
					onChange={(e) => onChange(e.target.value)}
					onKeyDown={(e) => {
						if (e.key === "Escape") onChange("");
					}}
				/>
				<kbd className={styles.kbd}>/</kbd>
			</label>
		);
	},
);

export function FilterButton({ filters, open, onClick }: { filters: Filters; open: boolean; onClick: () => void }) {
	const count = activeFilterCount(filters);
	return (
		<button type="button" className={cn(styles.tool, open && styles.toolOn)} onClick={onClick} aria-expanded={open}>
			<IconFilter size={16} />
			<T id="npmos.hosts.filters" />
			{count > 0 && <span className={styles.count}>{count}</span>}
		</button>
	);
}

interface Option {
	value: string;
	label: string;
}

export function FiltersPanel({
	filters,
	onChange,
	accessLists,
	groups,
	types,
}: {
	filters: Filters;
	onChange: (filters: Filters) => void;
	accessLists: AccessList[];
	groups: string[];
	types: HostType[];
}) {
	const groupsOf: { key: FilterKey; label: string; options: Option[] }[] = [
		{
			key: "type",
			label: t("npmos.hosts.column.type"),
			options: types.map((type) => ({ value: type, label: t(`npmos.hosts.type.${type}`) })),
		},
		{
			key: "status",
			label: t("column.status"),
			options: [
				{ value: "online", label: t("online") },
				{ value: "error", label: t("npmos.hosts.status.error") },
				{ value: "disabled", label: t("disabled") },
			],
		},
		{
			key: "tls",
			label: "TLS",
			options: [
				{ value: "none", label: t("no-tls") },
				{ value: "letsencrypt", label: "Let's Encrypt" },
				{ value: "custom", label: t("certificates.custom") },
				{ value: "expiring", label: t("npmos.hosts.tls.expiring") },
			],
		},
		{
			key: "waf",
			label: "WAF",
			options: (["off", "detect", "prevent"] as WafState[]).map((v) => ({
				value: v,
				label: t(`npmos.hosts.waf.${v}`),
			})),
		},
		{
			key: "mtls",
			label: "mTLS",
			options: ["off", "required", "optional"].map((v) => ({ value: v, label: t(`npmos.hosts.mtls.${v}`) })),
		},
		{
			key: "access",
			label: t("column.access"),
			options: [
				{ value: "public", label: t("access-list.public") },
				...accessLists.map((l) => ({ value: String(l.id), label: l.name })),
			],
		},
		{
			key: "group",
			label: t("proxy-host.directory"),
			options: groups.map((g) => ({ value: g, label: g })),
		},
	];
	const toggle = (key: FilterKey, value: string) => {
		const current = filters[key] as string[];
		const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
		onChange({ ...filters, [key]: next });
	};
	return (
		<div className={styles.filters}>
			{groupsOf
				.filter((g) => g.options.length)
				.map((group) => (
					<div key={group.key} className={styles.filterGroup}>
						<span className={styles.filterLabel}>{group.label}</span>
						<div className={styles.filterOptions}>
							{group.options.map((o) => {
								const on = (filters[group.key] as string[]).includes(o.value);
								return (
									<button
										key={o.value}
										type="button"
										className={cn(styles.filterChip, on && styles.filterChipOn)}
										aria-pressed={on}
										onClick={() => toggle(group.key, o.value)}
									>
										{o.label}
									</button>
								);
							})}
						</div>
					</div>
				))}
			{activeFilterCount(filters) > 0 && (
				<button
					type="button"
					className={styles.reset}
					onClick={() =>
						onChange({
							...filters,
							type: [],
							status: [],
							tls: [],
							waf: [],
							mtls: [],
							access: [],
							group: [],
						})
					}
				>
					<IconX size={14} />
					<T id="npmos.hosts.filters.reset" />
				</button>
			)}
		</div>
	);
}

export function ViewMenu({ view, onChange }: { view: View; onChange: (view: View) => void }) {
	return (
		<Dropdown
			floating
			inline
			ariaLabel={t("npmos.hosts.view")}
			title={t("npmos.hosts.view")}
			triggerClassName={styles.tool}
			trigger={
				<>
					<IconLayoutColumns size={16} />
					<span className={styles.toolText}>
						<T id="npmos.hosts.view" />
					</span>
				</>
			}
			items={[
				...COLUMNS.map((column) => ({
					key: column,
					label: columnLabel(column),
					active: !view.hidden.includes(column),
					onSelect: () =>
						onChange({
							...view,
							hidden: view.hidden.includes(column)
								? view.hidden.filter((c) => c !== column)
								: [...view.hidden, column],
						}),
				})),
				{
					key: "compact",
					divider: true,
					icon: <IconAdjustmentsHorizontal size={16} />,
					label: <T id="npmos.hosts.view.compact" />,
					active: view.compact,
					onSelect: () => onChange({ ...view, compact: !view.compact }),
				},
			]}
		/>
	);
}

export function TransferMenu({
	onExport,
	onImport,
	canImport,
	selected,
}: {
	onExport: (format: "json" | "csv") => void;
	onImport: () => void;
	canImport: boolean;
	selected: number;
}) {
	return (
		<Dropdown
			floating
			inline
			ariaLabel={t("npmos.hosts.transfer")}
			title={t("npmos.hosts.transfer")}
			triggerClassName={styles.tool}
			trigger={
				<>
					<IconDownload size={16} />
					<span className={styles.toolText}>
						<T id="npmos.hosts.transfer" />
					</span>
				</>
			}
			items={[
				{
					key: "json",
					icon: <IconDownload size={16} />,
					label: (
						<T
							id={selected ? "npmos.hosts.export.json-selected" : "npmos.hosts.export.json"}
							data={{ count: selected }}
						/>
					),
					onSelect: () => onExport("json"),
				},
				{
					key: "csv",
					icon: <IconDownload size={16} />,
					label: (
						<T
							id={selected ? "npmos.hosts.export.csv-selected" : "npmos.hosts.export.csv"}
							data={{ count: selected }}
						/>
					),
					onSelect: () => onExport("csv"),
				},
				...(canImport
					? [
							{
								key: "import",
								divider: true,
								icon: <IconUpload size={16} />,
								label: <T id="npmos.hosts.import" />,
								onSelect: onImport,
							},
						]
					: []),
			]}
		/>
	);
}

export function AddMenu({ types, onAdd }: { types: HostType[]; onAdd: (type: HostType) => void }) {
	if (!types.length) return null;
	return (
		<Dropdown
			floating
			inline
			ariaLabel={t("npmos.hosts.add")}
			triggerClassName={cn("btn btn-primary btn-sm", styles.add)}
			trigger={
				<>
					<IconPlus size={16} />
					<T id="npmos.hosts.add" />
				</>
			}
			items={HOST_TYPES.filter((type) => types.includes(type)).map((type) => ({
				key: type,
				label: (
					<span className={styles.option}>
						<T id={`npmos.hosts.type.${type}`} />
						<span className={styles.optionHint}>
							<T id={`npmos.hosts.type.${type}.hint`} />
						</span>
					</span>
				),
				onSelect: () => onAdd(type),
			}))}
		/>
	);
}

export function BulkBar({
	count,
	hasProxy,
	certificates,
	accessLists,
	onClear,
	onToggle,
	onWaf,
	onCertificate,
	onAccess,
	onDelete,
}: {
	count: number;
	hasProxy: boolean;
	certificates: Certificate[];
	accessLists: AccessList[];
	onClear: () => void;
	onToggle: (enabled: boolean) => void;
	onWaf: (waf: WafState) => void;
	onCertificate: (id: number) => void;
	onAccess: (id: number | null) => void;
	onDelete: () => void;
}) {
	return (
		<div className={styles.bulk}>
			<span className={styles.bulkCount}>
				<T id="npmos.hosts.selected" data={{ count }} />
			</span>
			<button type="button" className={styles.tool} onClick={() => onToggle(true)}>
				<T id="action.enable" />
			</button>
			<button type="button" className={styles.tool} onClick={() => onToggle(false)}>
				<T id="action.disable" />
			</button>
			{hasProxy && (
				<Dropdown
					floating
					inline
					ariaLabel="WAF"
					triggerClassName={styles.tool}
					trigger="WAF"
					items={(["off", "detect", "prevent"] as WafState[]).map((v) => ({
						key: v,
						label: <T id={`npmos.hosts.waf.${v}`} />,
						onSelect: () => onWaf(v),
					}))}
				/>
			)}
			<Dropdown
				floating
				inline
				ariaLabel={t("column.ssl")}
				triggerClassName={styles.tool}
				trigger={<T id="npmos.hosts.bulk.certificate" />}
				items={[
					{ key: "none", label: <T id="no-tls" />, onSelect: () => onCertificate(0) },
					...certificates
						.filter((c) => c.provider !== "mtls")
						.map((c, i) => ({
							key: `c${c.id}`,
							divider: i === 0,
							label: <span className={styles.ellipsis}>{c.niceName || c.domainNames.join(", ")}</span>,
							onSelect: () => onCertificate(c.id),
						})),
				]}
			/>
			{hasProxy && accessLists.length > 0 && (
				<Dropdown
					floating
					inline
					ariaLabel={t("column.access")}
					triggerClassName={styles.tool}
					trigger={<T id="column.access" />}
					items={[
						{ key: "public", label: <T id="access-list.public" />, onSelect: () => onAccess(null) },
						...accessLists.map((l, i) => ({
							key: `l${l.id}`,
							divider: i === 0,
							label: l.name,
							onSelect: () => onAccess(l.id as number),
						})),
					]}
				/>
			)}
			<button type="button" className={cn(styles.tool, styles.danger)} onClick={onDelete}>
				<T id="action.delete" />
			</button>
			<button type="button" className={styles.reset} onClick={onClear}>
				<IconX size={14} />
				<T id="npmos.hosts.selection.clear" />
			</button>
		</div>
	);
}
