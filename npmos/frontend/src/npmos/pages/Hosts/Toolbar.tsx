// Toolbar of the hosts table as in the Cloudflare DNS page: search, filters (field, operator,
// value), display options, export/import, "Add", active filters and bulk actions.
import {
	IconCheck,
	IconDownload,
	IconFilter,
	IconPlus,
	IconSettings,
	IconTrash,
	IconUpload,
	IconX,
} from "@tabler/icons-react";
import cn from "classnames";
import { forwardRef, useState } from "react";
import type { AccessList, Certificate } from "src/api/backend";
import { intl, T } from "src/locale";
import { Dropdown } from "../../ui/Dropdown";
import { Popover } from "../../ui/Popover";
import { SearchField } from "../../ui/SearchField";
import styles from "./Hosts.module.css";
import {
	FILTER_FIELDS,
	type FilterField,
	type FilterOp,
	type FilterRule,
	type Filters,
	HOST_TYPES,
	type HostType,
	isTextField,
	opsFor,
	type WafState,
} from "./rows";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export const COLUMNS = [
	"type",
	"target",
	"tls",
	"waf",
	"attacks",
	"crowdsec",
	"mtls",
	"access",
	"status",
	"changed",
] as const;
export type Column = (typeof COLUMNS)[number];
export const COLUMN_LABEL: Record<Column, string> = {
	type: "npmos.hosts.column.type",
	target: "column.destination",
	tls: "column.ssl",
	waf: "WAF",
	attacks: "npmos.hosts.column.attacks",
	crowdsec: "CrowdSec",
	mtls: "mTLS",
	access: "column.access",
	status: "column.status",
	changed: "npmos.hosts.column.changed",
};
export const columnLabel = (column: Column) =>
	column === "waf" || column === "mtls" || column === "crowdsec" ? COLUMN_LABEL[column] : t(COLUMN_LABEL[column]);

export interface View {
	hidden: Column[];
	compact: boolean;
}
/** "Changed", "Attacks 24 h" and "CrowdSec" are shown on request: the table should fit a laptop screen */
export const DEFAULT_VIEW: View = { hidden: ["changed", "attacks", "crowdsec"], compact: false };

/** search field above the table, "/" focuses it */
export const Search = forwardRef<HTMLInputElement, { value: string; onChange: (value: string) => void }>(
	function Search({ value, onChange }, ref) {
		return (
			<SearchField ref={ref} value={value} onChange={onChange} placeholder={t("npmos.hosts.search")} hotkey="/" />
		);
	},
);

// ---- filters ----

export interface FilterOptions {
	accessLists: AccessList[];
	groups: string[];
	types: HostType[];
}

const FIELD_LABEL: Record<FilterField, string> = {
	name: "column.name",
	type: "npmos.hosts.column.type",
	target: "column.destination",
	status: "column.status",
	tls: "column.ssl",
	waf: "WAF",
	mtls: "mTLS",
	access: "column.access",
	upstream: "npmos.hosts.upstream",
	group: "proxy-host.directory",
};
const fieldLabel = (field: FilterField) =>
	field === "waf" || field === "mtls" ? FIELD_LABEL[field] : t(FIELD_LABEL[field]);

/** values of a list field with their labels */
export function fieldValues(field: FilterField, options: FilterOptions): { value: string; label: string }[] {
	switch (field) {
		case "type":
			return options.types.map((type) => ({ value: type, label: t(`npmos.hosts.type.${type}`) }));
		case "status":
			return [
				{ value: "online", label: t("online") },
				{ value: "error", label: t("npmos.hosts.status.error") },
				{ value: "disabled", label: t("disabled") },
			];
		case "tls":
			return [
				{ value: "none", label: t("no-tls") },
				{ value: "letsencrypt", label: "Let's Encrypt" },
				{ value: "custom", label: t("certificates.custom") },
				{ value: "expiring", label: t("npmos.hosts.tls.expiring") },
			];
		case "waf":
			return (["off", "detect", "prevent"] as WafState[]).map((v) => ({
				value: v,
				label: t(`npmos.hosts.waf.${v}`),
			}));
		case "mtls":
			return ["off", "required", "optional"].map((v) => ({ value: v, label: t(`npmos.hosts.mtls.${v}`) }));
		case "access":
			return [
				{ value: "public", label: t("access-list.public") },
				...options.accessLists.map((l) => ({ value: String(l.id), label: l.name })),
			];
		case "upstream":
			return ["ok", "down"].map((v) => ({ value: v, label: t(`npmos.hosts.upstream.${v}`) }));
		case "group":
			return options.groups.map((g) => ({ value: g, label: g }));
		default:
			return [];
	}
}

const valueLabel = (rule: FilterRule, options: FilterOptions) =>
	isTextField(rule.field)
		? `«${rule.value}»`
		: (fieldValues(rule.field, options).find((v) => v.value === rule.value)?.label ?? rule.value);

const newRule = (field: FilterField = "name"): FilterRule => ({ field, op: opsFor(field)[0], value: "" });

function FilterEditor({
	filters,
	options,
	onApply,
}: {
	filters: Filters;
	options: FilterOptions;
	onApply: (rules: FilterRule[]) => void;
}) {
	const [rules, setRules] = useState<FilterRule[]>(() => (filters.rules.length ? filters.rules : [newRule()]));
	const change = (index: number, patch: Partial<FilterRule>) =>
		setRules((list) =>
			list.map((rule, i) => {
				if (i !== index) return rule;
				const next = { ...rule, ...patch };
				// another field: its own operators and values
				if (patch.field && patch.field !== rule.field) {
					next.op = opsFor(patch.field)[0];
					next.value = isTextField(patch.field) ? "" : (fieldValues(patch.field, options)[0]?.value ?? "");
				}
				return next;
			}),
		);
	const apply = () => onApply(rules.filter((r) => r.value.trim()));
	return (
		<form
			onSubmit={(e) => {
				e.preventDefault();
				apply();
			}}
		>
			<div className={styles.rules}>
				{rules.map((rule, index) => {
					const values = fieldValues(rule.field, options);
					return (
						<div key={index} className={styles.rule}>
							<select
								className="form-select form-select-sm"
								aria-label={t("npmos.hosts.filter.field")}
								value={rule.field}
								onChange={(e) => change(index, { field: e.target.value as FilterField })}
							>
								{FILTER_FIELDS.map((field) => (
									<option key={field} value={field}>
										{fieldLabel(field)}
									</option>
								))}
							</select>
							<select
								className="form-select form-select-sm"
								aria-label={t("npmos.hosts.filter.operator")}
								value={rule.op}
								onChange={(e) => change(index, { op: e.target.value as FilterOp })}
							>
								{opsFor(rule.field).map((op) => (
									<option key={op} value={op}>
										{t(`npmos.hosts.filter.op.${op}`)}
									</option>
								))}
							</select>
							{isTextField(rule.field) ? (
								<input
									className="form-control form-control-sm"
									aria-label={t("npmos.hosts.filter.value")}
									placeholder={t(
										rule.field === "name"
											? "npmos.hosts.filter.name-placeholder"
											: "npmos.hosts.filter.target-placeholder",
									)}
									value={rule.value}
									onChange={(e) => change(index, { value: e.target.value })}
								/>
							) : (
								<select
									className="form-select form-select-sm"
									aria-label={t("npmos.hosts.filter.value")}
									value={rule.value}
									onChange={(e) => change(index, { value: e.target.value })}
								>
									{!rule.value && <option value="">—</option>}
									{values.map((v) => (
										<option key={v.value} value={v.value}>
											{v.label}
										</option>
									))}
								</select>
							)}
							<button
								type="button"
								className={styles.ruleDelete}
								aria-label={t("npmos.hosts.filter.remove")}
								onClick={() =>
									setRules((list) =>
										list.length > 1 ? list.filter((_, i) => i !== index) : [newRule()],
									)
								}
							>
								<IconTrash size={16} />
							</button>
						</div>
					);
				})}
			</div>
			<div className={styles.rulesFoot}>
				<button
					type="button"
					className={styles.addRule}
					onClick={() => setRules((list) => [...list, newRule()])}
				>
					<IconPlus size={16} />
					<T id="npmos.hosts.filter.add" />
				</button>
				<span className={styles.hint}>
					<T id="npmos.hosts.filter.enter" />
				</span>
				<button type="submit" className="btn btn-primary btn-sm">
					<T id="npmos.hosts.filter.apply" />
				</button>
			</div>
		</form>
	);
}

export function FiltersPopover({
	filters,
	options,
	onChange,
}: {
	filters: Filters;
	options: FilterOptions;
	onChange: (rules: FilterRule[]) => void;
}) {
	const count = filters.rules.length;
	return (
		<Popover
			ariaLabel={t("npmos.hosts.filters")}
			title={<T id="npmos.hosts.filters" />}
			width="40rem"
			triggerClassName={cn(styles.tool, count > 0 && styles.toolOn)}
			activeClassName={styles.toolOn}
			trigger={
				<>
					<IconFilter size={16} />
					<span className={styles.toolText}>
						<T id="npmos.hosts.filters" />
					</span>
					{count > 0 && <span className={styles.count}>{count}</span>}
				</>
			}
		>
			{(close) => (
				<FilterEditor
					filters={filters}
					options={options}
					onApply={(rules) => {
						onChange(rules);
						close();
					}}
				/>
			)}
		</Popover>
	);
}

/** applied filters as chips under the toolbar */
export function ActiveFilters({
	filters,
	options,
	onChange,
}: {
	filters: Filters;
	options: FilterOptions;
	onChange: (rules: FilterRule[]) => void;
}) {
	if (!filters.rules.length) return null;
	return (
		<div className={styles.active}>
			{filters.rules.map((rule, index) => (
				<span key={`${rule.field}:${rule.op}:${rule.value}`} className={styles.activeChip}>
					<span className={styles.activeField}>{fieldLabel(rule.field)}</span>
					<span className={styles.activeOp}>{t(`npmos.hosts.filter.op.${rule.op}`)}</span>
					{valueLabel(rule, options)}
					<button
						type="button"
						aria-label={t("npmos.hosts.filter.remove")}
						onClick={() => onChange(filters.rules.filter((_, i) => i !== index))}
					>
						<IconX size={12} />
					</button>
				</span>
			))}
			<button type="button" className={styles.reset} onClick={() => onChange([])}>
				<T id="npmos.hosts.filters.reset" />
			</button>
		</div>
	);
}

// ---- display options ----

function Check({ on, label, onClick }: { on: boolean; label: React.ReactNode; onClick: () => void }) {
	return (
		<button type="button" role="menuitemcheckbox" aria-checked={on} className={styles.checkItem} onClick={onClick}>
			<span className={styles.checkMark}>{on && <IconCheck size={16} />}</span>
			{label}
		</button>
	);
}

export function ViewPopover({ view, onChange }: { view: View; onChange: (view: View) => void }) {
	const changed = view.hidden.length > 0 || view.compact;
	return (
		<Popover
			ariaLabel={t("npmos.hosts.view")}
			title={<T id="npmos.hosts.view.columns" />}
			titleAction={
				<button
					type="button"
					className={styles.reset}
					disabled={!changed}
					onClick={() => onChange(DEFAULT_VIEW)}
				>
					<T id="npmos.hosts.view.reset" />
				</button>
			}
			width="16rem"
			triggerClassName={styles.tool}
			activeClassName={styles.toolOn}
			trigger={
				<>
					<IconSettings size={16} />
					<span className={styles.toolText}>
						<T id="npmos.hosts.view" />
					</span>
				</>
			}
		>
			{() => (
				<div className={styles.checks}>
					<Check on label={<T id="column.name" />} onClick={() => undefined} />
					{COLUMNS.map((column) => (
						<Check
							key={column}
							on={!view.hidden.includes(column)}
							label={columnLabel(column)}
							onClick={() =>
								onChange({
									...view,
									hidden: view.hidden.includes(column)
										? view.hidden.filter((c) => c !== column)
										: [...view.hidden, column],
								})
							}
						/>
					))}
					<div className={styles.checksTitle}>
						<T id="npmos.hosts.view.other" />
					</div>
					<Check
						on={view.compact}
						label={<T id="npmos.hosts.view.compact" />}
						onClick={() => onChange({ ...view, compact: !view.compact })}
					/>
				</div>
			)}
		</Popover>
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
