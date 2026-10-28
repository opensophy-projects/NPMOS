// Hosts: proxy, redirection, stream and 404 hosts in one table, as DNS records in Cloudflare
// (docs/ROADMAP.md, phase 2). Data and the create/edit dialogs are those of NPMplus.
import { useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useNavigate, useSearchParams } from "react-router-dom";
import { LoadingPage } from "src/components";
import {
	useAccessLists,
	useCertificates,
	useDeadHosts,
	useProxyHosts,
	useRedirectionHosts,
	useStreams,
	useUser,
} from "src/hooks";
import { intl, T } from "src/locale";
import {
	showDeadHostModal,
	showDeleteConfirmModal,
	showProxyHostModal,
	showRedirectionHostModal,
	showStreamModal,
} from "src/modals";
import {
	ACCESS_LISTS,
	CERTIFICATES,
	DEAD_HOSTS,
	hasPermission,
	MANAGE,
	PROXY_HOSTS,
	REDIRECTION_HOSTS,
	type Section,
	STREAMS,
	VIEW,
} from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { setWafHost, WAF_DEFAULTS } from "../../api";
import { useHostAttacks, useHostChanges, useUpstreamChecks, useWafHosts, useWafStatus } from "../../hooks";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { useCan } from "../../rbac/hooks";
import { showHostHistoryModal } from "../../modals/HostHistoryModal";
import { createHost, deleteHost, OBJECT, QUERY_KEY, toggleHost, updateHost } from "./api";
import {
	AccessCell,
	ActionsCell,
	type CellContext,
	AttacksCell,
	ChangedCell,
	MtlsCell,
	NameCell,
	StatusCell,
	TargetCell,
	TlsCell,
	WafCell,
} from "./Cells";
import styles from "./Hosts.module.css";
import { Recommendations } from "./Recommendations";
import {
	emptyFilters,
	exportCsv,
	exportData,
	type Filters,
	filtersFromParams,
	filtersToParams,
	HOST_TYPES,
	type HostRow,
	type HostType,
	type MtlsState,
	matches,
	OBJECT_TYPE,
	parseImport,
	recommendations,
	type Sort,
	type SortKey,
	sortRows,
	toRows,
	type WafState,
} from "./rows";
import {
	ActiveFilters,
	AddMenu,
	BulkBar,
	COLUMNS,
	type Column,
	columnLabel,
	DEFAULT_VIEW,
	type FilterOptions,
	FiltersPopover,
	Search,
	TransferMenu,
	type View,
	ViewPopover,
} from "./Toolbar";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const SECTION: Record<HostType, Section> = {
	proxy: PROXY_HOSTS,
	redirect: REDIRECTION_HOSTS,
	stream: STREAMS,
	dead: DEAD_HOSTS,
};

const EDIT: Record<HostType, (id: number | "new", isClone?: boolean) => void> = {
	proxy: showProxyHostModal,
	redirect: showRedirectionHostModal,
	stream: showStreamModal,
	dead: showDeadHostModal,
};

const SORT_COLUMN: Partial<Record<Column | "name", SortKey>> = {
	name: "name",
	type: "type",
	target: "target",
	tls: "tls",
	waf: "waf",
	mtls: "mtls",
	status: "status",
	changed: "changed",
};

/** meta as stored: without the nginx state the API adds */
const settingsMeta = (row: HostRow) => {
	const { nginxOnline: _, nginxErr: __, ...meta } = row.raw.meta ?? {};
	return meta;
};

const download = (name: string, content: string, type: string) => {
	const url = URL.createObjectURL(new Blob([content], { type }));
	const a = document.createElement("a");
	a.href = url;
	a.download = name;
	a.click();
	URL.revokeObjectURL(url);
};

const VIEW_VERSION = 3;
/** columns added after a version of the stored view: hidden in views saved before them */
const NEW_COLUMNS: Record<number, Column[]> = { 2: ["changed"], 3: ["attacks"] };
const viewKey = (userId?: number) => `npmos.hosts.view.${userId ?? 0}`;
const loadView = (userId?: number): View => {
	try {
		const stored = JSON.parse(window.localStorage.getItem(viewKey(userId)) || "null");
		if (stored && Array.isArray(stored.hidden)) {
			// views saved before a column existed keep it hidden, like the default
			const version = Number(stored.v) || 1;
			const added = Object.entries(NEW_COLUMNS).flatMap(([v, columns]) => (Number(v) > version ? columns : []));
			const hidden = [...new Set([...stored.hidden, ...added])];
			return { hidden, compact: !!stored.compact };
		}
	} catch {
		// private mode, broken value: defaults
	}
	return DEFAULT_VIEW;
};

function HostsPage() {
	const queryClient = useQueryClient();
	const navigate = useNavigate();
	const [params, setParams] = useSearchParams();
	const { data: me } = useUser("me");
	const perms = me?.permissions;
	const roles = me?.roles;
	const can = (type: HostType, perm: typeof VIEW | typeof MANAGE) => hasPermission(SECTION[type], perm, perms, roles);
	const viewTypes = HOST_TYPES.filter((type) => can(type, VIEW));
	const manageTypes = HOST_TYPES.filter((type) => can(type, MANAGE));

	const proxy = useProxyHosts(["owner", "access_lists", "certificate"], { enabled: can("proxy", VIEW) });
	const redirect = useRedirectionHosts(["owner", "certificate"], { enabled: can("redirect", VIEW) });
	const stream = useStreams(["owner", "certificate"], { enabled: can("stream", VIEW) });
	const dead = useDeadHosts(["owner", "certificate"], { enabled: can("dead", VIEW) });
	const waf = useWafHosts({ enabled: can("proxy", VIEW) });
	const rbac = useCan();
	const wafStatus = useWafStatus({ enabled: rbac("waf_policy") });
	const certificates = useCertificates([], { enabled: hasPermission(CERTIFICATES, VIEW, perms, roles) });
	const accessLists = useAccessLists([], { enabled: hasPermission(ACCESS_LISTS, VIEW, perms, roles) });
	const changes = useHostChanges();
	const upstreams = useUpstreamChecks({ enabled: can("proxy", VIEW) || can("stream", VIEW) });
	const attacks = useHostAttacks({ enabled: rbac("analytics") });
	const attacksByHost = useMemo(
		() => (attacks.data ? new Map(attacks.data.map((a) => [a.host, a])) : undefined),
		[attacks.data],
	);

	const filters = useMemo(() => filtersFromParams(params), [params]);
	const sortKey = (params.get("sort") as SortKey) || "name";
	const sortDesc = params.get("desc") === "1";
	const sort: Sort = useMemo(() => ({ key: sortKey, desc: sortDesc }), [sortKey, sortDesc]);
	const [selected, setSelected] = useState<Set<string>>(new Set());
	const [view, setViewState] = useState<View>(() => loadView(me?.id));
	const searchRef = useRef<HTMLInputElement>(null);
	const importRef = useRef<HTMLInputElement>(null);

	useEffect(() => setViewState(loadView(me?.id)), [me?.id]);
	const setView = (next: View) => {
		setViewState(next);
		try {
			window.localStorage.setItem(viewKey(me?.id), JSON.stringify({ ...next, v: VIEW_VERSION }));
		} catch {
			// the view just is not remembered
		}
	};

	// "/" focuses the search unless the user is typing somewhere
	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
			const target = e.target as HTMLElement;
			if (e.key !== "/" || target.closest("input, textarea, select, [contenteditable]")) return;
			e.preventDefault();
			searchRef.current?.focus();
		};
		document.addEventListener("keydown", onKey);
		return () => document.removeEventListener("keydown", onKey);
	}, []);

	const setFilters = useCallback(
		(next: Filters) => setParams((prev) => filtersToParams(next, prev), { replace: true }),
		[setParams],
	);
	const setSort = (key: SortKey) =>
		setParams(
			(prev) => {
				const next = new URLSearchParams(prev);
				const desc = sort.key === key ? !sort.desc : false;
				next.set("sort", key);
				if (desc) next.set("desc", "1");
				else next.delete("desc");
				return next;
			},
			{ replace: true },
		);

	const allRows = useMemo(
		() =>
			toRows({
				proxy: proxy.data,
				redirect: redirect.data,
				stream: stream.data,
				dead: dead.data,
				waf: waf.data,
				upstreams: upstreams.data,
				changes: changes.data,
			}),
		[proxy.data, redirect.data, stream.data, dead.data, waf.data, upstreams.data, changes.data],
	);
	const rows = useMemo(
		() =>
			sortRows(
				allRows.filter((row) => matches(row, filters)),
				sort,
			),
		[allRows, filters, sort],
	);
	const recs = useMemo(() => recommendations(allRows, wafStatus.data?.enabled), [allRows, wafStatus.data?.enabled]);
	const groups = useMemo(
		() => Array.from(new Set(allRows.map((r) => r.group).filter(Boolean))).sort((a, b) => a.localeCompare(b)),
		[allRows],
	);

	// selection only keeps rows that are still shown
	useEffect(() => {
		setSelected((prev) => {
			const shown = new Set(rows.map((r) => r.key));
			const next = new Set([...prev].filter((key) => shown.has(key)));
			return next.size === prev.size ? prev : next;
		});
	}, [rows]);

	const filterOptions: FilterOptions = { accessLists: accessLists.data ?? [], groups, types: viewTypes };

	const queries = [proxy, redirect, stream, dead].filter((_, i) => can(HOST_TYPES[i], VIEW));
	if (!me || queries.some((q) => q.isLoading)) return <LoadingPage />;
	const failed = queries.find((q) => q.isError);
	if (!viewTypes.length) return <Alert variant="danger">{t("npmos.hosts.no-access")}</Alert>;

	const refresh = (types: HostType[]) => {
		for (const type of new Set(types)) {
			queryClient.invalidateQueries({ queryKey: [QUERY_KEY[type]] });
		}
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-hosts"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-host-changes"] });
	};

	/** runs changes of one or more hosts, reports the result, refreshes the lists */
	const run = async (targets: HostRow[], change: (row: HostRow) => Promise<unknown>, success?: string) => {
		const errors: string[] = [];
		for (const row of targets) {
			try {
				await change(row);
			} catch (err: any) {
				errors.push(`${row.names[0]}: ${err?.message || err}`);
			}
		}
		refresh(targets.map((r) => r.type));
		if (errors.length) showError(errors.join("\n"));
		else if (success) {
			// say which host changed: "app.example.com — WAF mode saved"
			showSuccess(
				targets.length === 1
					? `${targets[0].names[0]} — ${success}`
					: t("npmos.hosts.done.many", { count: targets.length, action: success }),
			);
		}
	};

	const changeWaf = (row: HostRow, state: WafState) => {
		const current = waf.data?.[row.id] ?? WAF_DEFAULTS;
		return setWafHost(row.id, {
			enabled: state !== "off",
			mode: state === "off" ? current.mode : state === "prevent" ? "prevent-learn" : "detect-learn",
			minimumConfidence: current.minimumConfidence,
		});
	};
	const changeAccess = (row: HostRow, listId: number | null) =>
		updateHost(row.type, row.id, {
			npmplusAccessListType: listId === null ? "public" : "custom",
			npmplusAccessListIds: listId === null ? [] : [listId],
		});
	const changeCertificate = (row: HostRow, certificateId: number | "new") =>
		updateHost(row.type, row.id, {
			certificateId,
			...(certificateId === "new" ? { sslForced: true, meta: settingsMeta(row) } : {}),
		});

	const ctx: CellContext = {
		canManage: (row) => can(row.type, MANAGE),
		canWaf: (row) => can(row.type, MANAGE) || rbac("waf_policy", "manage"),
		certificates: certificates.data ?? [],
		accessLists: accessLists.data ?? [],
		edit: (row) => EDIT[row.type](row.id),
		remove: (row) =>
			showDeleteConfirmModal({
				title: <T id="object.delete" tData={{ object: OBJECT[row.type] }} />,
				onConfirm: () => deleteHost(row.type, row.id),
				invalidations: [[QUERY_KEY[row.type]]],
				children: (
					<>
						<T id="object.delete.content" tData={{ object: OBJECT[row.type] }} />
						<div className="mt-2 fw-bold text-break">{row.names.join(", ")}</div>
					</>
				),
			}),
		toggle: (row, enabled) =>
			run(
				[row],
				(r) => toggleHost(r.type, r.id, enabled),
				t(enabled ? "npmos.hosts.done.enabled" : "npmos.hosts.done.disabled"),
			),
		setWaf: (row, state) => run([row], (r) => changeWaf(r, state), t("npmos.hosts.done.waf")),
		setMtls: (row, caId, mode: MtlsState) =>
			run(
				[row],
				(r) =>
					updateHost(r.type, r.id, {
						meta: {
							...settingsMeta(r),
							npmplusMtlsCertificateId: mode === "off" ? 0 : caId,
							npmplusMtlsVerifyClientOptional: mode === "optional",
						},
					}),
				t("npmos.hosts.done.mtls"),
			),
		setAccess: (row, listId) => run([row], (r) => changeAccess(r, listId), t("npmos.hosts.done.access")),
		setCertificate: (row, certificateId) => {
			if (certificateId === "new") showSuccess(t("npmos.hosts.tls.requesting"));
			return run([row], (r) => changeCertificate(r, certificateId), t("npmos.hosts.done.certificate"));
		},
		openCertificates: () => navigate("/certificates"),
		duplicate: (row) => EDIT[row.type](row.id, true),
		history: (row) => showHostHistoryModal(OBJECT_TYPE[row.type], row.id, row.names.join(", ")),
		attacks: attacksByHost,
		events: (row) =>
			navigate(`/waf/events?${new URLSearchParams({ host: row.names.map((n) => n.toLowerCase()).join(",") })}`),
	};

	const selectedRows = rows.filter((r) => selected.has(r.key) && can(r.type, MANAGE));
	const manageableShown = rows.filter((r) => can(r.type, MANAGE));
	const allSelected = manageableShown.length > 0 && manageableShown.every((r) => selected.has(r.key));
	const toggleSelect = (key: string) =>
		setSelected((prev) => {
			const next = new Set(prev);
			if (next.has(key)) next.delete(key);
			else next.add(key);
			return next;
		});

	const bulkDelete = () =>
		showConfirmModal({
			tTitle: "npmos.hosts.bulk.delete-title",
			tConfirm: "action.delete",
			danger: true,
			children: (
				<>
					<p>
						<T id="npmos.hosts.bulk.delete-text" data={{ count: selectedRows.length }} />
					</p>
					<ul className="mb-0">
						{selectedRows.map((r) => (
							<li key={r.key} className="text-break">
								{r.names.join(", ")}
							</li>
						))}
					</ul>
				</>
			),
			onConfirm: async () => {
				await run(selectedRows, (r) => deleteHost(r.type, r.id), t("npmos.hosts.done.deleted"));
				setSelected(new Set());
			},
		});

	const onExport = (format: "json" | "csv") => {
		const target = selected.size ? rows.filter((r) => selected.has(r.key)) : rows;
		const stamp = new Date().toISOString().slice(0, 10);
		if (format === "json") {
			download(`npmos-hosts-${stamp}.json`, JSON.stringify(exportData(target), null, 2), "application/json");
		} else {
			download(`npmos-hosts-${stamp}.csv`, exportCsv(target), "text/csv");
		}
	};

	const onImportFile = async (file: File) => {
		let parsed: ReturnType<typeof parseImport>;
		try {
			parsed = parseImport(await file.text(), {
				certificateIds: (certificates.data ?? []).map((c) => c.id),
				accessListIds: (accessLists.data ?? []).map((l) => l.id as number),
			});
		} catch {
			showError(t("npmos.hosts.import.invalid"));
			return;
		}
		const items = parsed.items.filter((item) => manageTypes.includes(item.type));
		if (!items.length) {
			showError(t("npmos.hosts.import.empty"));
			return;
		}
		showConfirmModal({
			tTitle: "npmos.hosts.import",
			tConfirm: "npmos.hosts.import.confirm",
			children: (
				<>
					<p>
						<T id="npmos.hosts.import.text" data={{ count: items.length }} />
					</p>
					{parsed.dropped > 0 && (
						<p className="text-warning mb-0">
							<T id="npmos.hosts.import.dropped" data={{ count: parsed.dropped }} />
						</p>
					)}
				</>
			),
			onConfirm: async () => {
				const errors: string[] = [];
				for (const item of items) {
					try {
						await createHost(item.type, item.data);
					} catch (err: any) {
						errors.push(
							`${(item.data.domainNames ?? [item.data.incomingPort]).join(", ")}: ${err?.message || err}`,
						);
					}
				}
				refresh(items.map((i) => i.type));
				if (errors.length) showError(errors.join("\n"));
				else showSuccess(t("npmos.hosts.import.done", { count: items.length }));
			},
		});
	};

	const visible = (column: Column) => !view.hidden.includes(column);
	const shownColumns = COLUMNS.filter(visible);
	const header = (column: Column | "name", label: ReactNode) => {
		const key = SORT_COLUMN[column];
		const on = key && sort.key === key;
		return (
			<th key={column} aria-sort={on ? (sort.desc ? "descending" : "ascending") : undefined}>
				{key ? (
					<button type="button" className={cn(styles.sort, on && styles.sortOn)} onClick={() => setSort(key)}>
						{label}
						<span className={styles.sortArrow}>{on ? (sort.desc ? "↓" : "↑") : "↕"}</span>
					</button>
				) : (
					label
				)}
			</th>
		);
	};

	const cell = (row: HostRow, column: Column) => {
		switch (column) {
			case "type":
				return (
					<span className={styles.type}>
						<T id={`npmos.hosts.type.${row.type}`} />
					</span>
				);
			case "target":
				return <TargetCell row={row} />;
			case "tls":
				return <TlsCell row={row} ctx={ctx} />;
			case "waf":
				return <WafCell row={row} ctx={ctx} />;
			case "mtls":
				return <MtlsCell row={row} ctx={ctx} />;
			case "access":
				return <AccessCell row={row} ctx={ctx} />;
			case "status":
				return <StatusCell row={row} ctx={ctx} />;
			case "changed":
				return <ChangedCell row={row} ctx={ctx} />;
			case "attacks":
				return <AttacksCell row={row} ctx={ctx} />;
		}
	};

	return (
		<div className={styles.page}>
			<div className={styles.head}>
				<div>
					<h1 className={styles.title}>
						<T id="npmos.hosts.title" />
					</h1>
					<p className={styles.subtitle}>
						<T id="npmos.hosts.subtitle" />
					</p>
				</div>
			</div>

			{failed && <Alert variant="danger">{failed.error?.message || <T id="npmos.common.unknown-error" />}</Alert>}

			<Recommendations items={recs} onShow={(rules) => setFilters({ q: "", rules })} />

			<div className={styles.toolbar}>
				<Search ref={searchRef} value={filters.q} onChange={(q) => setFilters({ ...filters, q })} />
				<FiltersPopover
					filters={filters}
					options={filterOptions}
					onChange={(rules) => setFilters({ ...filters, rules })}
				/>
				<ViewPopover view={view} onChange={setView} />
				<TransferMenu
					onExport={onExport}
					onImport={() => importRef.current?.click()}
					canImport={manageTypes.length > 0}
					selected={selected.size}
				/>
				<input
					ref={importRef}
					type="file"
					accept="application/json,.json"
					hidden
					onChange={(e) => {
						const file = e.target.files?.[0];
						e.target.value = "";
						if (file) onImportFile(file);
					}}
				/>
				<AddMenu types={manageTypes} onAdd={(type) => EDIT[type]("new")} />
			</div>

			<ActiveFilters
				filters={filters}
				options={filterOptions}
				onChange={(rules) => setFilters({ ...filters, rules })}
			/>

			<div className={cn("card", styles.tableCard)}>
				{selectedRows.length > 0 ? (
					<BulkBar
						count={selectedRows.length}
						hasProxy={selectedRows.some((r) => r.type === "proxy")}
						certificates={certificates.data ?? []}
						accessLists={accessLists.data ?? []}
						onClear={() => setSelected(new Set())}
						onToggle={(enabled) =>
							run(
								selectedRows,
								(r) => toggleHost(r.type, r.id, enabled),
								t(enabled ? "npmos.hosts.done.enabled" : "npmos.hosts.done.disabled"),
							)
						}
						onWaf={(state) =>
							run(
								selectedRows.filter((r) => r.type === "proxy"),
								(r) => changeWaf(r, state),
								t("npmos.hosts.done.waf"),
							)
						}
						onCertificate={(id) =>
							run(selectedRows, (r) => changeCertificate(r, id), t("npmos.hosts.done.certificate"))
						}
						onAccess={(id) =>
							run(
								selectedRows.filter((r) => r.type === "proxy"),
								(r) => changeAccess(r, id),
								t("npmos.hosts.done.access"),
							)
						}
						onDelete={bulkDelete}
					/>
				) : (
					<div className={styles.summary}>
						<T id="npmos.hosts.summary" data={{ shown: rows.length, total: allRows.length }} />
					</div>
				)}
				<div className={styles.scroller}>
					<table
						className={cn("table table-vcenter card-table", styles.table, view.compact && styles.compact)}
					>
						<thead>
							<tr>
								<th className={styles.check}>
									<input
										type="checkbox"
										className="form-check-input m-0"
										aria-label={t("npmos.hosts.select-all")}
										checked={allSelected}
										disabled={!manageableShown.length}
										onChange={() =>
											setSelected(
												allSelected ? new Set() : new Set(manageableShown.map((r) => r.key)),
											)
										}
									/>
								</th>
								{header("name", <T id="column.name" />)}
								{shownColumns.map((column) => header(column, columnLabel(column)))}
								<th className={styles.actions} />
							</tr>
						</thead>
						<tbody>
							{rows.map((row) => (
								<tr key={row.key} className={cn(selected.has(row.key) && styles.rowSelected)}>
									<td className={styles.check}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											aria-label={row.names[0]}
											checked={selected.has(row.key)}
											disabled={!can(row.type, MANAGE)}
											onChange={() => toggleSelect(row.key)}
										/>
									</td>
									<td>
										<NameCell row={row} ctx={ctx} />
									</td>
									{shownColumns.map((column) => (
										<td key={column}>{cell(row, column)}</td>
									))}
									<td className={styles.actions}>
										<ActionsCell row={row} ctx={ctx} />
									</td>
								</tr>
							))}
							{!rows.length && (
								<tr>
									<td colSpan={shownColumns.length + 3} className={styles.empty}>
										{allRows.length ? (
											<>
												<T id="npmos.nav.nothing-found" />{" "}
												<button
													type="button"
													className={styles.recLink}
													onClick={() => setFilters(emptyFilters())}
												>
													<T id="npmos.hosts.filters.reset" />
												</button>
											</>
										) : (
											<T id="npmos.hosts.empty" />
										)}
									</td>
								</tr>
							)}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
}

export default function Hosts() {
	return <HostsPage />;
}
