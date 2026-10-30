// Analytics → Audit log: pages from the server like the events (the upstream page showed the last 100 entries),
// search over the whole log, period, filters by action, object and user kept in the URL, export CSV/JSON.
import { IconChevronLeft, IconChevronRight, IconDownload, IconFilter, IconX } from "@tabler/icons-react";
import cn from "classnames";
import { useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useSearchParams } from "react-router-dom";
import { EventFormatter, HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showEventDetailsModal } from "src/modals";
import { ADMIN, VIEW } from "src/modules/Permissions";
import { showError } from "src/notifications";
import { downloadAudit, type EventQuery } from "../../api";
import { useAudit } from "../../hooks";
import { Dropdown } from "../../ui/Dropdown";
import { Popover } from "../../ui/Popover";
import styles from "../WafEvents/Events.module.css";
import hostStyles from "../Hosts/Hosts.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const PAGE_SIZE = 50;
const PERIODS = ["all", "24h", "7d", "30d", "90d"] as const;
type ListField = "action" | "object" | "user";
const LIST_FIELDS: ListField[] = ["action", "object", "user"];

/** a label of a value, or the value when the interface has no name for it */
const label = (id: string, fallback: string) => (intl.messages[id] ? t(id) : fallback);
const actionLabel = (action: string) => label(`npmos.audit.action.${action}`, action);
const objectLabel = (object: string) => label(object, object);

const values = (params: URLSearchParams, field: ListField) => (params.get(field) || "").split(",").filter(Boolean);

function AuditLogPage() {
	const [params, setParams] = useSearchParams();
	const asked = params.get("period") || "";
	const period = (PERIODS as readonly string[]).includes(asked) ? asked : "all";
	const q = params.get("q") || "";
	const page = Math.max(Number.parseInt(params.get("page") || "0", 10) || 0, 0);
	const selected = useMemo(
		() => Object.fromEntries(LIST_FIELDS.map((f) => [f, values(params, f)])) as Record<ListField, string[]>,
		[params],
	);
	const [search, setSearch] = useState(q);

	const update = (changes: Record<string, string>) => {
		const next = new URLSearchParams(params);
		for (const [key, value] of Object.entries(changes)) {
			if (value) next.set(key, value);
			else next.delete(key);
		}
		// another filter starts from the first page
		if (!("page" in changes)) next.delete("page");
		setParams(next, { replace: true });
	};
	const toggle = (field: ListField, value: string) => {
		const list = selected[field];
		update({ [field]: (list.includes(value) ? list.filter((v) => v !== value) : [...list, value]).join(",") });
	};

	useEffect(() => setSearch(q), [q]);
	// the search is applied a moment after typing stops
	// biome-ignore lint/correctness/useExhaustiveDependencies: runs when the typed text changes
	useEffect(() => {
		if (search === q) return;
		const timer = setTimeout(() => update({ q: search }), 400);
		return () => clearTimeout(timer);
	}, [search]);

	const query: EventQuery = {
		q: q || undefined,
		period: period === "all" ? undefined : period,
		action: selected.action.join(",") || undefined,
		object: selected.object.join(",") || undefined,
		user: selected.user.join(",") || undefined,
	};
	const { data, isLoading, isError, error, isFetching } = useAudit({
		...query,
		limit: PAGE_SIZE,
		offset: page * PAGE_SIZE,
	});
	const users = data?.facets.users ?? [];
	const userName = (id: string) => users.find((u) => String(u.id) === id)?.name ?? id;
	const fieldLabel: Record<ListField, (v: string) => string> = {
		action: actionLabel,
		object: objectLabel,
		user: userName,
	};
	const count = LIST_FIELDS.reduce((n, f) => n + selected[f].length, 0);
	const pages = data ? Math.max(Math.ceil(data.total / PAGE_SIZE), 1) : 1;

	const exportAs = async (format: "csv" | "json") => {
		try {
			await downloadAudit(query, format);
		} catch (err: any) {
			showError(err.message);
		}
	};

	const options = (field: ListField, items: { value: string; label: string }[]) => (
		<div className={styles.section}>
			<div className={styles.sectionTitle}>
				<T id={`npmos.audit.filter.${field}`} />
			</div>
			<div className={styles.options}>
				{items.map((item) => (
					<label key={item.value}>
						<input
							type="checkbox"
							className="form-check-input m-0"
							checked={selected[field].includes(item.value)}
							onChange={() => toggle(field, item.value)}
						/>
						{item.label}
					</label>
				))}
			</div>
		</div>
	);

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="auditlogs" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.audit.description" />
					</p>
				</div>
			</div>

			<div className={hostStyles.toolbar}>
				<div className={hostStyles.searchFrame}>
					<label className={hostStyles.search}>
						<input
							type="search"
							value={search}
							placeholder={t("npmos.audit.search")}
							aria-label={t("npmos.audit.search")}
							onChange={(e) => setSearch(e.target.value)}
						/>
					</label>
				</div>
				<div className={styles.periods} role="group" aria-label={t("npmos.events.period")}>
					{PERIODS.map((p) => (
						<button
							key={p}
							type="button"
							className={cn(styles.period, period === p && styles.periodOn)}
							aria-pressed={period === p}
							onClick={() => update({ period: p === "all" ? "" : p })}
						>
							<T id={`npmos.audit.period.${p}`} />
						</button>
					))}
				</div>
				<Popover
					ariaLabel={t("npmos.events.filters")}
					title={<T id="npmos.events.filters" />}
					titleAction={
						count > 0 ? (
							<button
								type="button"
								className={hostStyles.reset}
								onClick={() => update({ action: "", object: "", user: "" })}
							>
								<T id="npmos.events.filters.reset" />
							</button>
						) : undefined
					}
					width="26rem"
					triggerClassName={hostStyles.tool}
					activeClassName={hostStyles.toolOn}
					trigger={
						<>
							<IconFilter size={16} />
							<span className={hostStyles.toolText}>
								<T id="npmos.events.filters" />
							</span>
							{count > 0 && <span className={hostStyles.count}>{count}</span>}
						</>
					}
				>
					{() => (
						<div>
							{options(
								"action",
								(data?.facets.actions ?? []).map((a) => ({ value: a, label: actionLabel(a) })),
							)}
							{options(
								"object",
								(data?.facets.objects ?? []).map((o) => ({ value: o, label: objectLabel(o) })),
							)}
							{options(
								"user",
								users.map((u) => ({ value: String(u.id), label: u.name })),
							)}
						</div>
					)}
				</Popover>
				<Dropdown
					floating
					inline
					ariaLabel={t("npmos.events.export")}
					title={t("npmos.events.export")}
					triggerClassName={hostStyles.tool}
					trigger={
						<>
							<IconDownload size={16} />
							<span className={hostStyles.toolText}>
								<T id="npmos.events.export" />
							</span>
						</>
					}
					items={[
						{ key: "csv", label: "CSV", onSelect: () => exportAs("csv") },
						{ key: "json", label: "JSON", onSelect: () => exportAs("json") },
					]}
				/>
			</div>

			{count > 0 && (
				<div className={hostStyles.active}>
					{LIST_FIELDS.flatMap((field) =>
						selected[field].map((value) => (
							<span key={`${field}:${value}`} className={hostStyles.activeChip}>
								<span className={hostStyles.activeField}>
									<T id={`npmos.audit.filter.${field}`} />
								</span>
								<span>{fieldLabel[field](value)}</span>
								<button
									type="button"
									aria-label={t("npmos.events.filters.remove")}
									onClick={() => toggle(field, value)}
								>
									<IconX size={14} />
								</button>
							</span>
						)),
					)}
				</div>
			)}

			<div className={cn("card", hostStyles.tableCard)}>
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
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter table-hover card-table", hostStyles.table)}>
								<thead>
									<tr>
										<th>
											<T id="column.event" />
										</th>
										<th>
											<T id="npmos.audit.filter.user" />
										</th>
										<th />
									</tr>
								</thead>
								<tbody>
									{data.items.length === 0 ? (
										<tr>
											<td colSpan={3} className={hostStyles.empty}>
												<T id="npmos.audit.empty" />
											</td>
										</tr>
									) : (
										data.items.map((item) => (
											<tr
												key={item.id}
												className={styles.row}
												onClick={() => showEventDetailsModal(item.id)}
											>
												<td>
													<EventFormatter row={item} />
												</td>
												<td>{item.user?.name ?? "—"}</td>
												<td className="text-end">
													<button type="button" className="btn btn-action btn-sm px-1">
														<T id="action.view-details" />
													</button>
												</td>
											</tr>
										))
									)}
								</tbody>
							</table>
						</div>
						<div className={styles.pager}>
							<span>
								<T id="npmos.audit.total" data={{ total: data.total }} />
							</span>
							{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
							<div className={styles.pagerButtons}>
								<span>
									<T id="npmos.audit.page" data={{ page: page + 1, pages }} />
								</span>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page === 0}
									onClick={() => update({ page: page > 1 ? String(page - 1) : "" })}
								>
									<IconChevronLeft size={16} />
									<T id="npmos.events.newer" />
								</button>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page + 1 >= pages}
									onClick={() => update({ page: String(page + 1) })}
								>
									<T id="npmos.events.older" />
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

const AuditLog = () => (
	<HasPermission section={ADMIN} rbac="audit_log" permission={VIEW} pageLoading loadingNoLogo>
		<AuditLogPage />
	</HasPermission>
);

export default AuditLog;
