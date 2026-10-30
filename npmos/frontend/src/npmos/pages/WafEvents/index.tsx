// WAF → Events: security events of the open-appsec agent stored by NPMOS (docs/ROADMAP.md, phase 4):
// period, search, filters (host, IP, action, severity, attack type, score) kept in the URL, pages
// from the server, the event card, export CSV/JSON.
import { IconChevronLeft, IconChevronRight, IconDownload, IconFilter, IconX } from "@tabler/icons-react";
import cn from "classnames";
import { useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useSearchParams } from "react-router-dom";
import { HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError } from "src/notifications";
import { downloadEvents, type SecurityEvent } from "../../api";
import { useEvents } from "../../hooks";
import { showWafEventModal } from "../../modals/WafEventModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown } from "../../ui/Dropdown";
import { Popover } from "../../ui/Popover";
import hostStyles from "../Hosts/Hosts.module.css";
import { ActionBadge, EventTime, SeverityBadge } from "./badges";
import styles from "./Events.module.css";
import {
	ACTIONS,
	AGENT_OF,
	AGENTS,
	activeCount,
	type EventFilters,
	filtersFromParams,
	filtersToParams,
	filtersToQuery,
	KINDS,
	LIST_FIELDS,
	type ListField,
	PERIODS,
	SEVERITIES,
	withoutValue,
	withValue,
} from "./filters";
import { RetentionPopover } from "./Retention";
import { SearchField } from "../../ui/SearchField";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const PAGE_SIZE = 50;
/** examples of values in the filter fields (technical, not translated) */
const EXAMPLE_HOST = "app.example.com";
const EXAMPLE_IP = "203.0.113.7";
const EXAMPLE_TYPE = "SQL Injection";

/** value of <input type="datetime-local"> for an ISO time, and back */
const toLocalInput = (iso: string) => {
	if (!iso) return "";
	const d = new Date(iso);
	return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};
const fromLocalInput = (value: string) => (value ? new Date(value).toISOString() : "");

function Periods({ filters, onChange }: { filters: EventFilters; onChange: (f: EventFilters) => void }) {
	return (
		<div className={styles.periods} role="group" aria-label={t("npmos.events.period")}>
			{PERIODS.map((period) => (
				<button
					key={period}
					type="button"
					className={cn(styles.period, filters.period === period && styles.periodOn)}
					aria-pressed={filters.period === period}
					onClick={() =>
						onChange({
							...filters,
							period,
							from:
								period === "custom"
									? filters.from || new Date(Date.now() - 86400000).toISOString()
									: "",
							to: "",
						})
					}
				>
					<T id={`npmos.events.period.${period}`} />
				</button>
			))}
		</div>
	);
}

function TextValues({
	field,
	filters,
	onChange,
	placeholder,
	suggestions,
}: {
	field: ListField;
	filters: EventFilters;
	onChange: (f: EventFilters) => void;
	placeholder: string;
	suggestions?: string[];
}) {
	const [value, setValue] = useState("");
	const list = `npmos-events-${field}`;
	const add = () => {
		if (value.trim())
			onChange(withValue(filters, field, field === "host" ? value.trim().toLowerCase() : value.trim()));
		setValue("");
	};
	return (
		<>
			<input
				className="form-control form-control-sm"
				value={value}
				placeholder={placeholder}
				list={suggestions?.length ? list : undefined}
				onChange={(e) => setValue(e.target.value)}
				onKeyDown={(e) => {
					if (e.key === "Enter") {
						e.preventDefault();
						add();
					}
				}}
				onBlur={add}
			/>
			{suggestions?.length ? (
				<datalist id={list}>
					{suggestions.map((s) => (
						<option key={s} value={s} />
					))}
				</datalist>
			) : null}
		</>
	);
}

function FilterPanel({
	filters,
	onChange,
	types,
	hosts,
}: {
	filters: EventFilters;
	onChange: (f: EventFilters) => void;
	types: string[];
	hosts: string[];
}) {
	const toggle = (field: "action" | "severity" | "agent", value: string) =>
		onChange(
			filters[field].includes(value) ? withoutValue(filters, field, value) : withValue(filters, field, value),
		);
	const count = activeCount(filters);
	return (
		<Popover
			ariaLabel={t("npmos.events.filters")}
			title={<T id="npmos.events.filters" />}
			titleAction={
				count > 0 ? (
					<button
						type="button"
						className={hostStyles.reset}
						onClick={() =>
							onChange({
								...filters,
								important: false,
								agent: [],
								host: [],
								ip: [],
								action: [],
								severity: [],
								type: [],
								minScore: "",
								maxScore: "",
							})
						}
					>
						<T id="npmos.events.filters.reset" />
					</button>
				) : undefined
			}
			width="24rem"
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
					<div className={styles.section}>
						<label className="form-check form-switch m-0">
							<input
								className="form-check-input"
								type="checkbox"
								checked={filters.important}
								onChange={(e) => onChange({ ...filters, important: e.target.checked })}
							/>
							<span className="form-check-label">
								<T id="npmos.events.important-only" />
							</span>
						</label>
					</div>
					{filters.kind === "agents" && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="npmos.events.agent" />
							</div>
							<div className={styles.options}>
								{AGENTS.map((a) => (
									<label key={a}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={filters.agent.includes(a)}
											onChange={() => toggle("agent", a)}
										/>
										<T id={`npmos.events.agent.${a}`} />
									</label>
								))}
							</div>
						</div>
					)}
					<div className={styles.section}>
						<div className={styles.sectionTitle}>
							<T id="npmos.waf.events.action" />
						</div>
						<div className={styles.options}>
							{ACTIONS.map((a) => (
								<label key={a}>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={filters.action.includes(a)}
										onChange={() => toggle("action", a)}
									/>
									{a}
								</label>
							))}
						</div>
					</div>
					<div className={styles.section}>
						<div className={styles.sectionTitle}>
							<T id="npmos.waf.events.severity" />
						</div>
						<div className={styles.options}>
							{SEVERITIES.map((s) => (
								<label key={s}>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={filters.severity.includes(s)}
										onChange={() => toggle("severity", s)}
									/>
									{s}
								</label>
							))}
						</div>
					</div>
					<div className={styles.section}>
						<div className={styles.sectionTitle}>
							<T id="npmos.waf.events.host" />
						</div>
						<TextValues
							field="host"
							filters={filters}
							onChange={onChange}
							placeholder={EXAMPLE_HOST}
							suggestions={hosts}
						/>
					</div>
					<div className={styles.section}>
						<div className={styles.sectionTitle}>
							<T id="npmos.waf.events.source-ip" />
						</div>
						<TextValues field="ip" filters={filters} onChange={onChange} placeholder={EXAMPLE_IP} />
					</div>
					<div className={styles.section}>
						<div className={styles.sectionTitle}>
							<T id="npmos.events.attack-type" />
						</div>
						<TextValues
							field="type"
							filters={filters}
							onChange={onChange}
							placeholder={EXAMPLE_TYPE}
							suggestions={types}
						/>
					</div>
					<div className={styles.section}>
						<div className={styles.sectionTitle}>
							<T id="npmos.events.score" />
						</div>
						<div className={styles.scores}>
							<input
								type="number"
								min={0}
								max={10}
								step={0.1}
								className="form-control form-control-sm"
								aria-label={t("npmos.events.score.min")}
								placeholder="0"
								value={filters.minScore}
								onChange={(e) => onChange({ ...filters, minScore: e.target.value })}
							/>
							<span>—</span>
							<input
								type="number"
								min={0}
								max={10}
								step={0.1}
								className="form-control form-control-sm"
								aria-label={t("npmos.events.score.max")}
								placeholder="10"
								value={filters.maxScore}
								onChange={(e) => onChange({ ...filters, maxScore: e.target.value })}
							/>
						</div>
					</div>
				</div>
			)}
		</Popover>
	);
}

const FIELD_LABEL: Record<ListField, string> = {
	agent: "npmos.events.agent",
	host: "npmos.waf.events.host",
	ip: "npmos.waf.events.source-ip",
	action: "npmos.waf.events.action",
	severity: "npmos.waf.events.severity",
	type: "npmos.events.attack-type",
};

function ActiveFilters({ filters, onChange }: { filters: EventFilters; onChange: (f: EventFilters) => void }) {
	const chips: { key: string; label: string; value: string; remove: () => void }[] = [];
	if (filters.important) {
		chips.push({
			key: "important",
			label: t("npmos.events.important-only"),
			value: "",
			remove: () => onChange({ ...filters, important: false }),
		});
	}
	for (const field of LIST_FIELDS) {
		for (const value of filters[field]) {
			chips.push({
				key: `${field}:${value}`,
				label: t(FIELD_LABEL[field]),
				value: field === "agent" ? t(`npmos.events.agent.${value}`) : value,
				remove: () => onChange(withoutValue(filters, field, value)),
			});
		}
	}
	if (filters.minScore || filters.maxScore) {
		chips.push({
			key: "score",
			label: t("npmos.events.score"),
			value: `${filters.minScore || "0"}–${filters.maxScore || "10"}`,
			remove: () => onChange({ ...filters, minScore: "", maxScore: "" }),
		});
	}
	if (!chips.length) return null;
	return (
		<div className={hostStyles.active}>
			{chips.map((chip) => (
				<span key={chip.key} className={hostStyles.activeChip}>
					<span className={hostStyles.activeField}>{chip.label}</span>
					{chip.value && <span>{chip.value}</span>}
					<button type="button" aria-label={t("npmos.events.filters.remove")} onClick={chip.remove}>
						<IconX size={14} />
					</button>
				</span>
			))}
		</div>
	);
}

function EventRow({ event, onFilter }: { event: SecurityEvent; onFilter: (field: ListField, value: string) => void }) {
	const stop = (field: ListField, value: string) => (e: React.MouseEvent) => {
		e.stopPropagation();
		onFilter(field, value);
	};
	return (
		<tr className={styles.row} onClick={() => showWafEventModal(event, onFilter)}>
			<td className={styles.time}>
				<EventTime time={event.time} />
			</td>
			<td className={styles.agent}>
				<T id={`npmos.events.agent.${AGENT_OF[event.kind] ?? "open-appsec"}`} />
			</td>
			<td>
				<SeverityBadge severity={event.severity} />
			</td>
			<td>
				<div>{event.incidentType || event.name}</div>
				{event.incidentType && event.parameter && <div className={styles.sub}>{event.parameter}</div>}
			</td>
			<td>
				<ActionBadge action={event.action} />
			</td>
			<td className={styles.score}>{event.score ?? "—"}</td>
			<td>
				{event.sourceIp ? (
					<button type="button" className={styles.link} onClick={stop("ip", event.sourceIp)}>
						{event.sourceIp}
					</button>
				) : (
					"—"
				)}
			</td>
			<td>
				{event.host ? (
					<button type="button" className={styles.link} onClick={stop("host", event.host)}>
						{event.host}
					</button>
				) : (
					event.asset || "—"
				)}
			</td>
			<td className={styles.request} title={[event.method, event.uri].filter(Boolean).join(" ")}>
				{event.method && <span className={styles.method}>{event.method}</span>}
				{event.uri}
			</td>
		</tr>
	);
}

function WafEventsPage() {
	const can = useCan();
	const [params, setParams] = useSearchParams();
	const filters = useMemo(() => filtersFromParams(params), [params]);
	const [search, setSearch] = useState(filters.q);
	const [follow, setFollow] = useState(true);
	/** cursors of the pages before the current one (the first page has none) */
	const [cursors, setCursors] = useState<string[]>([]);
	const before = cursors[cursors.length - 1];
	const query = useMemo(() => filtersToQuery(filters), [filters]);
	const { data, isLoading, isError, error, isFetching } = useEvents(
		{ ...query, limit: PAGE_SIZE, before },
		// newer events only matter on the first page
		follow && !before,
	);

	const setFilters = (f: EventFilters) => {
		setCursors([]);
		setParams(filtersToParams(f, params), { replace: true });
	};

	// a search set from outside (a link) shows in the field
	useEffect(() => setSearch(filters.q), [filters.q]);

	// the search is applied a moment after typing stops
	// biome-ignore lint/correctness/useExhaustiveDependencies: runs when the typed text changes, with the filters of then
	useEffect(() => {
		if (search === filters.q) return;
		const timer = setTimeout(() => setFilters({ ...filters, q: search }), 400);
		return () => clearTimeout(timer);
	}, [search]);

	const events = data?.events ?? [];
	const types = [...new Set(events.map((e) => e.incidentType).filter(Boolean))].sort();
	const hosts = [...new Set(events.map((e) => e.host).filter(Boolean))].sort();
	const page = cursors.length;

	const exportAs = async (format: "csv" | "json") => {
		try {
			await downloadEvents(query, format);
		} catch (err: any) {
			showError(err.message);
		}
	};

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.waf.events" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.waf.events.description" />
					</p>
				</div>
			</div>

			<div className={hostStyles.toolbar}>
				<SearchField value={search} onChange={setSearch} placeholder={t("npmos.waf.events.search")} />
				<Periods filters={filters} onChange={setFilters} />
				<FilterPanel filters={filters} onChange={setFilters} types={types} hosts={hosts} />
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
				{can("settings") && <RetentionPopover canManage={can("settings", "manage")} />}
			</div>

			{filters.period === "custom" && (
				<div className={styles.custom}>
					<T id="npmos.events.from" />
					<input
						type="datetime-local"
						className="form-control form-control-sm"
						value={toLocalInput(filters.from)}
						onChange={(e) =>
							e.target.value && setFilters({ ...filters, from: fromLocalInput(e.target.value) })
						}
					/>
					<T id="npmos.events.to" />
					<input
						type="datetime-local"
						className="form-control form-control-sm"
						value={toLocalInput(filters.to)}
						onChange={(e) => setFilters({ ...filters, to: fromLocalInput(e.target.value) })}
					/>
				</div>
			)}

			<ActiveFilters filters={filters} onChange={setFilters} />

			{data && !data.available && (
				<Alert variant="warning" className="mb-0">
					<T id="npmos.waf.events.unavailable" />
				</Alert>
			)}
			{data?.ingestError && (
				<Alert variant="danger" className="mb-0">
					<T id="npmos.events.ingest-error" /> {data.ingestError}
				</Alert>
			)}

			<div className={cn("card", hostStyles.tableCard)}>
				<div className={hostStyles.summary}>
					<div className={styles.kinds}>
						{KINDS.map((kind) => (
							<button
								key={kind}
								type="button"
								className={cn(styles.period, filters.kind === kind && styles.periodOn)}
								aria-pressed={filters.kind === kind}
								onClick={() => setFilters({ ...filters, kind })}
							>
								<T id={`npmos.events.kind.${kind}`} />
							</button>
						))}
					</div>
					{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
					<label className="form-check form-switch m-0">
						<input
							className="form-check-input"
							type="checkbox"
							checked={follow}
							onChange={(e) => setFollow(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="npmos.waf.events.follow" />
						</span>
					</label>
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
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter table-hover card-table", hostStyles.table)}>
								<thead>
									<tr>
										<th>
											<T id="npmos.waf.events.time" />
										</th>
										<th>
											<T id="npmos.events.agent" />
										</th>
										<th>
											<T id="npmos.waf.events.severity" />
										</th>
										<th>
											<T id="npmos.waf.events.event" />
										</th>
										<th>
											<T id="npmos.waf.events.action" />
										</th>
										<th>
											<T id="npmos.events.score" />
										</th>
										<th>
											<T id="npmos.waf.events.source-ip" />
										</th>
										<th>
											<T id="npmos.waf.events.host" />
										</th>
										<th>
											<T id="npmos.waf.events.request" />
										</th>
									</tr>
								</thead>
								<tbody>
									{events.length === 0 ? (
										<tr>
											<td colSpan={9} className={hostStyles.empty}>
												<T id="npmos.events.empty" />
											</td>
										</tr>
									) : (
										events.map((event) => (
											<EventRow
												key={event.id}
												event={event}
												onFilter={(field, value) =>
													setFilters(withValue(filters, field, value))
												}
											/>
										))
									)}
								</tbody>
							</table>
						</div>
						<div className={styles.pager}>
							<span>
								<T
									id={data.totalCapped ? "npmos.events.total-capped" : "npmos.events.total"}
									data={{ total: data.total }}
								/>
							</span>
							<div className={styles.pagerButtons}>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={page === 0}
									onClick={() => setCursors(cursors.slice(0, -1))}
								>
									<IconChevronLeft size={16} />
									<T id="npmos.events.newer" />
								</button>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={!data.next}
									onClick={() => data.next && setCursors([...cursors, data.next])}
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

const WafEvents = () => (
	<HasPermission rbac="waf_events" permission={VIEW} pageLoading loadingNoLogo>
		<WafEventsPage />
	</HasPermission>
);

export default WafEvents;
