// WAF → Events: security events of the open-appsec agent stored by NginxionS (docs/ROADMAP.md, phase 4):
// period, search, filters (host, IP, action, severity, attack type, score) kept in the URL, pages
// from the server, the event card, export CSV/JSON.
import { IconChevronLeft, IconChevronRight, IconDownload, IconFilter, IconX } from "@tabler/icons-react";
import cn from "classnames";
import { useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useNavigate, useSearchParams } from "react-router-dom";
import { HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError } from "src/notifications";
import { downloadEvents, type SecurityEvent } from "../../api";
import { useEvents } from "../../hooks";
import { hostLabel, showRequestModal, statusTone } from "../../modals/RequestModal";
import { showWafEventModal } from "../../modals/WafEventModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown } from "../../ui/Dropdown";
import { Label } from "../../ui/InfoTip";
import { Popover } from "../../ui/Popover";
import hostStyles from "../Hosts/Hosts.module.css";
import { ActionBadge, EventTime, SeverityBadge } from "./badges";
import { RequestLogView } from "../RequestLog";
import logStyles from "../RequestLog/RequestLog.module.css";
import styles from "./Events.module.css";
import {
	AGENT_OF,
	AGENTS,
	AGENTS_OF_ALL,
	CLIENTS,
	OUTCOMES,
	STATUS_CLASSES,
	DEFAULT_FILTERS,
	actionsFor,
	activeCount,
	type EventFilters,
	FILTERS_OF,
	filtersFromParams,
	forKind,
	type Kind,
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
import { DateTimePicker } from "../../ui/DateTimePicker";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const PAGE_SIZE = 50;
/** examples of values in the filter fields (technical, not translated) */
const EXAMPLE_HOST = "app.example.com";
const EXAMPLE_IP = "203.0.113.7";
const EXAMPLE_TYPE = "SQL Injection";

function Periods({ filters, onChange }: { filters: EventFilters; onChange: (f: EventFilters) => void }) {
	return (
		<div className={styles.periods} role="group" aria-label={t("nginxions.events.period")}>
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
					<T id={`nginxions.events.period.${period}`} />
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
	const list = `nginxions-events-${field}`;
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
	const toggle = (field: "action" | "severity" | "agent" | "status" | "client", value: string) =>
		onChange(
			filters[field].includes(value) ? withoutValue(filters, field, value) : withValue(filters, field, value),
		);
	const count = activeCount(filters);
	// only the filters of this kind of events
	const has = (field: ListField) => FILTERS_OF[filters.kind].fields.includes(field);
	const actions = actionsFor(filters);
	return (
		<Popover
			ariaLabel={t("nginxions.events.filters")}
			title={<T id="nginxions.events.filters" />}
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
								status: [],
								client: [],
								minScore: "",
								maxScore: "",
								outcome: "",
							})
						}
					>
						<T id="nginxions.events.filters.reset" />
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
						<T id="nginxions.events.filters" />
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
								<T id="nginxions.events.important-only" />
							</span>
						</label>
					</div>
					{has("agent") && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.events.agent" />
							</div>
							<div className={styles.options}>
								{(filters.kind === "all" ? AGENTS_OF_ALL : AGENTS).map((a) => (
									<label key={a}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={filters.agent.includes(a)}
											onChange={() => {
												const next = filters.agent.includes(a)
													? withoutValue(filters, "agent", a)
													: withValue(filters, "agent", a);
												onChange(forKind(next, next.kind));
											}}
										/>
										<T id={`nginxions.events.agent.${a}`} />
									</label>
								))}
							</div>
						</div>
					)}
					{filters.kind === "all" && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.events.agent.nginx" />
							</div>
							<div className={styles.options}>
								{OUTCOMES.map((o) => (
									<label key={o}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={filters.outcome === o}
											onChange={(e) =>
												onChange({ ...filters, outcome: e.target.checked ? o : "" })
											}
										/>
										<T id={`nginxions.events.outcome.${o}`} />
									</label>
								))}
							</div>
							<div className={styles.options}>
								{STATUS_CLASSES.map((c) => (
									<label key={c}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={filters.status.includes(c)}
											onChange={() => toggle("status", c)}
										/>
										{c}
									</label>
								))}
							</div>
							<div className={styles.options}>
								{CLIENTS.map((c) => (
									<label key={c}>
										<input
											type="checkbox"
											className="form-check-input m-0"
											checked={filters.client.includes(c)}
											onChange={() => toggle("client", c)}
										/>
										<T id={`nginxions.traffic.client.${c}`} />
									</label>
								))}
							</div>
							<div className={styles.hint}>
								<T id="nginxions.events.requests-only" />
							</div>
						</div>
					)}
					{has("action") && actions.length > 0 && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.waf.events.action" />
							</div>
							<div className={styles.options}>
								{actions.map((a) => (
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
					)}
					{has("severity") && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.waf.events.severity" />
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
					)}
					{has("host") && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.waf.events.host" />
							</div>
							<TextValues
								field="host"
								filters={filters}
								onChange={onChange}
								placeholder={EXAMPLE_HOST}
								suggestions={hosts}
							/>
						</div>
					)}
					{has("ip") && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.waf.events.source-ip" />
							</div>
							<TextValues field="ip" filters={filters} onChange={onChange} placeholder={EXAMPLE_IP} />
						</div>
					)}
					{has("type") && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.events.attack-type" />
							</div>
							<TextValues
								field="type"
								filters={filters}
								onChange={onChange}
								placeholder={EXAMPLE_TYPE}
								suggestions={types}
							/>
						</div>
					)}
					{FILTERS_OF[filters.kind].score && (
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.events.score" />
							</div>
							<div className={styles.scores}>
								<input
									type="number"
									min={0}
									max={10}
									step={0.1}
									className="form-control form-control-sm"
									aria-label={t("nginxions.events.score.min")}
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
									aria-label={t("nginxions.events.score.max")}
									placeholder="10"
									value={filters.maxScore}
									onChange={(e) => onChange({ ...filters, maxScore: e.target.value })}
								/>
							</div>
						</div>
					)}
				</div>
			)}
		</Popover>
	);
}

const FIELD_LABEL: Record<ListField, string> = {
	agent: "nginxions.events.agent",
	host: "nginxions.waf.events.host",
	ip: "nginxions.waf.events.source-ip",
	action: "nginxions.waf.events.action",
	severity: "nginxions.waf.events.severity",
	type: "nginxions.events.attack-type",
	status: "nginxions.traffic.filter.status",
	client: "nginxions.traffic.filter.client",
};

function ActiveFilters({ filters, onChange }: { filters: EventFilters; onChange: (f: EventFilters) => void }) {
	const chips: { key: string; label: string; value: string; remove: () => void }[] = [];
	if (filters.important) {
		chips.push({
			key: "important",
			label: t("nginxions.events.important-only"),
			value: "",
			remove: () => onChange({ ...filters, important: false }),
		});
	}
	for (const field of LIST_FIELDS) {
		for (const value of filters[field]) {
			chips.push({
				key: `${field}:${value}`,
				label: t(FIELD_LABEL[field]),
				value:
					field === "agent"
						? t(`nginxions.events.agent.${value}`)
						: field === "client"
							? t(`nginxions.traffic.client.${value}`)
							: value,
				remove: () => onChange(withoutValue(filters, field, value)),
			});
		}
	}
	if (filters.outcome) {
		chips.push({
			key: "outcome",
			label: t("nginxions.traffic.log.outcome"),
			value: t(`nginxions.events.outcome.${filters.outcome}`),
			remove: () => onChange({ ...filters, outcome: "" }),
		});
	}
	if (filters.minScore || filters.maxScore) {
		chips.push({
			key: "score",
			label: t("nginxions.events.score"),
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
					<button type="button" aria-label={t("nginxions.events.filters.remove")} onClick={chip.remove}>
						<IconX size={14} />
					</button>
				</span>
			))}
		</div>
	);
}

/** a request of the request log in Events → All: its status in place of the action, its window on a click */
function RequestRow({
	event,
	onFilter,
}: {
	event: SecurityEvent;
	onFilter: (field: ListField, value: string) => void;
}) {
	const navigate = useNavigate();
	const r = event.request;
	if (!r) return null;
	const stop = (field: ListField, value: string) => (e: React.MouseEvent) => {
		e.stopPropagation();
		onFilter(field, value);
	};
	return (
		<tr className={styles.row} onClick={() => showRequestModal(r, onFilter, navigate)}>
			<td className={styles.time}>
				<EventTime time={r.time} />
			</td>
			<td className={styles.agent}>
				<T id="nginxions.events.agent.request" />
			</td>
			<td />
			<td>
				<div>
					<T id="nginxions.events.request-row" />
				</div>
				{!r.known && <div className={styles.sub}>{t("nginxions.traffic.host.unknown")}</div>}
			</td>
			<td>
				<span className={cn(logStyles.status, statusTone(r.status))}>{r.status}</span>
			</td>
			<td className={styles.score}>—</td>
			<td>
				<button type="button" className={styles.link} onClick={stop("ip", r.ip)}>
					{r.ip}
				</button>
			</td>
			<td>
				{r.host && r.host !== "_" ? (
					<button type="button" className={styles.link} onClick={stop("host", r.host)}>
						{r.host}
					</button>
				) : (
					hostLabel(r.host)
				)}
			</td>
			<td className={styles.request} title={`${r.method} ${r.path}`}>
				<span className={styles.method}>{r.method}</span>
				{r.path}
			</td>
		</tr>
	);
}

function EventRow({ event, onFilter }: { event: SecurityEvent; onFilter: (field: ListField, value: string) => void }) {
	if (event.kind === "request") return <RequestRow event={event} onFilter={onFilter} />;
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
				<T id={`nginxions.events.agent.${AGENT_OF[event.kind] ?? "open-appsec"}`} />
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

/**
 * The kinds of Events: the agents (open-appsec, CrowdSec), mTLS refusals, all of them, and every request of the hosts
 * (the request log, with the permission of Analytics). Another kind keeps the period, hosts and addresses.
 */
function KindSwitch({ current }: { current: Kind | "requests" }) {
	const can = useCan();
	const [params, setParams] = useSearchParams();
	const go = (kind: Kind | "requests") => {
		const next = new URLSearchParams();
		for (const key of ["period", "from", "to", "host", "ip"]) {
			const v = params.get(key);
			if (v) next.set(key, v);
		}
		if (kind !== DEFAULT_FILTERS.kind) next.set("kind", kind);
		setParams(next, { replace: true });
	};
	// agents, mTLS, requests (with the permission of Analytics), all
	const kinds: (Kind | "requests")[] = KINDS.flatMap((k) =>
		k === "all" && can("analytics") ? (["requests", k] as const) : [k],
	);
	return (
		<div className={styles.kinds}>
			{kinds.map((kind) => (
				<button
					key={kind}
					type="button"
					className={cn(styles.period, current === kind && styles.periodOn)}
					aria-pressed={current === kind}
					onClick={() => go(kind)}
				>
					<T id={`nginxions.events.kind.${kind}`} />
				</button>
			))}
		</div>
	);
}

function EventsHead() {
	return (
		<div className={hostStyles.head}>
			<div>
				<h1 className={hostStyles.title}>
					<T id="nginxions.waf.events" />
				</h1>
				<p className={hostStyles.subtitle}>
					<T id="nginxions.waf.events.description" />
				</p>
			</div>
		</div>
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
			<EventsHead />

			<div className={hostStyles.toolbar}>
				<SearchField value={search} onChange={setSearch} placeholder={t("nginxions.waf.events.search")} />
				<Periods filters={filters} onChange={setFilters} />
				<FilterPanel filters={filters} onChange={setFilters} types={types} hosts={hosts} />
				<Dropdown
					floating
					inline
					ariaLabel={t("nginxions.events.export")}
					title={t("nginxions.events.export")}
					triggerClassName={hostStyles.tool}
					trigger={
						<>
							<IconDownload size={16} />
							<span className={hostStyles.toolText}>
								<T id="nginxions.events.export" />
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
					<T id="nginxions.events.from" />
					{/* the start is never after the end (or now), the end never before the start */}
					<DateTimePicker
						label={t("nginxions.events.from")}
						value={filters.from}
						max={filters.to || new Date().toISOString()}
						onChange={(iso) => iso && setFilters({ ...filters, from: iso })}
					/>
					<T id="nginxions.events.to" />
					<DateTimePicker
						label={t("nginxions.events.to")}
						value={filters.to}
						min={filters.from || undefined}
						placeholder={t("nginxions.date.now-placeholder")}
						clearable
						onChange={(iso) => setFilters({ ...filters, to: iso })}
					/>
				</div>
			)}

			<ActiveFilters filters={filters} onChange={setFilters} />

			{data && !data.available && (
				<Alert variant="warning" className="mb-0">
					<T id="nginxions.waf.events.unavailable" />
				</Alert>
			)}
			{data?.ingestError && (
				<Alert variant="danger" className="mb-0">
					<T id="nginxions.events.ingest-error" /> {data.ingestError}
				</Alert>
			)}

			<div className={cn("card", hostStyles.tableCard)}>
				<div className={hostStyles.summary}>
					<KindSwitch current={filters.kind} />
					{isFetching && <span className="spinner-border spinner-border-sm text-secondary" />}
					<label className="form-check form-switch m-0">
						<input
							className="form-check-input"
							type="checkbox"
							checked={follow}
							onChange={(e) => setFollow(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="nginxions.waf.events.follow" />
						</span>
					</label>
				</div>
				{isLoading ? (
					<LoadingPage noLogo />
				) : isError || !data ? (
					<div className="card-body">
						<Alert variant="danger" className="mb-0">
							{error?.message || <T id="nginxions.common.unknown-error" />}
						</Alert>
					</div>
				) : (
					<>
						<div className={hostStyles.scroller}>
							<table className={cn("table table-vcenter table-hover card-table", hostStyles.table)}>
								<thead>
									<tr>
										<th>
											<Label id="nginxions.waf.events.time" />
										</th>
										<th>
											<Label id="nginxions.events.agent" />
										</th>
										<th>
											<Label id="nginxions.waf.events.severity" />
										</th>
										<th>
											<Label id="nginxions.waf.events.event" />
										</th>
										<th>
											<Label id="nginxions.waf.events.action" />
										</th>
										<th>
											<Label id="nginxions.events.score" />
										</th>
										<th>
											<Label id="nginxions.waf.events.source-ip" />
										</th>
										<th>
											<Label id="nginxions.waf.events.host" />
										</th>
										<th>
											<Label id="nginxions.waf.events.request" />
										</th>
									</tr>
								</thead>
								<tbody>
									{events.length === 0 ? (
										<tr>
											<td colSpan={9} className={hostStyles.empty}>
												<T id="nginxions.events.empty" />
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
									id={data.totalCapped ? "nginxions.events.total-capped" : "nginxions.events.total"}
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
									<T id="nginxions.events.newer" />
								</button>
								<button
									type="button"
									className={hostStyles.tool}
									disabled={!data.next}
									onClick={() => data.next && setCursors([...cursors, data.next])}
								>
									<T id="nginxions.events.older" />
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

/** Events → Requests: the request log of the hosts in the same panel (permission of Analytics) */
const RequestsPage = () => (
	<HasPermission rbac="analytics" permission={VIEW} pageLoading loadingNoLogo>
		<div className={hostStyles.page}>
			<EventsHead />
			<RequestLogView kinds={<KindSwitch current="requests" />} />
		</div>
	</HasPermission>
);

const WafEvents = () => {
	const [params] = useSearchParams();
	if (params.get("kind") === "requests") return <RequestsPage />;
	return (
		<HasPermission rbac="waf_events" permission={VIEW} pageLoading loadingNoLogo>
			<WafEventsPage />
		</HasPermission>
	);
};

export default WafEvents;
