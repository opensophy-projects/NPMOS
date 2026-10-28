// WAF → Events: the agent's security log (Important / All events, as in open-appsec-npm)
import cn from "classnames";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import type { WafEvent, WafEventsView } from "../../api";
import { useWafEvents } from "../../hooks";
import { showWafEventModal } from "../../modals/WafEventModal";
import { ActionBadge, EventTime, SeverityBadge } from "./badges";

const VIEWS: WafEventsView[] = ["important", "all"];

function EventRow({ event }: { event: WafEvent }) {
	return (
		<tr className="cursor-pointer" onClick={() => showWafEventModal(event)}>
			<td className="text-nowrap text-secondary">
				<EventTime time={event.time} />
			</td>
			<td>
				<SeverityBadge severity={event.severity} />
			</td>
			<td>
				<div>{event.incidentType || event.name}</div>
				{event.incidentType && <div className="text-secondary small">{event.name}</div>}
			</td>
			<td>
				<ActionBadge action={event.action} />
			</td>
			<td className="text-nowrap">{event.sourceIp}</td>
			<td>{event.host || event.asset}</td>
			<td className="text-break" style={{ maxWidth: "24rem" }}>
				{event.method && <span className="text-secondary me-1">{event.method}</span>}
				{event.uri}
			</td>
		</tr>
	);
}

function WafEventsPage() {
	const [view, setView] = useState<WafEventsView>("important");
	const [search, setSearch] = useState("");
	const [query, setQuery] = useState("");
	const [follow, setFollow] = useState(true);
	const { data, isLoading, isError, error, isFetching } = useWafEvents(view, query, follow);

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-red" />
			<div className="card-header">
				<div className="row w-full align-items-center g-2">
					<div className="col">
						<h2 className="mt-1 mb-0">
							<T id="npmos.waf.events" />
						</h2>
						<div className="text-secondary">
							<T id="npmos.waf.events.description" />
						</div>
					</div>
					<div className="col-auto">
						<form
							onSubmit={(e) => {
								e.preventDefault();
								setQuery(search.trim());
							}}
						>
							<input
								type="search"
								className="form-control form-control-sm"
								placeholder={intl.formatMessage({ id: "npmos.waf.events.search" })}
								value={search}
								onChange={(e) => {
									setSearch(e.target.value);
									if (!e.target.value) setQuery("");
								}}
							/>
						</form>
					</div>
					<div className="col-auto">
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
				</div>
			</div>
			<div className="card-header">
				<ul className="nav nav-tabs card-header-tabs">
					{VIEWS.map((v) => (
						<li className="nav-item" key={v}>
							<button
								type="button"
								className={cn("nav-link", { active: view === v })}
								onClick={() => setView(v)}
							>
								<T id={`npmos.waf.events.${v}`} />
							</button>
						</li>
					))}
				</ul>
				{isFetching && <span className="spinner-border spinner-border-sm ms-auto text-secondary" />}
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
					{!data.available && (
						<div className="card-body">
							<Alert variant="warning" className="mb-0">
								<T id="npmos.waf.events.unavailable" />
							</Alert>
						</div>
					)}
					<div className="table-responsive">
						<table className="table table-vcenter table-hover card-table">
							<thead>
								<tr>
									<th>
										<T id="npmos.waf.events.time" />
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
								{data.events.length === 0 ? (
									<tr>
										<td colSpan={7} className="text-center text-secondary py-4">
											<T id={`npmos.waf.events.empty-${view}`} />
										</td>
									</tr>
								) : (
									data.events.map((event, i) => (
										<EventRow key={`${event.time}-${event.source}-${i}`} event={event} />
									))
								)}
							</tbody>
						</table>
					</div>
					<div className="card-footer text-secondary small">
						<T id="npmos.waf.events.shown" data={{ shown: data.events.length, total: data.total }} />
						{data.truncated && (
							<>
								{" "}
								<T id="npmos.waf.events.truncated" />
							</>
						)}
					</div>
				</>
			)}
		</div>
	);
}

const WafEvents = () => (
	<HasPermission rbac="waf_events" permission={VIEW} pageLoading loadingNoLogo>
		<WafEventsPage />
	</HasPermission>
);

export default WafEvents;
