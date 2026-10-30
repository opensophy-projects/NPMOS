// One security event of the open-appsec agent or an alert of CrowdSec: the request, what the WAF
// matched (as the red zone of the open-appsec-npm Security Log), how it scored, and the whole event
// as the agent or CrowdSec wrote it. Its source can be banned in CrowdSec from here.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showError } from "src/notifications";
import type { SecurityEvent } from "../api";
import { useDecisions } from "../crowdsec/api";
import { showBanModal } from "../crowdsec/BanModal";
import { remaining } from "../crowdsec/labels";
import { useEvent } from "../hooks";
import { type Decision, getEventGroup } from "../learning/api";
import { showLabelModal } from "../learning/LabelModal";
import { ActionBadge, EventTime, SeverityBadge } from "../pages/WafEvents/badges";
import { getPolicyObjects } from "../policy/api";
import { showObjectModal } from "../policy/ObjectModal";
import { useCan } from "../rbac/hooks";

type FilterField = "ip" | "host";

/** "3h59m55.1s" → seconds */
const remainingSeconds = (d: string) => {
	const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(d || "");
	return m ? Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0) : 0;
};

interface Props extends InnerModalProps {
	event: SecurityEvent;
	/** show only the events of this IP or host (the events page) */
	onFilter?: (field: FilterField, value: string) => void;
}

function Field({ label, value }: { label: string; value?: React.ReactNode }) {
	if (value === undefined || value === null || value === "") return null;
	return (
		<div className="datagrid-item">
			<div className="datagrid-title">
				<T id={label} />
			</div>
			<div className="datagrid-content text-break">{value}</div>
		</div>
	);
}

/**
 * An exception (WAF → Policy) for what the event shows: its source, URL and parameter; added to the
 * default policy. The administrator removes the conditions that are too narrow before saving.
 */
const createException = async (event: SecurityEvent) => {
	try {
		const data = await getPolicyObjects();
		const condition = [
			event.sourceIp && { key: "sourceIp", value: event.sourceIp },
			event.uri && { key: "url", value: event.uri },
			event.parameter && { key: "paramName", value: event.parameter },
		].filter(Boolean);
		const base = `event-${(event.sourceIp || event.host || "x").toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
		let name = base.replace(/-+$/, "");
		for (let n = 2; data.objects.some((o) => o.kind === "exception" && o.name === name); n++) name = `${base}-${n}`;
		showObjectModal({
			kind: "exception",
			objects: data.objects,
			addToDefault: data.policy,
			initial: {
				name,
				description: [event.name, event.host].filter(Boolean).join(" · ").slice(0, 500),
				spec: { action: "accept", condition },
			},
		});
	} catch (err: any) {
		showError(err.message);
	}
};

/** labels the group of the event (Agents → open-appsec → Learning) */
const labelEvent = async (event: SecurityEvent, decision: Decision) => {
	try {
		const group = await getEventGroup(event.id);
		if (group.labelled) {
			showError(intl.formatMessage({ id: "npmos.events.label.labelled" }));
			return;
		}
		showLabelModal({ group, decision });
	} catch (err: any) {
		showError(err.message);
	}
};

const WafEventModal = EasyModal.create(({ visible, remove, event: summary, onFilter }: Props) => {
	const can = useCan();
	const full = useEvent(summary.id, summary.time);
	// lists may hold only a part of the fields: the whole event once it is loaded
	const event: SecurityEvent = { ...summary, ...full.data };
	const matched = event.sample || event.parameter || event.location;
	// whether CrowdSec bans the source now: "ban" again would only add a second decision
	const csView = !!event.sourceIp && can("crowdsec", "view");
	const decisions = useDecisions({ q: event.sourceIp || "", limit: 50 }, { enabled: csView });
	const active = (decisions.data?.items ?? []).filter((d) => d.value === event.sourceIp);
	const longest = active.reduce<(typeof active)[number] | null>(
		(a, d) => (!a || remainingSeconds(d.duration) > remainingSeconds(a.duration) ? d : a),
		null,
	);
	const request = [event.method, event.uri + (event.query ? `?${event.query}` : "")].filter(Boolean).join(" ");
	const filter = (field: FilterField, value: string, label: React.ReactNode) =>
		onFilter ? (
			<button
				type="button"
				className="btn btn-link p-0 text-reset text-decoration-underline"
				title={intl.formatMessage({ id: "npmos.events.filter-by" })}
				onClick={() => {
					onFilter(field, value);
					remove();
				}}
			>
				{label}
			</button>
		) : (
			label
		);
	return (
		<Modal show={visible} onHide={remove} size="xl">
			<Modal.Header closeButton>
				<Modal.Title>
					{event.incidentType || event.name} <SeverityBadge severity={event.severity} />{" "}
					<ActionBadge action={event.action} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<div className="datagrid mb-3">
					<Field label="npmos.waf.events.time" value={<EventTime time={event.time} />} />
					<Field
						label="npmos.waf.events.source-ip"
						value={
							event.sourceIp &&
							filter(
								"ip",
								event.sourceIp,
								`${event.sourceIp}${event.sourcePort ? `:${event.sourcePort}` : ""}`,
							)
						}
					/>
					<Field label="npmos.events.country" value={event.sourceCountry} />
					<Field label="npmos.waf.events.proxy-ip" value={event.proxyIp} />
					<Field
						label="npmos.waf.events.host"
						value={event.host ? filter("host", event.host, event.host) : event.asset}
					/>
					<Field label="npmos.waf.events.request" value={request} />
					<Field label="npmos.events.response-code" value={event.responseCode} />
					<Field label="npmos.waf.events.event" value={event.name} />
					<Field label="npmos.waf.events.component" value={event.service} />
				</div>
				{(matched || event.score !== null || event.indicators) && (
					<div className="card card-sm border-danger mb-3">
						<div className="card-status-start bg-red" />
						<div className="card-body">
							<h4 className="text-red">
								<T
									id={
										event.kind === "crowdsec"
											? "npmos.waf.events.matched-crowdsec"
											: "npmos.waf.events.matched"
									}
								/>
							</h4>
							<div className="datagrid">
								<Field label="npmos.waf.events.matched-location" value={event.location} />
								<Field label="npmos.waf.events.matched-parameter" value={event.parameter} />
								<Field label="npmos.events.score" value={event.score} />
								<Field label="npmos.events.confidence" value={event.confidence} />
								<Field label="npmos.events.indicators" value={event.indicators} />
								<Field label="npmos.events.rule" value={event.rule} />
								<Field
									label="npmos.events.override"
									value={event.override !== "None" && event.override}
								/>
							</div>
							{event.sample && <pre className="mt-2 mb-0 text-wrap">{event.sample}</pre>}
						</div>
					</div>
				)}
				<h4>
					<T id="npmos.events.raw" />
				</h4>
				<pre className="mb-0" style={{ maxHeight: "45vh", overflow: "auto" }}>
					{full.data ? JSON.stringify(full.data.raw, null, 2) : full.isError ? full.error.message : "…"}
				</pre>
			</Modal.Body>
			<Modal.Footer>
				{csView && decisions.data && (
					<span className="me-auto small text-secondary">
						{longest ? (
							<T
								id="npmos.events.cs-banned"
								data={{
									decision: ["ban", "captcha"].includes(longest.type)
										? intl.formatMessage({ id: `npmos.crowdsec.decision.${longest.type}` })
										: longest.type,
									left: remaining(longest.duration),
								}}
							/>
						) : (
							<T id="npmos.events.cs-not-banned" />
						)}
					</span>
				)}
				{event.sourceIp && can("crowdsec", "decide") && (
					<Button
						className="btn-outline-danger"
						onClick={() => {
							remove();
							showBanModal({
								values: [event.sourceIp],
								reason: event.incidentType || event.name,
								extend: !!longest,
							});
						}}
					>
						<T id={longest ? "npmos.events.extend-ban" : "npmos.events.ban-ip"} />
					</Button>
				)}
				{event.kind === "security" && can("waf_learning", "label") && (
					<>
						<Button onClick={() => labelEvent(event, "benign").then(remove)}>
							<T id="npmos.events.label.benign" />
						</Button>
						<Button onClick={() => labelEvent(event, "malicious").then(remove)}>
							<T id="npmos.events.label.malicious" />
						</Button>
					</>
				)}
				{event.kind === "security" && can("waf_policy", "manage") && (
					<Button onClick={() => createException(event).then(remove)}>
						<T id="npmos.events.create-exception" />
					</Button>
				)}
				<Button onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showWafEventModal = (event: SecurityEvent, onFilter?: Props["onFilter"]) =>
	EasyModal.show(WafEventModal, { event, onFilter });
