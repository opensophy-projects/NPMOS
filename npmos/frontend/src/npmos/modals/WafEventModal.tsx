// One security event of the open-appsec agent: what was matched (as the red zone of the
// open-appsec-npm Security Log) and the whole event as the agent wrote it.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { T } from "src/locale";
import type { WafEvent } from "../api";
import { ActionBadge, EventTime, SeverityBadge } from "../pages/WafEvents/badges";

interface Props extends InnerModalProps {
	event: WafEvent;
}

function Field({ label, value }: { label: string; value?: React.ReactNode }) {
	if (!value) return null;
	return (
		<div className="datagrid-item">
			<div className="datagrid-title">
				<T id={label} />
			</div>
			<div className="datagrid-content text-break">{value}</div>
		</div>
	);
}

const WafEventModal = EasyModal.create(({ visible, remove, event }: Props) => {
	const matched = event.matchedSample || event.matchedParameter || event.matchedLocation;
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
					<Field label="npmos.waf.events.time" value={event.time && <EventTime time={event.time} />} />
					<Field label="npmos.waf.events.source-ip" value={event.sourceIp} />
					<Field label="npmos.waf.events.proxy-ip" value={event.proxyIp} />
					<Field label="npmos.waf.events.host" value={event.host || event.asset} />
					<Field
						label="npmos.waf.events.request"
						value={[event.method, event.uri].filter(Boolean).join(" ")}
					/>
					<Field label="npmos.waf.events.event" value={event.name} />
					<Field label="npmos.waf.events.component" value={event.service || event.source} />
				</div>
				{matched && (
					<div className="card card-sm border-danger mb-3">
						<div className="card-status-start bg-red" />
						<div className="card-body">
							<h4 className="text-red">
								<T id="npmos.waf.events.matched" />
							</h4>
							<div className="datagrid">
								<Field label="npmos.waf.events.matched-location" value={event.matchedLocation} />
								<Field label="npmos.waf.events.matched-parameter" value={event.matchedParameter} />
							</div>
							{event.matchedSample && <pre className="mt-2 mb-0 text-wrap">{event.matchedSample}</pre>}
						</div>
					</div>
				)}
				<pre className="mb-0" style={{ maxHeight: "45vh", overflow: "auto" }}>
					{JSON.stringify(event.raw, null, 2)}
				</pre>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showWafEventModal = (event: WafEvent) => EasyModal.show(WafEventModal, { event });
