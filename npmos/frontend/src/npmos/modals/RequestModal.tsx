// One request of the request log (Events → Requests, Events → All): what was asked, who asked, what the host and the
// server behind it answered and how fast. The address can be banned in CrowdSec from here (as from an event), the
// list filtered by it, its events opened; a domain that is not in Hosts can be added.
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import type { RequestLogRow } from "../api";
import logStyles from "../pages/RequestLog/RequestLog.module.css";
import analyticsStyles from "../pages/WafAnalytics/Analytics.module.css";
import { useCan } from "../rbac/hooks";
import { countryName, formatBytes, formatMs } from "../ui/charts/format";
import { dateTime } from "../ui/time";
import { useBan } from "./BanActions";

type FilterField = "ip" | "host";

interface Props extends InnerModalProps {
	request: RequestLogRow;
	/** show only the requests of this IP or host (the list the window was opened from) */
	onFilter?: (field: FilterField, value: string) => void;
	/** the window is outside the router: the page navigates */
	navigate?: (to: string) => void;
}

const t = (id: string) => intl.formatMessage({ id });

export const statusTone = (s: number) =>
	s >= 500 ? logStyles.s5 : s >= 400 ? logStyles.s4 : s >= 300 ? logStyles.s3 : logStyles.s2;

export const hostLabel = (host: string) => (host === "_" || !host ? t("npmos.traffic.host.none") : host);

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

const RequestModal = EasyModal.create(({ visible, remove, request: r, onFilter, navigate }: Props) => {
	const can = useCan();
	const ban = useBan(r.ip, `${r.method} ${hostLabel(r.host)}${r.path}`, remove);
	const go = (to: string) => {
		remove();
		navigate?.(to);
	};
	const filter = (field: FilterField, value: string, label: React.ReactNode) =>
		onFilter && value ? (
			<button
				type="button"
				className="btn btn-link p-0 text-reset text-decoration-underline"
				title={t("npmos.events.filter-by")}
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
				<Modal.Title className="text-break">
					<span className={cn(logStyles.status, statusTone(r.status))}>{r.status}</span> {r.method}{" "}
					{hostLabel(r.host)}
					{r.path}
					{!r.known && (
						<span className={cn(analyticsStyles.unknown, "ms-2 small")}>
							{t("npmos.traffic.host.unknown")}
						</span>
					)}
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<div className="datagrid mb-3">
					<Field label="npmos.traffic.log.time" value={dateTime(r.time)} />
					<Field label="npmos.traffic.filter.ip" value={filter("ip", r.ip, r.ip)} />
					<Field label="npmos.traffic.filter.country" value={r.country ? countryName(r.country) : "—"} />
					<Field
						label="npmos.traffic.filter.host"
						value={filter("host", r.host, `${hostLabel(r.host)}${r.port ? `:${r.port}` : ""}`)}
					/>
					<Field label="npmos.traffic.log.request" value={`${r.method} ${r.path}`} />
					<Field label="npmos.traffic.filter.status" value={r.status} />
					<Field
						label="npmos.traffic.log.size"
						value={`${formatBytes(r.bytes)} / ${formatBytes(r.requestBytes)}`}
					/>
					<Field label="npmos.traffic.log.duration" value={formatMs(r.durationMs)} />
					<Field label="npmos.traffic.filter.origin" value={r.upstreamAddr || "—"} />
					<Field label="npmos.traffic.log.origin-status" value={r.upstreamStatus ?? "—"} />
					<Field label="npmos.traffic.log.origin-time" value={formatMs(r.upstreamMs)} />
					<Field label="npmos.traffic.filter.cache" value={r.cache || "—"} />
					<Field label="npmos.traffic.filter.protocol" value={`${r.protocol}${r.tls ? ` · ${r.tls}` : ""}`} />
					<Field label="npmos.traffic.filter.contentType" value={r.contentType || "—"} />
					<Field label="npmos.traffic.log.referer" value={r.refererHost || "—"} />
					<Field
						label="npmos.traffic.filter.device"
						value={
							r.device === "bot" || !r.browser
								? t(`npmos.traffic.device.${r.device || "other"}`)
								: `${r.browser} · ${r.os} · ${t(`npmos.traffic.device.${r.device}`)}`
						}
					/>
					<Field
						label="npmos.traffic.filter.mitigated"
						value={t(
							r.mitigated ? "npmos.traffic.filter.mitigated.yes" : "npmos.traffic.filter.mitigated.no",
						)}
					/>
				</div>
				<h4>
					<T id="npmos.traffic.log.agent" />
				</h4>
				<pre className="mb-0 text-wrap">{r.userAgent || "—"}</pre>
			</Modal.Body>
			<Modal.Footer>
				{ban.status}
				{ban.button}
				{navigate && can("waf_events") && (
					<Button onClick={() => go(`/waf/events?kind=all&ip=${encodeURIComponent(r.ip)}`)}>
						<T id="npmos.traffic.log.ip-events" />
					</Button>
				)}
				{navigate && !r.known && can("proxy_hosts", "manage") && (
					<Button onClick={() => go("/hosts")}>
						<T id="npmos.traffic.unknown-hosts.add" />
					</Button>
				)}
				<Button onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showRequestModal = (request: RequestLogRow, onFilter?: Props["onFilter"], navigate?: Props["navigate"]) =>
	EasyModal.show(RequestModal, { request, onFilter, navigate });
