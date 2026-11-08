// Analytics -> Live: what is happening now. The last five minutes of events (how many, how many refused) and the
// newest of them, every five seconds; the charts of the page follow the last hour at the same pace.
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import { Link } from "react-router-dom";
import { T } from "src/locale";
import { getEvents } from "../../api";
import { timeAgo } from "../../ui/time";
import { ActionBadge } from "../WafEvents/badges";
import styles from "./Analytics.module.css";

export const LIVE_MS = 5000;
const WINDOW_MS = 5 * 60 * 1000;

export function LiveNow({ host }: { host: string }) {
	const { data } = useQuery({
		queryKey: ["nginxions-analytics-live", host],
		queryFn: () =>
			getEvents({
				from: new Date(Date.now() - WINDOW_MS).toISOString(),
				limit: 200,
				...(host ? { host } : {}),
			}),
		refetchInterval: LIVE_MS,
		placeholderData: (previous) => previous,
	});
	const events = data?.events ?? [];
	const refused = events.filter((e) => ["Prevent", "ban", "captcha", "denied"].includes(e.action)).length;
	const sources = new Set(events.map((e) => e.sourceIp).filter(Boolean)).size;
	return (
		<section className={cn(styles.panel, styles.wide, styles.live)}>
			<div className={styles.liveHead}>
				<span className={styles.pulse} aria-hidden="true" />
				<h3 className={styles.panelTitle}>
					<T id="nginxions.analytics.live.title" />
				</h3>
				<span className="text-secondary small ms-auto">
					<T id="nginxions.analytics.live.window" />
				</span>
			</div>
			<div className={styles.liveCounts}>
				<div>
					<strong>{data?.totalCapped ? `${data.total}+` : (data?.total ?? 0)}</strong>
					<T id="nginxions.analytics.live.events" />
				</div>
				<div>
					<strong>{refused}</strong>
					<T id="nginxions.analytics.live.refused" />
				</div>
				<div>
					<strong>{sources}</strong>
					<T id="nginxions.analytics.live.sources" />
				</div>
			</div>
			{events.length === 0 ? (
				<p className="text-secondary small mb-0">
					<T id="nginxions.analytics.live.quiet" />
				</p>
			) : (
				<ul className={styles.liveList}>
					{events.slice(0, 8).map((e) => (
						<li key={`${e.id}-${e.time}`}>
							<span className={styles.liveTime}>{timeAgo(e.time, Date.now(), "narrow")}</span>
							<ActionBadge action={e.action} />
							<span className="text-truncate">{e.incidentType || e.name}</span>
							<span className="font-monospace text-secondary small">{e.sourceIp}</span>
							<span className="text-secondary small text-truncate">{e.host}</span>
						</li>
					))}
				</ul>
			)}
			<Link to="/waf/events" className="small">
				<T id="nginxions.analytics.live.all" />
			</Link>
		</section>
	);
}
