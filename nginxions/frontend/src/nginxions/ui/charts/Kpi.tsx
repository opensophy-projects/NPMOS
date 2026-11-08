// A KPI card of Analytics: label, value, change against the previous period of the same length, a sparkline of the
// period at the bottom (the cards of the Cloudflare dashboard, in the card style of NginxionS).
import cn from "classnames";
import type { ReactNode } from "react";
import { intl } from "src/locale";
import { InfoTip, infoOfNode } from "../InfoTip";
import { Sparkline } from "./AreaChart";
import styles from "./charts.module.css";
import { formatChange } from "./format";

interface KpiProps {
	label: ReactNode;
	value: ReactNode;
	/** relative change, e.g. 0.12 */
	change?: number | null;
	/** a rise is bad (errors, response time): it is shown in the accent colour */
	riseIsBad?: boolean;
	series?: (number | null)[] | null;
	color?: string;
	hint?: ReactNode;
	title?: string;
}

export function Kpi({ label, value, change, riseIsBad, series, color, hint, title }: KpiProps) {
	const text = formatChange(change);
	const info = infoOfNode(label);
	const good = change !== null && change !== undefined && (riseIsBad ? change <= 0 : change >= 0);
	return (
		<div className={cn(styles.surface, styles.kpi)} title={title}>
			<div className={styles.kpiLabel}>
				{label}
				{info && <InfoTip id={info} />}
			</div>
			<div className={styles.kpiValue}>
				{value}
				{text && <span className={cn(styles.change, good ? styles.up : styles.down)}>{text}</span>}
			</div>
			{hint && <div className={styles.kpiHint}>{hint}</div>}
			{series && series.length > 1 ? (
				<div className={styles.spark}>
					<Sparkline values={series} color={color} />
					{!series.some((v) => v) && (
						<span className={styles.sparkEmpty}>
							{intl.formatMessage({ id: "nginxions.traffic.no-data" })}
						</span>
					)}
				</div>
			) : (
				<div style={{ height: 12 }} />
			)}
		</div>
	);
}

export function Kpis({ children }: { children: ReactNode }) {
	return <div className={styles.kpis}>{children}</div>;
}
