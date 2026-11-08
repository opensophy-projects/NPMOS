// Area chart of Analytics, after AreaChart of the opensophy site (apps/web/src/lib/components/charts/AreaChart.svelte):
// monotone curves, a dashed line over a vertical gradient fill, a stack or overlapping areas, a dashed cursor with
// the values of the bucket, a legend with the totals that highlights a series on click. Plain SVG on the theme
// tokens, no chart library.
import cn from "classnames";
import { type ReactNode, useId, useState } from "react";
import { niceScale, useWidth } from "../Charts";
import styles from "./charts.module.css";
import { areaPath, linePath } from "./curves";
import { formatCount } from "./format";

export interface AreaSeries<T> {
	key: keyof T & string;
	label: string;
	/** CSS colour, e.g. var(--series-1) */
	color: string;
}

interface AreaChartProps<T> {
	data: T[];
	series: AreaSeries<T>[];
	/** stack the series (a total) or let them overlap (e.g. percentiles) */
	stacked?: boolean;
	height?: number;
	xLabel: (item: T) => string;
	tooltipTitle: (item: T) => string;
	/** values on the axis, the tooltip and the legend */
	format?: (n: number) => string;
	/** legend totals: the sum (default), none for values that do not add up (percentiles, ms) */
	legendTotal?: "sum" | "none";
	emptyText: string;
	ariaLabel: string;
	legend?: boolean;
	/** an extra line under the tooltip title */
	tooltipExtra?: (item: T) => ReactNode;
}

const PAD = { top: 10, right: 12, bottom: 24, left: 48 };

const value = <T,>(item: T, key: keyof T): number | null => {
	const v = item[key] as unknown;
	if (v === null || v === undefined) return null;
	const n = Number(v);
	return Number.isFinite(n) ? n : null;
};

export function AreaChart<T>({
	data,
	series,
	stacked = false,
	height = 240,
	xLabel,
	tooltipTitle,
	format = formatCount,
	legendTotal = "sum",
	emptyText,
	ariaLabel,
	legend = true,
	tooltipExtra,
}: AreaChartProps<T>) {
	const id = useId().replace(/:/g, "");
	const { ref, width } = useWidth();
	const [hover, setHover] = useState<number | null>(null);
	const [selected, setSelected] = useState<string | null>(null);

	// stacks: [base, top] per series and bucket; null keeps a gap (no value)
	const stacks = series.map(() => [] as ([number, number] | null)[]);
	let max = 0;
	data.forEach((item, i) => {
		let base = 0;
		series.forEach((s, j) => {
			const v = value(item, s.key);
			if (v === null) {
				stacks[j][i] = null;
				return;
			}
			const b = stacked ? base : 0;
			stacks[j][i] = [b, b + v];
			if (stacked) base += v;
			max = Math.max(max, b + v);
		});
	});
	const empty = max === 0;
	const scale = niceScale(max);
	const innerW = Math.max(1, width - PAD.left - PAD.right);
	const innerH = height - PAD.top - PAD.bottom;
	const step = data.length > 1 ? innerW / (data.length - 1) : innerW;
	const x = (i: number) => PAD.left + (data.length > 1 ? i * step : innerW / 2);
	const y = (v: number) => PAD.top + innerH - (v / scale.max) * innerH;
	const ticks = Array.from({ length: Math.round(scale.max / scale.step) + 1 }, (_, i) => i * scale.step);
	const labelEvery = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(innerW / 72))));
	const totals = series.map((s) => data.reduce((n, item) => n + (value(item, s.key) ?? 0), 0));

	const onMove = (e: React.MouseEvent<SVGRectElement>) => {
		const box = e.currentTarget.getBoundingClientRect();
		const px = e.clientX - box.left;
		const i = data.length > 1 ? Math.round(px / step) : 0;
		setHover(Math.min(data.length - 1, Math.max(0, i)));
	};
	const dim = (key: string) => selected !== null && selected !== key;

	return (
		<div className={styles.chart} ref={ref}>
			{legend && (
				<div className={styles.legend}>
					{series.map((s, j) => (
						<button
							key={s.key}
							type="button"
							className={cn(styles.legendItem, dim(s.key) && styles.legendDim)}
							aria-pressed={selected === s.key}
							onClick={() => setSelected(selected === s.key ? null : s.key)}
						>
							<span className={styles.dot} style={{ background: s.color }} />
							{s.label}
							{legendTotal === "sum" && <strong>{format(totals[j])}</strong>}
						</button>
					))}
				</div>
			)}
			<svg className={styles.svg} width={width} height={height} role="img" aria-label={ariaLabel}>
				<defs>
					{series.map((s, j) => (
						<linearGradient key={s.key} id={`${id}-fill-${j}`} x1="0" y1="0" x2="0" y2="1">
							<stop offset="0%" stopColor={s.color} stopOpacity={stacked ? 0.42 : 0.3} />
							<stop offset="100%" stopColor={s.color} stopOpacity={stacked ? 0.08 : 0} />
						</linearGradient>
					))}
				</defs>
				{ticks.map((tk) => (
					<g key={tk}>
						<line className={styles.grid} x1={PAD.left} x2={width - PAD.right} y1={y(tk)} y2={y(tk)} />
						<text className={styles.axis} x={PAD.left - 8} y={y(tk)} dy="0.32em" textAnchor="end">
							{empty ? (tk === 0 ? "0" : "") : format(tk)}
						</text>
					</g>
				))}
				{data.map((item, i) =>
					i % labelEvery === 0 ? (
						<text key={i} className={styles.axis} x={x(i)} y={height - 6} textAnchor="middle">
							{xLabel(item)}
						</text>
					) : null,
				)}
				{!empty &&
					// overlapping areas: the larger ones (later series, e.g. p99) behind the smaller ones
					(stacked
						? series.map((s, j) => [s, j] as const)
						: series.map((s, j) => [s, j] as const).reverse()
					).map(([s, j]) => {
						// a series without a value in the whole period draws no line over the others
						if (totals[j] === 0 && series.length > 1) return null;
						const points = stacks[j].map((p, i) => (p ? { x: x(i), y: y(p[1]), y0: y(p[0]) } : null));
						return (
							<g key={s.key} className={styles.area} opacity={dim(s.key) ? 0.25 : 1}>
								<path d={areaPath(points)} fill={`url(#${id}-fill-${j})`} stroke="none" />
								<path
									d={linePath(points)}
									fill="none"
									stroke={s.color}
									strokeWidth={1.5}
									strokeDasharray="4 3"
									strokeLinejoin="round"
								/>
							</g>
						);
					})}
				{empty && <line className={styles.grid} x1={PAD.left} x2={width - PAD.right} y1={y(0)} y2={y(0)} />}
				{hover !== null && !empty && (
					<g pointerEvents="none">
						<line
							className={styles.cursor}
							x1={x(hover)}
							x2={x(hover)}
							y1={PAD.top}
							y2={PAD.top + innerH}
						/>
						{series.map((s, j) => {
							const p = stacks[j][hover];
							if (!p || dim(s.key)) return null;
							return (
								<circle
									key={s.key}
									cx={x(hover)}
									cy={y(p[1])}
									r={3.5}
									fill={s.color}
									stroke="var(--background)"
									strokeWidth={1.5}
								/>
							);
						})}
					</g>
				)}
				{/* biome-ignore lint/a11y/noStaticElementInteractions: hover tooltip only; the totals are in the legend */}
				<rect
					className={styles.overlay}
					x={PAD.left}
					y={PAD.top}
					width={innerW}
					height={innerH}
					onMouseMove={onMove}
					onMouseLeave={() => setHover(null)}
				/>
			</svg>
			{empty && <div className={styles.empty}>{emptyText}</div>}
			{hover !== null && !empty && data[hover] && (
				<div
					className={styles.tooltip}
					style={{
						top: legend ? 32 : 4,
						left: x(hover) + 196 > width ? Math.max(0, x(hover) - 196) : x(hover) + 12,
					}}
				>
					<div className={styles.tooltipTitle}>{tooltipTitle(data[hover])}</div>
					{tooltipExtra?.(data[hover])}
					{series.map((s) => {
						const v = value(data[hover], s.key);
						return (
							<div key={s.key} className={styles.tooltipRow}>
								<span className={styles.dot} style={{ background: s.color }} />
								<span>{s.label}</span>
								<span>{v === null ? "—" : format(v)}</span>
							</div>
						);
					})}
				</div>
			)}
		</div>
	);
}

/** a small area chart without axes for KPI cards (the shape of a value over the period) */
export function Sparkline({
	values,
	color = "var(--series-1)",
	height = 40,
}: {
	values: (number | null)[];
	color?: string;
	height?: number;
}) {
	const id = useId().replace(/:/g, "");
	const { ref, width } = useWidth();
	const max = Math.max(0, ...values.map((v) => v ?? 0));
	const step = values.length > 1 ? width / (values.length - 1) : width;
	const y = (v: number) => (max > 0 ? 4 + (height - 6) * (1 - v / max) : height - 2);
	const points = values.map((v, i) => (v === null ? null : { x: i * step, y: y(v), y0: height }));
	return (
		<div ref={ref} className={styles.spark}>
			<svg width={width} height={height} className={styles.svg} aria-hidden="true">
				<defs>
					<linearGradient id={`${id}-spark`} x1="0" y1="0" x2="0" y2="1">
						<stop offset="0%" stopColor={color} stopOpacity={max > 0 ? 0.28 : 0.06} />
						<stop offset="100%" stopColor={color} stopOpacity={0} />
					</linearGradient>
				</defs>
				<path d={areaPath(points)} fill={`url(#${id}-spark)`} />
				<path
					d={linePath(points)}
					fill="none"
					stroke={max > 0 ? color : "var(--border-strong)"}
					strokeWidth={1.25}
					strokeDasharray={max > 0 ? undefined : "4 3"}
				/>
			</svg>
		</div>
	);
}
