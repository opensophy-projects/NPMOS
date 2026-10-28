// Small SVG charts on the theme tokens (no chart library in the upstream frontend): a stacked bar
// timeline with a hover tooltip, a bar list for top lists, KPI tiles. Series colours are
// --series-1..3 in a fixed order (validated for both themes, see tokens.css).
import cn from "classnames";
import { type ReactNode, useLayoutEffect, useRef, useState } from "react";
import { intl } from "src/locale";
import styles from "./Charts.module.css";

export const formatNumber = (n: number) => intl.formatNumber(n);

/** a round axis maximum and its step */
export const niceScale = (max: number, ticks = 4) => {
	if (max <= 0) return { max: ticks, step: 1 };
	const raw = max / ticks;
	const magnitude = 10 ** Math.floor(Math.log10(raw));
	const step = [1, 2, 2.5, 5, 10].map((m) => m * magnitude).find((s) => s >= raw) ?? 10 * magnitude;
	return { max: Math.ceil(max / step) * step, step };
};

function useWidth() {
	const ref = useRef<HTMLDivElement>(null);
	const [width, setWidth] = useState(600);
	useLayoutEffect(() => {
		if (!ref.current) return;
		const observer = new ResizeObserver(([entry]) => setWidth(Math.max(240, entry.contentRect.width)));
		observer.observe(ref.current);
		return () => observer.disconnect();
	}, []);
	return { ref, width };
}

export interface Series<T> {
	key: keyof T & string;
	label: string;
	/** CSS colour, e.g. var(--series-1) */
	color: string;
}

interface StackedBarsProps<T> {
	data: T[];
	series: Series<T>[];
	/** label of a bucket on the axis and in the tooltip */
	xLabel: (item: T) => string;
	tooltipTitle: (item: T) => string;
	height?: number;
	emptyText: string;
	ariaLabel: string;
}

const PAD = { top: 8, right: 8, bottom: 22, left: 44 };

/** values stacked per bucket; the legend names the series (colour is never the only cue) */
export function StackedBars<T>({
	data,
	series,
	xLabel,
	tooltipTitle,
	height = 220,
	emptyText,
	ariaLabel,
}: StackedBarsProps<T>) {
	const { ref, width } = useWidth();
	const [hover, setHover] = useState<number | null>(null);
	const value = (item: T, key: keyof T) => Number(item[key]) || 0;
	const totals = data.map((item) => series.reduce((n, s) => n + value(item, s.key), 0));
	const scale = niceScale(Math.max(0, ...totals));
	const innerW = width - PAD.left - PAD.right;
	const innerH = height - PAD.top - PAD.bottom;
	const slot = data.length ? innerW / data.length : innerW;
	const gap = slot > 6 ? 2 : 0;
	const barW = Math.max(1, slot - gap);
	const y = (v: number) => PAD.top + innerH - (v / scale.max) * innerH;
	const labelEvery = Math.max(1, Math.ceil(data.length / Math.max(2, Math.floor(innerW / 70))));
	const ticks = Array.from({ length: Math.round(scale.max / scale.step) + 1 }, (_, i) => i * scale.step);

	return (
		<div className={styles.chart} ref={ref}>
			<div className={styles.legend}>
				{series.map((s) => (
					<span key={s.key} className={styles.legendItem}>
						<span className={styles.swatch} style={{ background: s.color }} />
						{s.label}
					</span>
				))}
			</div>
			{totals.every((t) => t === 0) ? (
				<div className={styles.empty} style={{ height }}>
					{emptyText}
				</div>
			) : (
				<svg className={styles.svg} width={width} height={height} role="img" aria-label={ariaLabel}>
					{ticks.map((t) => (
						<g key={t}>
							<line className={styles.grid} x1={PAD.left} x2={width - PAD.right} y1={y(t)} y2={y(t)} />
							<text className={styles.axis} x={PAD.left - 6} y={y(t)} dy="0.32em" textAnchor="end">
								{formatNumber(t)}
							</text>
						</g>
					))}
					{data.map((item, i) => {
						const x = PAD.left + i * slot + gap / 2;
						let base = 0;
						const segments = series
							.map((s) => ({ s, v: value(item, s.key) }))
							.filter(({ v }) => v > 0)
							.map(({ s, v }, j, all) => {
								const top = y(base + v);
								const bottom = y(base);
								base += v;
								const last = j === all.length - 1;
								// 2px surface gap between stacked segments, rounded data end on the top one
								const h = Math.max(1, bottom - top - (last ? 0 : 2));
								return (
									<rect
										key={s.key}
										x={x}
										y={top + (last ? 0 : 2)}
										width={barW}
										height={h}
										rx={last && barW > 6 ? Math.min(4, barW / 2) : 0}
										fill={s.color}
									/>
								);
							});
						return (
							<g key={i}>
								{hover === i && (
									<rect
										className={styles.hover}
										x={PAD.left + i * slot}
										y={PAD.top}
										width={slot}
										height={innerH}
									/>
								)}
								{segments}
								{i % labelEvery === 0 && (
									<text className={styles.axis} x={x + barW / 2} y={height - 6} textAnchor="middle">
										{xLabel(item)}
									</text>
								)}
								{/* biome-ignore lint/a11y/noStaticElementInteractions: hover tooltip only; the numbers are in the lists and the events */}
								<rect
									className={styles.hit}
									x={PAD.left + i * slot}
									y={PAD.top}
									width={slot}
									height={innerH}
									onMouseEnter={() => setHover(i)}
									onMouseLeave={() => setHover(null)}
								/>
							</g>
						);
					})}
				</svg>
			)}
			{hover !== null && data[hover] && (
				<div
					className={styles.tooltip}
					style={{
						top: 28,
						left: Math.min(width - 180, Math.max(0, PAD.left + (hover + 1) * slot + 8)),
					}}
				>
					<div className={styles.tooltipTitle}>{tooltipTitle(data[hover])}</div>
					{series.map((s) => (
						<div key={s.key} className={styles.tooltipRow}>
							<span className={styles.swatch} style={{ background: s.color }} />
							<span>{s.label}</span>
							<span>{formatNumber(value(data[hover], s.key))}</span>
						</div>
					))}
				</div>
			)}
		</div>
	);
}

export interface BarItem {
	key: string;
	label: ReactNode;
	value: number;
	sub?: ReactNode;
	title?: string;
	onClick?: () => void;
}

/** top lists: label and value in text colours, one hue for the bars */
export function BarList({ items, emptyText }: { items: BarItem[]; emptyText: string }) {
	if (!items.length) return <div className={cn(styles.empty, "py-3")}>{emptyText}</div>;
	const max = Math.max(...items.map((i) => i.value), 1);
	return (
		<ul className={styles.list}>
			{items.map((item) => (
				<li key={item.key} className={styles.listItem} title={item.title}>
					<span className={styles.listLabel}>
						{item.onClick ? (
							<button type="button" className={styles.listButton} onClick={item.onClick}>
								{item.label}
							</button>
						) : (
							item.label
						)}
						{item.sub && <span className={styles.listSub}> · {item.sub}</span>}
					</span>
					<span className={styles.listValue}>{formatNumber(item.value)}</span>
					<span className={styles.track}>
						<span
							className={styles.bar}
							style={{ display: "block", width: `${(item.value / max) * 100}%` }}
						/>
					</span>
				</li>
			))}
		</ul>
	);
}

export function Tiles({ children }: { children: ReactNode }) {
	return <div className={styles.tiles}>{children}</div>;
}

export function Tile({ value, label, hint }: { value: ReactNode; label: ReactNode; hint?: ReactNode }) {
	return (
		<div className={cn("card", styles.tile)}>
			<div className={styles.tileValue}>{value}</div>
			<div className={styles.tileLabel}>{label}</div>
			{hint && <div className={styles.tileHint}>{hint}</div>}
		</div>
	);
}
