// World map of Analytics: countries coloured by a count (requests, page views, attacks), the name and the count on
// hover, a click filters by the country. Outlines of Natural Earth 1:110m (public domain) in the bundle
// (worldMap.json, scripts/gen-world-map.mjs): no tiles, nothing is fetched from the internet.
import cn from "classnames";
import { useEffect, useState } from "react";
import styles from "./charts.module.css";
import { countryName, formatCount } from "./format";

interface MapData {
	width: number;
	height: number;
	top: number;
	countries: { c: string; n: string; d: string }[];
}

let cached: MapData | null = null;

/** the outlines, loaded once on first use (a separate chunk) */
export function useWorldMap() {
	const [data, setData] = useState<MapData | null>(cached);
	useEffect(() => {
		if (cached) return;
		let alive = true;
		import("../worldMap.json").then((m) => {
			cached = (m.default ?? m) as MapData;
			if (alive) setData(cached);
		});
		return () => {
			alive = false;
		};
	}, []);
	return data;
}

interface WorldMapProps {
	/** ISO code → count */
	values: Map<string, number>;
	/** colour of the highest count */
	color?: string;
	format?: (n: number) => string;
	/** name of the counted thing in the tooltip, e.g. "requests" */
	unit: string;
	lowLabel: string;
	highLabel: string;
	ariaLabel: string;
	onSelect?: (code: string) => void;
	selected?: string;
}

export function WorldMap({
	values,
	color = "var(--series-1)",
	format = formatCount,
	unit,
	lowLabel,
	highLabel,
	ariaLabel,
	onSelect,
	selected,
}: WorldMapProps) {
	const map = useWorldMap();
	const [hover, setHover] = useState<{ code: string; name: string; x: number; y: number } | null>(null);
	const max = Math.max(0, ...values.values());
	// a square root scale: one loud country does not wash out the others
	const fill = (code: string) => {
		const v = values.get(code) ?? 0;
		if (!v || !max) return "var(--background-muted)";
		const share = Math.round(18 + 82 * Math.sqrt(v / max));
		return `color-mix(in oklab, ${color} ${share}%, var(--background-muted))`;
	};
	if (!map) return <div className={styles.map} style={{ aspectRatio: "1000 / 435" }} />;
	return (
		<div className={styles.map}>
			<svg
				className={styles.mapSvg}
				viewBox={`0 ${map.top} ${map.width} ${map.height - map.top}`}
				role="img"
				aria-label={ariaLabel}
				onMouseLeave={() => setHover(null)}
			>
				{map.countries.map((c) => {
					const v = values.get(c.c) ?? 0;
					const active = !!onSelect && !!c.c && v > 0;
					return (
						// biome-ignore lint/a11y/noStaticElementInteractions: the counts are also in the list of countries
						<path
							key={`${c.c}-${c.n}`}
							d={c.d}
							className={cn(
								styles.country,
								active && styles.countryActive,
								(selected === c.c || hover?.code === c.c) && c.c && styles.countryHover,
							)}
							fill={
								selected && selected !== c.c && v
									? `color-mix(in oklab, ${fill(c.c)} 45%, var(--background-muted))`
									: fill(c.c)
							}
							onMouseMove={(e) => {
								const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
								setHover({
									code: c.c,
									name: c.c ? countryName(c.c) : c.n,
									x: e.clientX - box.left,
									y: e.clientY - box.top,
								});
							}}
							onClick={active ? () => onSelect?.(c.c) : undefined}
						/>
					);
				})}
			</svg>
			{hover && (
				<div className={styles.tooltip} style={{ top: hover.y + 14, left: Math.max(0, hover.x - 80) }}>
					<div className={styles.tooltipTitle}>{hover.name}</div>
					<div className={styles.tooltipRow}>
						<span className={styles.dot} style={{ background: color }} />
						<span>{unit}</span>
						<span>{format(values.get(hover.code) ?? 0)}</span>
					</div>
				</div>
			)}
			<div className={styles.scale}>
				<span>{lowLabel}</span>
				<span
					className={styles.scaleBar}
					style={{ background: `linear-gradient(90deg, var(--background-muted), ${color})` }}
				/>
				<span>{highLabel}</span>
			</div>
		</div>
	);
}
