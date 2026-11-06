// Paths of the area chart: monotone cubic interpolation (d3-shape curveMonotoneX), as AreaChart of the opensophy site
// (apps/web/src/lib/components/charts/curves.ts). A gap (null) splits a line into segments.
export interface Point {
	x: number;
	y: number;
}

const n = (v: number) => String(Math.round(v * 100) / 100);
const pt = (p: Point) => `${n(p.x)},${n(p.y)}`;

const linear = (points: Point[]) => points.map((p, i) => `${i === 0 ? "M" : "L"}${pt(p)}`).join("");

const sign = (x: number) => (x < 0 ? -1 : 1);

function slope3(x0: number, y0: number, x1: number, y1: number, x2: number, y2: number) {
	const h0 = x1 - x0;
	const h1 = x2 - x1;
	const s0 = (y1 - y0) / (h0 || (h1 < 0 ? -0 : 0));
	const s1 = (y2 - y1) / (h1 || (h0 < 0 ? -0 : 0));
	const p = (s0 * h1 + s1 * h0) / (h0 + h1);
	return (sign(s0) + sign(s1)) * Math.min(Math.abs(s0), Math.abs(s1), 0.5 * Math.abs(p)) || 0;
}

function slope2(x0: number, y0: number, x1: number, y1: number, t: number) {
	const h = x1 - x0;
	return h ? ((3 * (y1 - y0)) / h - t) / 2 : t;
}

export function monotone(points: Point[]) {
	if (points.length === 0) return "";
	if (points.length < 3) return linear(points);
	let d = `M${pt(points[0])}`;
	const t: number[] = [];
	for (let i = 1; i < points.length - 1; i++) {
		const [a, b, c] = [points[i - 1], points[i], points[i + 1]];
		t[i] = slope3(a.x, a.y, b.x, b.y, c.x, c.y);
	}
	t[0] = slope2(points[0].x, points[0].y, points[1].x, points[1].y, t[1]);
	const last = points.length - 1;
	t[last] = slope2(points[last - 1].x, points[last - 1].y, points[last].x, points[last].y, t[last - 1]);
	for (let i = 0; i < last; i++) {
		const [p0, p1] = [points[i], points[i + 1]];
		const dx = (p1.x - p0.x) / 3;
		d += `C${n(p0.x + dx)},${n(p0.y + dx * t[i])} ${n(p1.x - dx)},${n(p1.y - dx * t[i + 1])} ${pt(p1)}`;
	}
	return d;
}

/** runs of points without gaps */
export function segments<P>(points: (P | null)[]): P[][] {
	const out: P[][] = [];
	let run: P[] = [];
	for (const p of points) {
		if (p === null) {
			if (run.length) out.push(run);
			run = [];
		} else run.push(p);
	}
	if (run.length) out.push(run);
	return out;
}

export function linePath(points: (Point | null)[]) {
	return segments(points)
		.map((s) => (s.length === 1 ? `M${pt(s[0])}h0.01` : monotone(s)))
		.join("");
}

/** the top edge with the curve, then the base drawn back with the same curve (stacked bases) */
export function areaPath(points: ((Point & { y0: number }) | null)[]) {
	return segments(points)
		.map((s) => {
			const top = monotone(s);
			const base = monotone([...s].reverse().map((p) => ({ x: p.x, y: p.y0 }))).replace(/^M/, "L");
			return `${top}${base}Z`;
		})
		.join("");
}
