#!/usr/bin/env node
// Builds npmos/frontend/src/npmos/ui/worldMap.json (country outlines of the Analytics map) from Natural Earth
// 1:110m Admin 0 countries (public domain): https://www.naturalearthdata.com/ — file
// ne_110m_admin_0_countries.geojson of github.com/nvkelso/natural-earth-vector. The map is part of the bundle:
// no tiles and no requests to the internet. Equal Earth projection, Antarctica left out.
// Usage: node scripts/gen-world-map.mjs <ne_110m_admin_0_countries.geojson>
import { readFileSync, writeFileSync } from "node:fs";

const src = process.argv[2];
if (!src) {
	console.error("usage: gen-world-map.mjs <ne_110m_admin_0_countries.geojson>");
	process.exit(1);
}
const WIDTH = 1000;
const A1 = 1.340264;
const A2 = -0.081106;
const A3 = 0.000893;
const A4 = 0.003796;
const M = Math.sqrt(3) / 2;
const equalEarth = ([lon, lat]) => {
	const l = (lon * Math.PI) / 180;
	const p = (lat * Math.PI) / 180;
	const t = Math.asin(M * Math.sin(p));
	const t2 = t * t;
	const t6 = t2 * t2 * t2;
	const x = (l * Math.cos(t)) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)));
	const y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2));
	return [x, y];
};
// extent of the projection: x ±2.7064, y ±1.3173
const XMAX = equalEarth([180, 0])[0];
const YMAX = equalEarth([0, 90])[1];
const scale = WIDTH / (2 * XMAX);
const r = (v) => Math.round(v * 10) / 10;
let minY = Number.POSITIVE_INFINITY;
let maxY = Number.NEGATIVE_INFINITY;
const project = (pt) => {
	const [x, y] = equalEarth(pt);
	const px = r((x + XMAX) * scale);
	const py = r((YMAX - y) * scale);
	minY = Math.min(minY, py);
	maxY = Math.max(maxY, py);
	return [px, py];
};
const ring = (coords) => {
	let d = "";
	let last = null;
	for (const pt of coords) {
		const [x, y] = project(pt);
		const key = `${x},${y}`;
		if (key === last) continue;
		d += `${d ? "L" : "M"}${key}`;
		last = key;
	}
	return `${d}Z`;
};
const geo = JSON.parse(readFileSync(src, "utf8"));
const countries = [];
for (const f of geo.features) {
	const p = f.properties;
	let code = p.ISO_A2_EH && p.ISO_A2_EH !== "-99" ? p.ISO_A2_EH : p.ISO_A2;
	if (code === "-99") code = "";
	if (p.ADM0_A3 === "ATA") continue;
	const polys = f.geometry.type === "Polygon" ? [f.geometry.coordinates] : f.geometry.coordinates;
	const d = polys.map((poly) => poly.map(ring).join("")).join("");
	countries.push({ c: code, n: p.NAME_EN || p.NAME, d });
}
countries.sort((a, b) => a.n.localeCompare(b.n));
const height = Math.ceil(maxY + 2);
const out = { width: WIDTH, height, top: Math.floor(minY - 2), countries };
writeFileSync(
	new URL("../npmos/frontend/src/npmos/ui/worldMap.json", import.meta.url),
	`${JSON.stringify(out)}\n`,
);
console.log(`${countries.length} countries, viewBox 0 ${out.top} ${WIDTH} ${height - out.top}`);
