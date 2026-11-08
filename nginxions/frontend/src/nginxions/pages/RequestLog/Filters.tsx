// "Filters" of Events → Requests: every field of the request log (as the filter panel of the other kinds of Events).
// Values are comma-separated in the address, as in Analytics; the chips under the toolbar show and remove them.
import { IconFilter } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import { T } from "src/locale";
import type { TrafficFilters } from "../../api";
import { Popover } from "../../ui/Popover";
import hostStyles from "../Hosts/Hosts.module.css";
import { FILTER_KEYS, t } from "../WafAnalytics/common";
import { choiceLabel } from "../WafAnalytics/index";
import styles from "../WafEvents/Events.module.css";
import logStyles from "./RequestLog.module.css";

type Key = keyof TrafficFilters;
type Set = (changes: Partial<Record<Key, string | null>>) => void;

const values = (v?: string) =>
	(v ?? "")
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);

const CHOICES: { key: Key; options: string[] }[] = [
	{ key: "client", options: ["human", "bot", "scanner"] },
	{ key: "status", options: ["2xx", "3xx", "4xx", "5xx"] },
	{ key: "method", options: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] },
	{ key: "device", options: ["desktop", "mobile", "tablet", "bot", "other"] },
	{ key: "protocol", options: ["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"] },
	{ key: "cache", options: ["HIT", "MISS", "EXPIRED", "BYPASS", "STALE", "UPDATING", "REVALIDATED"] },
];

const TEXT: { key: Key; placeholder: string }[] = [
	{ key: "host", placeholder: "example.com" },
	{ key: "ip", placeholder: "203.0.113.7" },
	{ key: "country", placeholder: "DE" },
	{ key: "path", placeholder: "/api/" },
	{ key: "status", placeholder: "404, 429" },
	{ key: "browser", placeholder: "Chrome" },
	{ key: "os", placeholder: "Windows" },
	{ key: "referer", placeholder: "google.com" },
	{ key: "contentType", placeholder: "text/html" },
	{ key: "origin", placeholder: "10.0.0.2:8080" },
	{ key: "originStatus", placeholder: "502, 5xx" },
	{ key: "port", placeholder: "443" },
	{ key: "tls", placeholder: "TLSv1.3" },
];

/** one value added to a comma-separated filter on Enter or leaving the field */
function TextValue({
	k,
	filters,
	set,
	placeholder,
}: {
	k: Key;
	filters: TrafficFilters;
	set: Set;
	placeholder: string;
}) {
	const [value, setValue] = useState("");
	const add = () => {
		const v = value.trim();
		setValue("");
		if (!v) return;
		// the path is one prefix, the others are lists
		if (k === "path") return set({ path: v });
		const now = values(filters[k]);
		const next = k === "host" ? v.toLowerCase() : k === "country" ? v.toUpperCase() : v;
		if (!now.includes(next)) set({ [k]: [...now, next].join(",") });
	};
	return (
		<input
			className="form-control form-control-sm"
			aria-label={t(`nginxions.traffic.filter.${k}`)}
			value={value}
			placeholder={placeholder}
			onChange={(e) => setValue(e.target.value)}
			onKeyDown={(e) => {
				if (e.key === "Enter") {
					e.preventDefault();
					add();
				}
			}}
			onBlur={add}
		/>
	);
}

/** a range of numbers: response time in ms, size in KB (stored in bytes) */
function Range({
	title,
	min,
	max,
	filters,
	set,
	scale = 1,
}: {
	title: string;
	min: Key;
	max: Key;
	filters: TrafficFilters;
	set: Set;
	scale?: number;
}) {
	const shown = (v?: string) => (v ? String(Math.round(Number(v) / scale)) : "");
	const store = (v: string) => (v === "" ? null : String(Math.max(0, Math.round(Number(v) * scale))));
	return (
		<div className={styles.section}>
			<div className={styles.sectionTitle}>{title}</div>
			<div className={styles.scores}>
				<input
					type="number"
					min={0}
					className="form-control form-control-sm"
					aria-label={`${title}: ${t("nginxions.traffic.log.from")}`}
					placeholder={t("nginxions.traffic.log.from")}
					value={shown(filters[min])}
					onChange={(e) => set({ [min]: store(e.target.value) })}
				/>
				<span>—</span>
				<input
					type="number"
					min={0}
					className="form-control form-control-sm"
					aria-label={`${title}: ${t("nginxions.traffic.log.to")}`}
					placeholder={t("nginxions.traffic.log.to")}
					value={shown(filters[max])}
					onChange={(e) => set({ [max]: store(e.target.value) })}
				/>
			</div>
		</div>
	);
}

export function RequestFilters({ filters, set }: { filters: TrafficFilters; set: Set }) {
	const count = FILTER_KEYS.filter((k) => k !== "q" && filters[k]).length;
	const toggle = (k: Key, v: string) => {
		const now = values(filters[k]);
		const next = now.includes(v) ? now.filter((x) => x !== v) : [...now, v];
		set({ [k]: next.length ? next.join(",") : null });
	};
	return (
		<Popover
			ariaLabel={t("nginxions.events.filters")}
			title={<T id="nginxions.events.filters" />}
			titleAction={
				count > 0 ? (
					<button
						type="button"
						className={hostStyles.reset}
						onClick={() =>
							set(Object.fromEntries(FILTER_KEYS.filter((k) => k !== "q").map((k) => [k, null])))
						}
					>
						<T id="nginxions.events.filters.reset" />
					</button>
				) : undefined
			}
			width="64rem"
			triggerClassName={hostStyles.tool}
			activeClassName={hostStyles.toolOn}
			trigger={
				<>
					<IconFilter size={16} />
					<span className={hostStyles.toolText}>
						<T id="nginxions.events.filters" />
					</span>
					{count > 0 && <span className={hostStyles.count}>{count}</span>}
				</>
			}
		>
			{() => (
				<div>
					<div className={logStyles.columns}>
						<div className={styles.section}>
							<div className={styles.sectionTitle}>
								<T id="nginxions.traffic.log.outcome" />
							</div>
							<div className={styles.options}>
								<label>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={filters.mitigated === "1"}
										onChange={(e) => set({ mitigated: e.target.checked ? "1" : null })}
									/>
									{t("nginxions.traffic.filter.mitigated.yes")}
								</label>
								<label>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={filters.mitigated === "0"}
										onChange={(e) => set({ mitigated: e.target.checked ? "0" : null })}
									/>
									{t("nginxions.traffic.filter.mitigated.no")}
								</label>
								<label>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={!!filters.unknown}
										onChange={(e) => set({ unknown: e.target.checked ? "1" : null })}
									/>
									<T id="nginxions.traffic.log.only-unknown" />
								</label>
							</div>
						</div>
						{CHOICES.map(({ key, options }) => (
							<div key={key} className={styles.section}>
								<div className={styles.sectionTitle}>{t(`nginxions.traffic.filter.${key}`)}</div>
								<div className={styles.options}>
									{options.map((o) => (
										<label key={o}>
											<input
												type="checkbox"
												className="form-check-input m-0"
												checked={values(filters[key]).includes(o)}
												onChange={() => toggle(key, o)}
											/>
											{choiceLabel(key, o)}
										</label>
									))}
								</div>
							</div>
						))}
						<Range
							title={t("nginxions.traffic.log.duration-ms")}
							min="minMs"
							max="maxMs"
							filters={filters}
							set={set}
						/>
						<Range
							title={t("nginxions.traffic.log.size-kb")}
							min="minBytes"
							max="maxBytes"
							filters={filters}
							set={set}
							scale={1024}
						/>
					</div>
					<div className={cn(styles.section, logStyles.fields)}>
						{TEXT.map(({ key, placeholder }) => (
							<div key={`text-${key}`}>
								<div className={styles.sectionTitle}>{t(`nginxions.traffic.filter.${key}`)}</div>
								<TextValue k={key} filters={filters} set={set} placeholder={placeholder} />
							</div>
						))}
						<small className={cn("text-secondary", logStyles.hint)}>
							<T id="nginxions.traffic.log.values-hint" />
						</small>
					</div>
				</div>
			)}
		</Popover>
	);
}
