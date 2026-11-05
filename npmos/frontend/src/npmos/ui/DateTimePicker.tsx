// A date and time field in the look of NPMOS (the system picker of the browser looks different in every browser
// and theme): a button with the value, a month calendar and the time in a popover. Values are ISO strings.
import { IconCalendar, IconChevronLeft, IconChevronRight } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import { intl, T } from "src/locale";
import styles from "./DateTimePicker.module.css";
import { Popover } from "./Popover";

const t = (id: string) => intl.formatMessage({ id });
const pad = (n: number) => String(n).padStart(2, "0");
const sameDay = (a: Date, b: Date) =>
	a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

/** the days of a month grid, Monday first, with the days of the months around it */
export const monthGrid = (year: number, month: number) => {
	const first = new Date(year, month, 1);
	const shift = (first.getDay() + 6) % 7;
	return Array.from({ length: 42 }, (_, i) => new Date(year, month, 1 - shift + i));
};

interface Props {
	value: string;
	onChange: (iso: string) => void;
	label: string;
	/** a field that may stay empty ("now" for the end of a period) */
	placeholder?: string;
	clearable?: boolean;
}

export function DateTimePicker({ value, onChange, label, placeholder, clearable }: Props) {
	const current = value ? new Date(value) : null;
	const locale = intl.locale;
	const [view, setView] = useState(() => {
		const d = current ?? new Date();
		return { year: d.getFullYear(), month: d.getMonth() };
	});
	const [time, setTime] = useState(() =>
		current ? `${pad(current.getHours())}:${pad(current.getMinutes())}` : "00:00",
	);
	const shown = current
		? current.toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" })
		: (placeholder ?? "—");
	const weekdays = monthGrid(2024, 0)
		.slice(0, 7)
		.map((d) => d.toLocaleDateString(locale, { weekday: "short" }));
	const title = new Date(view.year, view.month, 1).toLocaleDateString(locale, { month: "long", year: "numeric" });
	const move = (delta: number) => {
		const d = new Date(view.year, view.month + delta, 1);
		setView({ year: d.getFullYear(), month: d.getMonth() });
	};
	const pick = (day: Date, hhmm = time) => {
		const [h, m] = hhmm.split(":").map((x) => Number.parseInt(x, 10) || 0);
		onChange(new Date(day.getFullYear(), day.getMonth(), day.getDate(), h, m).toISOString());
	};
	const today = new Date();

	return (
		<Popover
			ariaLabel={label}
			title={label}
			width="18.5rem"
			triggerClassName={cn("form-control form-control-sm", styles.trigger)}
			trigger={
				<>
					<IconCalendar size={15} className={styles.icon} />
					<span className={cn(!current && styles.empty)}>{shown}</span>
				</>
			}
		>
			{(close) => (
				<div className={styles.picker}>
					<div className={styles.nav}>
						<button type="button" aria-label={t("npmos.date.previous")} onClick={() => move(-1)}>
							<IconChevronLeft size={16} />
						</button>
						<span className={styles.month}>{title}</span>
						<button type="button" aria-label={t("npmos.date.next")} onClick={() => move(1)}>
							<IconChevronRight size={16} />
						</button>
					</div>
					<div className={styles.grid} role="grid">
						{weekdays.map((w) => (
							<span key={w} className={styles.weekday}>
								{w}
							</span>
						))}
						{monthGrid(view.year, view.month).map((day) => (
							<button
								key={day.toISOString()}
								type="button"
								className={cn(
									styles.day,
									day.getMonth() !== view.month && styles.outside,
									sameDay(day, today) && styles.today,
									current && sameDay(day, current) && styles.selected,
								)}
								aria-pressed={!!current && sameDay(day, current)}
								onClick={() => pick(day)}
							>
								{day.getDate()}
							</button>
						))}
					</div>
					<div className={styles.foot}>
						<label className={styles.time}>
							<T id="npmos.date.time" />
							<input
								type="text"
								inputMode="numeric"
								className="form-control form-control-sm"
								value={time}
								maxLength={5}
								aria-label={t("npmos.date.time")}
								onChange={(e) => {
									const v = e.target.value.replace(/[^\d:]/g, "");
									setTime(v);
									if (/^([01]\d|2[0-3]):[0-5]\d$/.test(v) && current) pick(current, v);
								}}
							/>
						</label>
						<button
							type="button"
							className="btn btn-sm"
							onClick={() => {
								const now = new Date();
								setTime(`${pad(now.getHours())}:${pad(now.getMinutes())}`);
								setView({ year: now.getFullYear(), month: now.getMonth() });
								onChange(now.toISOString());
							}}
						>
							<T id="npmos.date.now" />
						</button>
						{clearable && current && (
							<button
								type="button"
								className="btn btn-sm"
								onClick={() => {
									onChange("");
									close();
								}}
							>
								<T id="npmos.date.clear" />
							</button>
						)}
						<button type="button" className="btn btn-sm btn-primary ms-auto" onClick={close}>
							<T id="npmos.date.done" />
						</button>
					</div>
				</div>
			)}
		</Popover>
	);
}
