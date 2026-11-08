// A "?" (the icon of help, as on the Access lists page) next to a column, a chart or a number: what it shows, on hover, focus or a tap (phones have no hover).
// The text is the message `<id>.info`: a Label, or a panel or a KPI titled with a T element, gets its
// explanation by adding that message, nothing else changes. Drawn in a portal: tables and scroll areas do not clip it.
import { IconHelp } from "@tabler/icons-react";
import cn from "classnames";
import { isValidElement, type ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { intl, T } from "src/locale";
import styles from "./InfoTip.module.css";

/** the message that explains a label, if there is one */
const infoOf = (id: unknown): string | undefined =>
	typeof id === "string" && intl.messages[`${id}.info`] ? `${id}.info` : undefined;

/** the explanation of a title given as <T id="…" /> */
export const infoOfNode = (node: ReactNode): string | undefined =>
	isValidElement<{ id?: unknown }>(node) ? infoOf(node.props.id) : undefined;

export function InfoTip({ id, values }: { id: string; values?: Record<string, string | number | undefined> }) {
	const [open, setOpen] = useState(false);
	const [pinned, setPinned] = useState(false);
	const [pos, setPos] = useState<{ top: number; left: number; above: boolean }>({ top: 0, left: 0, above: false });
	const button = useRef<HTMLButtonElement>(null);
	const tip = useRef<HTMLDivElement>(null);
	const shown = open || pinned;

	useLayoutEffect(() => {
		if (!shown || !button.current) return;
		const r = button.current.getBoundingClientRect();
		const width = Math.min(288, window.innerWidth - 32);
		const left = Math.min(Math.max(16, r.left + r.width / 2 - width / 2), window.innerWidth - 16 - width);
		const above = r.bottom + 160 > window.innerHeight && r.top > 160;
		setPos({ top: above ? r.top - 6 : r.bottom + 6, left, above });
	}, [shown]);

	useEffect(() => {
		if (!pinned) return;
		const outside = (e: MouseEvent) => {
			const target = e.target as Node;
			if (!tip.current?.contains(target) && !button.current?.contains(target)) setPinned(false);
		};
		const key = (e: KeyboardEvent) => e.key === "Escape" && setPinned(false);
		const away = () => setPinned(false);
		document.addEventListener("mousedown", outside);
		document.addEventListener("keydown", key);
		window.addEventListener("scroll", away, true);
		window.addEventListener("resize", away);
		return () => {
			document.removeEventListener("mousedown", outside);
			document.removeEventListener("keydown", key);
			window.removeEventListener("scroll", away, true);
			window.removeEventListener("resize", away);
		};
	}, [pinned]);

	return (
		<>
			<button
				ref={button}
				type="button"
				className={cn("btn", styles.button)}
				aria-label={intl.formatMessage({ id: "nginxions.common.what-is-it" })}
				aria-expanded={shown}
				onMouseEnter={() => setOpen(true)}
				onMouseLeave={() => setOpen(false)}
				onFocus={() => setOpen(true)}
				onBlur={() => setOpen(false)}
				onClick={(e) => {
					// a header that sorts on click must not sort
					e.stopPropagation();
					e.preventDefault();
					setPinned(!pinned);
				}}
			>
				<IconHelp size={14} />
			</button>
			{shown &&
				createPortal(
					<div
						ref={tip}
						role="tooltip"
						className={styles.tip}
						style={{
							top: pos.top,
							left: pos.left,
							transform: pos.above ? "translateY(-100%)" : undefined,
						}}
					>
						<T id={id} data={values} />
					</div>,
					document.body,
				)}
		</>
	);
}

/** a label (a column, a number) with its explanation, if it has one */
export function Label({ id, values }: { id: string; values?: Record<string, string | number | undefined> }) {
	const info = infoOf(id);
	return (
		<span className={styles.label}>
			<T id={id} data={values} />
			{info && <InfoTip id={info} />}
		</span>
	);
}
