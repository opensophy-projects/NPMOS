// A panel that opens under its button (filters and display options of tables, as in the
// Cloudflare dashboard). Positioned against the viewport, so tables and scroll areas do not clip it.
import { IconX } from "@tabler/icons-react";
import cn from "classnames";
import { type CSSProperties, type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { intl } from "src/locale";
import styles from "./Popover.module.css";

interface Props {
	/** content of the button */
	trigger: ReactNode;
	triggerClassName?: string;
	/** class of the button while the panel is open */
	activeClassName?: string;
	title: ReactNode;
	/** an action next to the title (e.g. "Reset") */
	titleAction?: ReactNode;
	ariaLabel: string;
	/** width of the panel */
	width?: string;
	/** the panel content; `close` closes it */
	children: (close: () => void) => ReactNode;
}

export function Popover({
	trigger,
	triggerClassName,
	activeClassName,
	title,
	titleAction,
	ariaLabel,
	width = "20rem",
	children,
}: Props) {
	const [open, setOpen] = useState(false);
	const [style, setStyle] = useState<CSSProperties>({});
	const button = useRef<HTMLButtonElement>(null);
	const panel = useRef<HTMLDivElement>(null);

	const close = useCallback(() => {
		setOpen(false);
		button.current?.focus();
	}, []);

	useLayoutEffect(() => {
		if (!open || !button.current) return;
		const rect = button.current.getBoundingClientRect();
		const right = rect.left + rect.width / 2 > window.innerWidth / 2;
		setStyle({
			width: `min(${width}, calc(100vw - 2rem))`,
			top: rect.bottom + 8,
			left: right ? "auto" : Math.max(16, rect.left),
			right: right ? Math.max(16, window.innerWidth - rect.right) : "auto",
			maxHeight: `calc(100vh - ${rect.bottom + 24}px)`,
		});
	}, [open, width]);

	useEffect(() => {
		if (!open) return;
		const outside = (e: MouseEvent) => {
			const target = e.target as Node;
			// menus of selects inside the panel are rendered outside it
			if ((target as HTMLElement).closest?.("[data-popover-keep]")) return;
			if (!panel.current?.contains(target) && !button.current?.contains(target)) setOpen(false);
		};
		const key = (e: KeyboardEvent) => {
			if (e.key === "Escape") close();
		};
		const resize = () => setOpen(false);
		document.addEventListener("mousedown", outside);
		document.addEventListener("keydown", key);
		window.addEventListener("resize", resize);
		return () => {
			document.removeEventListener("mousedown", outside);
			document.removeEventListener("keydown", key);
			window.removeEventListener("resize", resize);
		};
	}, [open, close]);

	return (
		<>
			<button
				ref={button}
				type="button"
				className={cn(triggerClassName, open && activeClassName)}
				aria-expanded={open}
				aria-haspopup="dialog"
				aria-label={ariaLabel}
				onClick={() => setOpen(!open)}
			>
				{trigger}
			</button>
			{open && (
				<div ref={panel} className={styles.panel} style={style} role="dialog" aria-label={ariaLabel}>
					<div className={styles.head}>
						<span className={styles.title}>{title}</span>
						{titleAction}
						<button
							type="button"
							className={styles.close}
							aria-label={intl.formatMessage({ id: "npmos.common.close" })}
							onClick={close}
						>
							<IconX size={16} />
						</button>
					</div>
					{children(close)}
				</div>
			)}
		</>
	);
}
