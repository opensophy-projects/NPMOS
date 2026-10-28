// Dropdown of opensophy.com (ui-registry/Dropdown): inset trigger, card menu, keyboard support.
import cn from "classnames";
import { type CSSProperties, type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import styles from "./Shell.module.css";

export interface DropdownItem {
	key: string;
	label: ReactNode;
	icon?: ReactNode;
	active?: boolean;
	/** draws a divider above the item */
	divider?: boolean;
	disabled?: boolean;
	onSelect: () => void;
}

interface Props {
	/** content of the trigger */
	trigger: ReactNode;
	/** classes of the trigger (default: the inset field of the sidebar) */
	triggerClassName?: string;
	items: DropdownItem[];
	header?: ReactNode;
	/** prefer opening upwards (bottom of the sidebar); flips when there is no room */
	up?: boolean;
	inline?: boolean;
	/** extra classes of the menu (e.g. the compact language list) */
	menuClassName?: string;
	/** the menu is positioned against the viewport: not clipped by tables and scroll areas */
	floating?: boolean;
	/** a tooltip of the trigger */
	title?: string;
	ariaLabel: string;
}

export function Dropdown({
	trigger,
	triggerClassName,
	items,
	header,
	up,
	inline,
	menuClassName,
	floating,
	title,
	ariaLabel,
}: Props) {
	const [open, setOpen] = useState(false);
	const box = useRef<HTMLDivElement>(null);
	const button = useRef<HTMLButtonElement>(null);
	const refs = useRef<(HTMLButtonElement | null)[]>([]);
	const [place, setPlace] = useState<{ up: boolean; right: boolean; maxHeight: number; fixed?: CSSProperties }>({
		up: !!up,
		right: false,
		maxHeight: 320,
	});

	const menu = useRef<HTMLDivElement>(null);
	const measured = useRef(false);

	// open towards the side with room and never past the viewport; `wanted` is the menu height
	const placeMenu = useCallback(
		(wanted: number) => {
			if (!box.current) return;
			const rect = box.current.getBoundingClientRect();
			const gap = 12;
			const above = rect.top - gap;
			const below = window.innerHeight - rect.bottom - gap;
			const goUp = up ? above >= wanted || above > below : below < wanted && above > below;
			const right = rect.left + rect.width / 2 > window.innerWidth / 2 && (floating || rect.width < 200);
			setPlace({
				up: goUp,
				right,
				maxHeight: Math.max(120, goUp ? above : below),
				fixed: floating
					? {
							position: "fixed",
							margin: 0,
							minWidth: Math.max(rect.width, 160),
							top: goUp ? "auto" : rect.bottom + 4,
							bottom: goUp ? window.innerHeight - rect.top + 4 : "auto",
							left: right ? "auto" : rect.left,
							right: right ? window.innerWidth - rect.right : "auto",
						}
					: undefined,
			});
		},
		[up, floating],
	);

	// first an estimate, then once more with the real height of the rendered menu
	useLayoutEffect(() => {
		if (!open) return;
		measured.current = false;
		placeMenu(Math.min(320, (items.length + (header ? 1 : 0)) * 36 + 8));
	}, [open, items.length, header, placeMenu]);
	useLayoutEffect(() => {
		if (!open || measured.current || !menu.current) return;
		measured.current = true;
		placeMenu(menu.current.scrollHeight);
	});

	// a floating menu does not follow its trigger: close it when the page scrolls or resizes
	useEffect(() => {
		if (!open || !floating) return;
		const closeMenu = (e: Event) => {
			if (e.type === "scroll" && box.current?.contains(e.target as Node)) return;
			setOpen(false);
		};
		window.addEventListener("scroll", closeMenu, true);
		window.addEventListener("resize", closeMenu);
		return () => {
			window.removeEventListener("scroll", closeMenu, true);
			window.removeEventListener("resize", closeMenu);
		};
	}, [open, floating]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: focus once when the menu opens
	useEffect(() => {
		if (!open) return;
		const outside = (e: MouseEvent) => {
			if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
		};
		document.addEventListener("mousedown", outside);
		const first = Math.max(
			0,
			items.findIndex((i) => i.active),
		);
		requestAnimationFrame(() => refs.current[first]?.focus());
		return () => document.removeEventListener("mousedown", outside);
	}, [open]);

	const close = () => {
		setOpen(false);
		button.current?.focus();
	};

	const onKeyDown = (e: React.KeyboardEvent) => {
		if (!open) return;
		const index = refs.current.indexOf(document.activeElement as HTMLButtonElement);
		if (e.key === "Escape") {
			e.preventDefault();
			close();
		} else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
			e.preventDefault();
			const next = e.key === "ArrowDown" ? Math.min(index + 1, items.length - 1) : Math.max(index - 1, 0);
			refs.current[next]?.focus();
		} else if (e.key === "Tab") {
			setOpen(false);
		}
	};

	return (
		// biome-ignore lint/a11y/noStaticElementInteractions: keyboard navigation of the menu inside
		<div className={cn(styles.dropdown, inline && styles.dropdownInline)} ref={box} onKeyDown={onKeyDown}>
			<button
				ref={button}
				type="button"
				className={triggerClassName ?? cn(styles.field, styles.trigger)}
				aria-haspopup="menu"
				aria-expanded={open}
				aria-label={ariaLabel}
				title={title}
				onClick={() => setOpen(!open)}
			>
				{trigger}
			</button>
			{open && (
				<div
					ref={menu}
					className={cn(
						styles.menu,
						place.up && styles.menuUp,
						place.right && styles.menuRight,
						menuClassName,
					)}
					style={{ "--menu-max": `${place.maxHeight}px`, ...place.fixed } as CSSProperties}
					role="menu"
				>
					{header}
					{items.map((item, i) => (
						<div key={item.key} style={{ display: "contents" }}>
							{item.divider && <div className={styles.menuDivider} />}
							<button
								ref={(el) => {
									refs.current[i] = el;
								}}
								type="button"
								role="menuitem"
								className={cn(styles.menuItem, item.active && styles.menuItemActive)}
								disabled={item.disabled}
								onClick={() => {
									close();
									item.onSelect();
								}}
							>
								{item.icon}
								{item.label}
							</button>
						</div>
					))}
				</div>
			)}
		</div>
	);
}
