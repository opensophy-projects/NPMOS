// Dropdown of opensophy.com (ui-registry/Dropdown): inset trigger, card menu, keyboard support.
import cn from "classnames";
import { type CSSProperties, type ReactNode, useEffect, useLayoutEffect, useRef, useState } from "react";
import styles from "./Shell.module.css";

export interface DropdownItem {
	key: string;
	label: ReactNode;
	icon?: ReactNode;
	active?: boolean;
	/** draws a divider above the item */
	divider?: boolean;
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
	ariaLabel: string;
}

export function Dropdown({ trigger, triggerClassName, items, header, up, inline, menuClassName, ariaLabel }: Props) {
	const [open, setOpen] = useState(false);
	const box = useRef<HTMLDivElement>(null);
	const button = useRef<HTMLButtonElement>(null);
	const refs = useRef<(HTMLButtonElement | null)[]>([]);
	const [place, setPlace] = useState<{ up: boolean; right: boolean; maxHeight: number }>({
		up: !!up,
		right: false,
		maxHeight: 320,
	});

	// open towards the side with room and never past the viewport
	useLayoutEffect(() => {
		if (!open || !box.current) return;
		const rect = box.current.getBoundingClientRect();
		const gap = 12;
		const above = rect.top - gap;
		const below = window.innerHeight - rect.bottom - gap;
		const wanted = Math.min(320, (items.length + (header ? 1 : 0)) * 36 + 8);
		const goUp = up ? above >= wanted || above > below : below < wanted && above > below;
		setPlace({
			up: goUp,
			right: rect.left + rect.width / 2 > window.innerWidth / 2 && rect.width < 200,
			maxHeight: Math.max(120, goUp ? above : below),
		});
	}, [open, up, items.length, header]);

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
	}, [open, items]);

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
				onClick={() => setOpen(!open)}
			>
				{trigger}
			</button>
			{open && (
				<div
					className={cn(
						styles.menu,
						place.up && styles.menuUp,
						place.right && styles.menuRight,
						menuClassName,
					)}
					style={{ "--menu-max": `${place.maxHeight}px` } as CSSProperties}
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
