// Sidebar of opensophy.com/docs (content/ContentSidebar): brand, user menu, collapsible groups with a guide line, a hover highlight sliding between items and an accent
// line next to the active page; theme and language at the bottom.
import { IconChevronRight } from "@tabler/icons-react";
import cn from "classnames";
import { type CSSProperties, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useUser } from "src/hooks";
import { intl, T } from "src/locale";
import { useCan } from "../rbac/hooks";
import { Brand, LocaleSwitch, ThemeToggle, UserMenu } from "./Controls";
import { containsActive, isActivePath, type NavItem, navigation, visibleItems } from "./menu";
import styles from "./Shell.module.css";

/** how long the active line follows a group that opens or closes (the panel transition) */
const FOLLOW_MS = 260;

interface Indicator {
	top: number;
	height: number;
	left?: number;
	visible: boolean;
}
const hidden: Indicator = { top: 0, height: 0, left: 0, visible: false };

interface Props {
	/** called after navigation (closes the mobile drawer) */
	onNavigate?: () => void;
}

export function Sidebar({ onNavigate }: Props) {
	const { pathname } = useLocation();
	const navigate = useNavigate();
	const { data: me } = useUser("me");
	const [expanded, setExpanded] = useState<Record<string, boolean>>({});
	const [hover, setHover] = useState<Indicator>(hidden);
	const [active, setActive] = useState<Indicator>(hidden);
	const [follow, setFollow] = useState(false);
	const nav = useRef<HTMLElement>(null);

	const can = useCan();
	const items = useMemo(() => visibleItems(navigation, me, can), [me, can]);

	// a group with the active page opens when the page changes (it can be closed afterwards)
	useEffect(() => {
		const open: Record<string, boolean> = {};
		const walk = (list: NavItem[]) => {
			for (const item of list) {
				if (item.items && containsActive(item, pathname)) {
					open[item.id] = true;
					walk(item.items);
				}
			}
		};
		walk(navigation);
		setExpanded((prev) => ({ ...prev, ...open }));
	}, [pathname]);

	const measureActive = useCallback(() => {
		const root = nav.current;
		const node = root?.querySelector<HTMLElement>("[data-active='true']");
		if (!root || !node) {
			setActive(hidden);
			return;
		}
		const navRect = root.getBoundingClientRect();
		const rect = node.getBoundingClientRect();
		// clip by the panels of closing groups
		let top = rect.top;
		let bottom = rect.bottom;
		for (
			let p = node.closest<HTMLElement>("[data-panel]");
			p;
			p = p.parentElement?.closest("[data-panel]") ?? null
		) {
			const clip = p.getBoundingClientRect();
			top = Math.max(top, clip.top);
			bottom = Math.min(bottom, clip.bottom);
		}
		const height = Math.max(0, bottom - top);
		setActive({ left: rect.left - navRect.left - 8, top: top - navRect.top, height, visible: height > 0 });
	}, []);

	// the line jumps without animation while a group opens or closes, then animates again
	const followLayout = useCallback(() => {
		setFollow(true);
		const start = performance.now();
		let frame = 0;
		const step = (now: number) => {
			measureActive();
			if (now - start < FOLLOW_MS) {
				frame = requestAnimationFrame(step);
			} else {
				setFollow(false);
			}
		};
		frame = requestAnimationFrame(step);
		return () => cancelAnimationFrame(frame);
	}, [measureActive]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: re-measure when the page, the menu or a group changes
	useLayoutEffect(() => followLayout(), [pathname, items, expanded, followLayout]);

	useEffect(() => {
		window.addEventListener("resize", measureActive);
		return () => window.removeEventListener("resize", measureActive);
	}, [measureActive]);

	const showHover = (node: HTMLElement) => {
		if (!nav.current) return;
		const navRect = nav.current.getBoundingClientRect();
		const rect = node.getBoundingClientRect();
		setHover({ top: rect.top - navRect.top, height: rect.height, visible: true });
	};
	const hideHover = () => setHover((h) => ({ ...h, visible: false }));

	const go = (to: string) => {
		navigate(to);
		onNavigate?.();
	};

	const isOpen = (item: NavItem) => expanded[item.id] ?? containsActive(item, pathname);

	const renderItem = (item: NavItem, depth: number) => {
		const hoverHandlers = {
			onMouseEnter: (e: React.MouseEvent<HTMLElement>) => showHover(e.currentTarget),
			onFocus: (e: React.FocusEvent<HTMLElement>) => showHover(e.currentTarget),
		};
		if (item.items) {
			const open = isOpen(item);
			return (
				<div key={item.id} style={{ display: "flex", flexDirection: "column" }}>
					<button
						type="button"
						className={cn(styles.item, open && styles.itemOpen)}
						aria-expanded={open}
						onClick={() => setExpanded((prev) => ({ ...prev, [item.id]: !open }))}
						{...hoverHandlers}
					>
						<T id={item.label} />
						<IconChevronRight size={16} className={styles.chevron} />
					</button>
					<div data-panel className={cn(styles.panel, open && styles.panelOpen)}>
						<div className={styles.panelInner} inert={!open}>
							<div className={cn(styles.children, depth > 0 && styles.childrenNested)}>
								{item.items.map((child) => renderItem(child, depth + 1))}
							</div>
						</div>
					</div>
				</div>
			);
		}
		const to = item.to as string;
		const current = item.tabs ? containsActive(item, pathname) : isActivePath(to, pathname);
		return (
			<a
				key={item.id}
				href={to}
				data-active={current}
				aria-current={current ? "page" : undefined}
				className={cn(styles.item, current && styles.itemActive)}
				style={{ justifyContent: "flex-start" }}
				onClick={(e) => {
					e.preventDefault();
					go(to);
				}}
				{...hoverHandlers}
			>
				<T id={item.label} />
			</a>
		);
	};

	return (
		<aside className={styles.aside} aria-label={intl.formatMessage({ id: "npmos.nav.menu" })}>
			<a
				href="/"
				className={styles.brand}
				onClick={(e) => {
					e.preventDefault();
					go("/");
				}}
			>
				<Brand />
			</a>

			<div className={styles.controls}>
				<UserMenu />
			</div>

			<div className={styles.navScroll}>
				<nav
					ref={nav}
					className={cn(styles.nav, follow && styles.navFollow)}
					aria-label={intl.formatMessage({ id: "npmos.nav.menu" })}
					onMouseLeave={hideHover}
					onBlur={(e) => {
						if (!nav.current?.contains(e.relatedTarget as Node)) hideHover();
					}}
					style={
						{
							"--hover-top": `${hover.top}px`,
							"--hover-height": `${hover.height}px`,
							"--hover-opacity": hover.visible ? 1 : 0,
							"--active-left": `${active.left}px`,
							"--active-top": `${active.top}px`,
							"--active-height": `${active.height}px`,
							"--active-opacity": active.visible ? 1 : 0,
						} as CSSProperties
					}
				>
					{items.map((item) => renderItem(item, 0))}
				</nav>
			</div>

			<div className={styles.bottom}>
				<ThemeToggle />
				<LocaleSwitch />
			</div>
		</aside>
	);
}
