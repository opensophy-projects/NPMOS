// Application shell in the look of opensophy.com/docs (content/ContentSectionLayout): the sidebar
// on the left, the page in an inset panel that scrolls on its own; on narrow screens a top bar
// and the sidebar as a drawer from the right. Replaces the upstream header, top menu and footer.
import { IconLayoutSidebarRightExpand, IconX } from "@tabler/icons-react";
import cn from "classnames";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { intl, T } from "src/locale";
import styles from "./Shell.module.css";
import { Sidebar } from "./Sidebar";

const MAIN_ID = "npmos-main";
const SCROLL_ID = "npmos-content";

function MobileDrawer() {
	const navigate = useNavigate();
	const [open, setOpen] = useState(false);
	const toggle = useRef<HTMLButtonElement>(null);
	const closeButton = useRef<HTMLButtonElement>(null);

	useEffect(() => {
		if (!open) return;
		document.body.style.overflow = "hidden";
		closeButton.current?.focus();
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "Escape") setOpen(false);
		};
		document.addEventListener("keydown", onKey);
		return () => {
			document.body.style.overflow = "";
			document.removeEventListener("keydown", onKey);
		};
	}, [open]);

	const close = () => {
		setOpen(false);
		toggle.current?.focus();
	};

	return (
		<>
			<div className={styles.mobileBar}>
				<a
					href="/"
					className={styles.mobileBrand}
					onClick={(e) => {
						e.preventDefault();
						navigate("/");
					}}
				>
					<img src="/images/logo-no-text.svg" alt="" />
					npmos
				</a>
				<button
					ref={toggle}
					type="button"
					className={styles.iconButton}
					aria-label={intl.formatMessage({ id: "npmos.nav.open-menu" })}
					aria-expanded={open}
					onClick={() => setOpen(true)}
				>
					<IconLayoutSidebarRightExpand size={16} />
				</button>
			</div>
			<div className={cn(open && styles.drawerOpen)}>
				<div className={styles.overlay} aria-hidden onClick={close} />
				<div
					className={styles.drawer}
					role="dialog"
					aria-modal="true"
					aria-label={intl.formatMessage({ id: "npmos.nav.menu" })}
					inert={!open}
				>
					<button
						ref={closeButton}
						type="button"
						className={styles.drawerClose}
						aria-label={intl.formatMessage({ id: "npmos.nav.close-menu" })}
						onClick={close}
					>
						<IconX size={24} />
					</button>
					<Sidebar onNavigate={() => setOpen(false)} />
				</div>
			</div>
		</>
	);
}

export function Shell({ children }: { children: ReactNode }) {
	const { pathname } = useLocation();

	// a new page starts at the top of the panel
	// biome-ignore lint/correctness/useExhaustiveDependencies: runs on navigation
	useEffect(() => {
		document.getElementById(SCROLL_ID)?.scrollTo({ top: 0 });
	}, [pathname]);

	return (
		<>
			<a href={`#${MAIN_ID}`} className={styles.skip}>
				<T id="npmos.nav.skip" />
			</a>
			<main className={styles.main}>
				<MobileDrawer />
				<div className={styles.grid}>
					<div className={styles.sidebarShell}>
						<Sidebar hotkey />
					</div>
					<div className={styles.contentShell}>
						<div className={styles.content}>
							<div id={SCROLL_ID} className={styles.scroll}>
								<div id={MAIN_ID} tabIndex={-1} className={styles.page}>
									{children}
								</div>
							</div>
						</div>
					</div>
				</div>
			</main>
		</>
	);
}
