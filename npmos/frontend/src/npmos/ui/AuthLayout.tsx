// Login and first-run setup: the panel sits exactly in the middle of the screen, the brand above
// it, theme, language and version below it.
import type { ReactNode } from "react";
import styles from "./Auth.module.css";
import { Brand, LocaleSwitch, ThemeToggle } from "./Controls";

export function AuthLayout({ children, version }: { children: ReactNode; version?: string }) {
	return (
		<div className={styles.screen}>
			<div className={styles.top}>
				<Brand />
			</div>
			<div className={styles.panel}>{children}</div>
			<div className={styles.bottom}>
				<div className={styles.controls}>
					<ThemeToggle />
					<LocaleSwitch />
				</div>
				{version ? <div className={styles.version}>{version}</div> : null}
			</div>
		</div>
	);
}
