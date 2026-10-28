// Notice block of opensophy.com (docs/markdown/Admonition.svelte): an inset frame, a coloured
// strip with the icon on the left, title and text on the right. The colour follows the meaning:
// accent for notes and tips, red for alerts, yellow for warnings, green for success.
import {
	IconAlertOctagon,
	IconAlertTriangle,
	IconBulb,
	IconCircleCheck,
	IconInfoCircle,
	type TablerIcon,
} from "@tabler/icons-react";
import cn from "classnames";
import type { ReactNode } from "react";
import styles from "./Admonition.module.css";

export type AdmonitionVariant = "note" | "tip" | "success" | "warning" | "alert";

const ICON: Record<AdmonitionVariant, TablerIcon> = {
	note: IconInfoCircle,
	tip: IconBulb,
	success: IconCircleCheck,
	warning: IconAlertTriangle,
	alert: IconAlertOctagon,
};

interface Props {
	variant?: AdmonitionVariant;
	title: ReactNode;
	children?: ReactNode;
	/** smaller paddings (lists of notices, toasts) */
	compact?: boolean;
	className?: string;
	/** extra content on the right (a button, a close cross) */
	aside?: ReactNode;
}

export function Admonition({ variant = "note", title, children, compact, className, aside }: Props) {
	const Icon = ICON[variant];
	return (
		<div className={cn(styles.frame, compact && styles.compact, className)}>
			<div className={styles.box}>
				<div className={cn(styles.strip, styles[variant])}>
					<Icon size={compact ? 18 : 22} stroke={1.75} />
				</div>
				<div className={styles.body}>
					<div className={styles.title}>{title}</div>
					{children && <div className={styles.text}>{children}</div>}
				</div>
				{aside && <div className={styles.aside}>{aside}</div>}
			</div>
		</div>
	);
}
