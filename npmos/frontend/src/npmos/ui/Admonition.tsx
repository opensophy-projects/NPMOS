// Notice block in the highlight box of opensophy.com (HighlightBox.svelte, .os-highlight in tokens.css): an outer
// frame tinted with the tone of the notice and a surface inside it with the icon, title and text. The tone follows
// the meaning: red alerts, orange warnings, yellow cautions, green success, blue tips, the accent for notes.
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

export type AdmonitionVariant = "note" | "tip" | "success" | "warning" | "caution" | "alert";

const ICON: Record<AdmonitionVariant, TablerIcon> = {
	note: IconInfoCircle,
	tip: IconBulb,
	success: IconCircleCheck,
	warning: IconAlertTriangle,
	caution: IconAlertTriangle,
	alert: IconAlertOctagon,
};

/** tone of the highlight box (classes of tokens.css); a note keeps the accent */
const TONE: Record<AdmonitionVariant, string> = {
	note: "",
	tip: "tone-blue",
	success: "tone-green",
	warning: "tone-orange",
	caution: "tone-yellow",
	alert: "tone-red",
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
		<div className={cn("os-highlight", TONE[variant], styles.box, compact && styles.compact, className)}>
			<Icon className={cn("os-highlight-icon", styles.icon)} size={compact ? 18 : 20} stroke={1.75} />
			<div className={styles.body}>
				<div className={cn("os-highlight-title", styles.title)}>{title}</div>
				{children && <div className={styles.text}>{children}</div>}
			</div>
			{aside && <div className={styles.aside}>{aside}</div>}
		</div>
	);
}
