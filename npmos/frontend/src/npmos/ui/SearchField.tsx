// Search field of NPMOS: "frame" above a table, "inset" inside a card, a table or a modal (SearchField.module.css).
import { IconSearch } from "@tabler/icons-react";
import cn from "classnames";
import { forwardRef } from "react";
import styles from "./SearchField.module.css";

interface Props {
	value: string;
	onChange: (value: string) => void;
	/** what the search covers: also the name of the field for screen readers */
	placeholder: string;
	variant?: "frame" | "inset";
	/** a key that focuses the field, shown at its end */
	hotkey?: string;
	disabled?: boolean;
	className?: string;
}

export const SearchField = forwardRef<HTMLInputElement, Props>(function SearchField(
	{ value, onChange, placeholder, variant = "frame", hotkey, disabled, className },
	ref,
) {
	const field = (
		<label className={cn(variant === "frame" ? styles.surface : styles.inset, variant === "inset" && className)}>
			<IconSearch size={16} />
			<input
				ref={ref}
				type="search"
				className={styles.input}
				value={value}
				disabled={disabled}
				placeholder={placeholder}
				aria-label={placeholder}
				onChange={(e) => onChange(e.target.value)}
				onKeyDown={(e) => {
					if (e.key === "Escape" && value) {
						e.stopPropagation();
						onChange("");
					}
				}}
			/>
			{hotkey && <kbd className={styles.kbd}>{hotkey}</kbd>}
		</label>
	);
	return variant === "frame" ? <div className={cn(styles.frame, className)}>{field}</div> : field;
});
