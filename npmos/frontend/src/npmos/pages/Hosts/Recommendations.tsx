// Recommendations above the hosts table (as in the Cloudflare DNS page): what is worth fixing,
// with a link that filters the table to the affected hosts.
import { IconChevronDown } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import { T } from "src/locale";
import styles from "./Hosts.module.css";
import type { Filters, Recommendation } from "./rows";

export function Recommendations({
	items,
	onShow,
}: {
	items: Recommendation[];
	onShow: (filter: Partial<Filters>) => void;
}) {
	const [open, setOpen] = useState(true);
	if (!items.length) return null;
	return (
		<div className={cn("card", styles.recs)}>
			<button type="button" className={styles.recsHead} onClick={() => setOpen(!open)} aria-expanded={open}>
				<T id="npmos.hosts.recommendations" />
				<span className={styles.count}>{items.length}</span>
				<IconChevronDown size={16} className={cn(styles.recsChevron, open && styles.recsChevronOpen)} />
			</button>
			{open && (
				<ul className={styles.recsList}>
					{items.map((item) => (
						<li key={item.id} className={styles.rec}>
							<span className={cn(styles.recDot, styles[item.level])} />
							<div className={styles.recText}>
								<div className={styles.recTitle}>
									<T id={`npmos.hosts.rec.${item.id}`} data={{ count: item.rows.length }} />
								</div>
								<div className={styles.recHint}>
									<T id={`npmos.hosts.rec.${item.id}.hint`} data={{ count: item.rows.length }} />{" "}
									<button
										type="button"
										className={styles.recLink}
										onClick={() => onShow(item.filter)}
									>
										<T id="npmos.hosts.rec.show" />
									</button>
								</div>
							</div>
						</li>
					))}
				</ul>
			)}
		</div>
	);
}
