// Recommendations above the hosts table (as in the Cloudflare DNS page) shown as notice blocks of
// opensophy.com; each one has a link that filters the table to the affected hosts.
import { IconChevronDown } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import { T } from "src/locale";
import { Admonition, type AdmonitionVariant } from "../../ui/Admonition";
import styles from "./Hosts.module.css";
import type { FilterRule, Recommendation } from "./rows";

const LIMIT = 3;

const VARIANT: Record<Recommendation["level"], AdmonitionVariant> = {
	alert: "alert",
	warning: "warning",
	info: "tip",
};

export function Recommendations({ items, onShow }: { items: Recommendation[]; onShow: (rules: FilterRule[]) => void }) {
	const [open, setOpen] = useState(true);
	const [all, setAll] = useState(false);
	if (!items.length) return null;
	// the most important first; the rest on request so the table stays in view
	const shown = all ? items : items.slice(0, LIMIT);
	return (
		<section className={styles.recs}>
			<button type="button" className={styles.recsHead} onClick={() => setOpen(!open)} aria-expanded={open}>
				<T id="npmos.hosts.recommendations" />
				<span className={styles.count}>{items.length}</span>
				<IconChevronDown size={16} className={cn(styles.recsChevron, open && styles.recsChevronOpen)} />
			</button>
			{open && (
				<div className={styles.recsList}>
					{shown.map((item) => (
						<Admonition
							key={item.id}
							compact
							variant={VARIANT[item.level]}
							title={<T id={`npmos.notice.${item.level}`} />}
							aside={
								<button type="button" className={styles.recLink} onClick={() => onShow(item.filter)}>
									<T id="npmos.hosts.rec.show" />
								</button>
							}
						>
							<span className={styles.recTitle}>
								<T id={`npmos.hosts.rec.${item.id}`} data={{ count: item.rows.length }} />
							</span>{" "}
							<T id={`npmos.hosts.rec.${item.id}.hint`} data={{ count: item.rows.length }} />
						</Admonition>
					))}
					{items.length > LIMIT && (
						<button type="button" className={styles.recLink} onClick={() => setAll(!all)}>
							<T
								id={all ? "npmos.hosts.rec.less" : "npmos.hosts.rec.all"}
								data={{ count: items.length }}
							/>
						</button>
					)}
				</div>
			)}
		</section>
	);
}
