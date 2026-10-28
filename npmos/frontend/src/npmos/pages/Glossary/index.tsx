// Glossary: what the English terms of the interface mean (docs/ROADMAP.md, phase 2).
import { IconSearch } from "@tabler/icons-react";
import { useState } from "react";
import { intl, T } from "src/locale";
import styles from "./Glossary.module.css";
import { GROUPS, TERMS } from "./terms";

const t = (id: string) => intl.formatMessage({ id });

export default function Glossary() {
	const [query, setQuery] = useState("");
	const q = query.trim().toLocaleLowerCase();
	const shown = TERMS.filter(
		(term) => !q || `${term.name} ${t(`npmos.glossary.${term.id}`)}`.toLocaleLowerCase().includes(q),
	);
	return (
		<div className={styles.page}>
			<div>
				<h1 className={styles.title}>
					<T id="npmos.glossary" />
				</h1>
				<p className={styles.subtitle}>
					<T id="npmos.glossary.subtitle" />
				</p>
			</div>
			<label className={styles.search}>
				<IconSearch size={16} />
				<input
					type="search"
					value={query}
					placeholder={t("npmos.glossary.search")}
					aria-label={t("npmos.glossary.search")}
					onChange={(e) => setQuery(e.target.value)}
				/>
			</label>
			{GROUPS.map((group) => {
				const terms = shown.filter((term) => term.group === group);
				if (!terms.length) return null;
				return (
					<section key={group} className="card">
						<div className={styles.group}>
							<h2 className={styles.groupTitle}>
								<T id={`npmos.glossary.group.${group}`} />
							</h2>
							<dl className={styles.list}>
								{terms.map((term) => (
									<div key={term.id} className={styles.term} id={term.id}>
										<dt>{term.name}</dt>
										<dd>
											<T id={`npmos.glossary.${term.id}`} />
										</dd>
									</div>
								))}
							</dl>
						</div>
					</section>
				);
			})}
			{!shown.length && (
				<p className={styles.subtitle}>
					<T id="npmos.nav.nothing-found" />
				</p>
			)}
		</div>
	);
}
