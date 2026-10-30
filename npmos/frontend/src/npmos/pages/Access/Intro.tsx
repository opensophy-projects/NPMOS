// Hosts → Access lists: what an access list is for, its two kinds of rules and where it is applied, above the
// table of NPMplus (the upstream page had a title and a help button only).
import { IconKey, IconNetwork, IconPlugConnected } from "@tabler/icons-react";
import { T } from "src/locale";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "./Intro.module.css";

const POINTS = [
	{ id: "password", icon: IconKey },
	{ id: "ip", icon: IconNetwork },
	{ id: "apply", icon: IconPlugConnected },
] as const;

export function AccessIntro() {
	return (
		<div className={styles.intro}>
			<div>
				<h1 className={hostStyles.title}>
					<T id="access-lists" />
				</h1>
				<p className={hostStyles.subtitle}>
					<T id="npmos.access.description" />
				</p>
			</div>
			<div className={styles.points}>
				{POINTS.map(({ id, icon: Icon }) => (
					<div key={id} className={styles.point}>
						<Icon size={18} className={styles.icon} />
						<div>
							<div className={styles.pointTitle}>
								<T id={`npmos.access.point.${id}`} />
							</div>
							<div className={styles.pointText}>
								<T id={`npmos.access.point.${id}.text`} />
							</div>
						</div>
					</div>
				))}
			</div>
		</div>
	);
}
