// Sections NPMOS adds to System → Settings (the upstream page has "Default site"): env settings of
// NPMplus by group, the retention of security events and the GeoIP database.
import type { ReactNode } from "react";
import { T } from "src/locale";
import { RetentionForm } from "../pages/WafEvents/Retention";
import type { EnvGroup } from "./api";
import { EnvSection, RestartBanner } from "./EnvSection";
import { GeoipForm } from "./Geoip";

const GROUPS: EnvGroup[] = ["general", "network", "nginx", "tls", "logs", "external"];

export interface SettingsSection {
	id: string;
	label: string;
	render: (canManage: boolean) => ReactNode;
}

export const NPMOS_SETTINGS_SECTIONS: SettingsSection[] = [
	...GROUPS.map((group) => ({
		id: `npmos-${group}`,
		label: `npmos.system.group.${group}`,
		render: (canManage: boolean) => (
			<>
				<EnvSection group={group} />
				{group === "logs" && (
					<div className="px-4 pb-4">
						<h3 className="h4 mt-2">
							<T id="npmos.events.retention" />
						</h3>
						<RetentionForm canManage={canManage} />
					</div>
				)}
			</>
		),
	})),
	{
		id: "npmos-geoip",
		label: "npmos.system.group.geoip",
		render: (canManage: boolean) => <GeoipForm canManage={canManage} />,
	},
];

export { RestartBanner };
