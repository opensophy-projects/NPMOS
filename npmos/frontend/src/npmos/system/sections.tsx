// Sections NPMOS adds to System → Settings (the upstream page has "Default site"): env settings of
// NPMplus by group and the retention of security events.
import type { ReactNode } from "react";
import { T } from "src/locale";
import { RetentionForm } from "../pages/WafEvents/Retention";
import type { EnvGroup } from "./api";
import { EnvSection, RestartBanner } from "./EnvSection";

const GROUPS: EnvGroup[] = ["general", "network", "nginx", "tls", "logs", "external"];

export interface SettingsSection {
	id: string;
	label: string;
	render: (canManage: boolean) => ReactNode;
}

export const NPMOS_SETTINGS_SECTIONS: SettingsSection[] = GROUPS.map((group) => ({
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
}));

export { RestartBanner };
