// Sections NginxionS adds to System → Settings (the upstream page has "Default site"): env settings of
// NPMplus by group, the retention of security events, the GeoIP database and the migration from
// NPM / NPMplus.
import type { ReactNode } from "react";
import { T } from "src/locale";
import { AcmeServers } from "../acme/AcmeServers";
import { RetentionForm } from "../pages/WafEvents/Retention";
import type { EnvGroup } from "./api";
import { EnvSection, RestartBanner } from "./EnvSection";
import { GeoipForm } from "./Geoip";
import { MigrationForm } from "./Migration";

const GROUPS: EnvGroup[] = ["general", "network", "nginx", "tls", "acme", "logs", "external"];

interface SettingsSection {
	id: string;
	label: string;
	render: (canManage: boolean) => ReactNode;
}

export const NGINXIONS_SETTINGS_SECTIONS: SettingsSection[] = [
	...GROUPS.map((group) => ({
		id: `nginxions-${group}`,
		label: `nginxions.system.group.${group}`,
		render: (canManage: boolean) => (
			<>
				{group === "acme" && <AcmeServers canManage={canManage} />}
				<EnvSection group={group} />
				{group === "logs" && (
					<div className="px-4 pb-4">
						<h3 className="h4 mt-2">
							<T id="nginxions.events.retention" />
						</h3>
						<RetentionForm canManage={canManage} />
					</div>
				)}
			</>
		),
	})),
	{
		id: "nginxions-geoip",
		label: "nginxions.system.group.geoip",
		render: (canManage: boolean) => <GeoipForm canManage={canManage} />,
	},
	{
		id: "nginxions-migration",
		label: "nginxions.system.group.migration",
		render: (canManage: boolean) => <MigrationForm canManage={canManage} />,
	},
];

export { RestartBanner };
