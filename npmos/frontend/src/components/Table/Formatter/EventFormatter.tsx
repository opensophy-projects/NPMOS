import {
	IconArrowsCross,
	IconBell,
	IconBolt,
	IconBoltOff,
	IconDisc,
	IconLock,
	IconServer,
	IconSettings,
	IconShield,
	IconShieldCheck,
	IconUser,
	IconUsersGroup,
} from "@tabler/icons-react";
import cn from "classnames";
import type { AuditLog } from "src/api/backend";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";

// NPMOS: names of NPMOS objects in the audit log, shown in the language of the interface
const NPMOS_NAMES: Record<string, string> = {
	"open-appsec": "npmos.audit.name.waf",
	"open-appsec agent": "npmos.audit.name.agent",
	"open-appsec advanced model": "npmos.audit.name.model",
	"local_policy.yaml": "npmos.audit.name.policy",
	"local_policy.yaml (expert)": "npmos.audit.name.expert",
	diagnostics: "npmos.audit.name.diagnostics",
	"events.retention": "npmos.settings.events-retention",
};

const getEventValue = (event: AuditLog) => {
	switch (event.objectType) {
		case "access-list":
		case "user":
		// NPMOS: System → Services events (restart, regenerate, diagnostics), WAF switch
		case "service":
		case "waf":
		case "role":
		case "setting":
		case "notification":
			return NPMOS_NAMES[event.meta?.name]
				? intl.formatMessage({ id: NPMOS_NAMES[event.meta.name] })
				: event.meta?.name;
		case "proxy-host":
		case "redirection-host":
		case "dead-host":
			return event.meta?.domainNames?.join(", ") || "N/A";
		case "stream":
			return event.meta?.incomingPort || "N/A";
		case "certificate":
			return event.meta?.domainNames?.join(", ") || event.meta?.niceName || "N/A";
		default:
			return `UNKNOWN EVENT TYPE: ${event.objectType}`;
	}
};

const getColorForAction = (action: string) => {
	switch (action) {
		case "created":
			return "text-lime";
		case "deleted":
			return "text-red";
		default:
			return "text-blue";
	}
};

const getIcon = (row: AuditLog) => {
	const c = cn(getColorForAction(row.action), "me-1");
	let ico = null;
	switch (row.objectType) {
		case "user":
			ico = <IconUser size={16} className={c} />;
			break;
		case "proxy-host":
			ico = <IconBolt size={16} className={c} />;
			break;
		case "redirection-host":
			ico = <IconArrowsCross size={16} className={c} />;
			break;
		case "dead-host":
			ico = <IconBoltOff size={16} className={c} />;
			break;
		case "stream":
			ico = <IconDisc size={16} className={c} />;
			break;
		case "access-list":
			ico = <IconLock size={16} className={c} />;
			break;
		case "certificate":
			ico = <IconShield size={16} className={c} />;
			break;
		// NPMOS: System → Services events
		case "service":
			ico = <IconServer size={16} className={c} />;
			break;
		case "waf":
			ico = <IconShieldCheck size={16} className={c} />;
			break;
		case "role":
			ico = <IconUsersGroup size={16} className={c} />;
			break;
		case "setting":
			ico = <IconSettings size={16} className={c} />;
			break;
		case "notification":
			ico = <IconBell size={16} className={c} />;
			break;
	}

	return ico;
};

interface Props {
	row: AuditLog;
}
export function EventFormatter({ row }: Props) {
	const { locale } = useLocaleState();
	return (
		<div className="flex-fill">
			<div className="font-weight-medium">
				{getIcon(row)}
				<T id={`object.event.${row.action}`} tData={{ object: row.objectType }} />
				&nbsp; &mdash; <span className="badge">{getEventValue(row)}</span>
			</div>
			<div className="text-secondary mt-1">{formatDateTime(row.createdOn, locale)}</div>
		</div>
	);
}
