import {
	IconArrowsCross,
	IconBell,
	IconBolt,
	IconBoltOff,
	IconCertificate,
	IconDisc,
	IconLock,
	IconLockAccess,
	IconSchool, // NginxionS: WAF learning
	IconShieldHalf,
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

// NginxionS: names of NginxionS objects in the audit log, shown in the language of the interface
const NGINXIONS_NAMES: Record<string, string> = {
	"open-appsec": "nginxions.audit.name.waf",
	"open-appsec agent": "nginxions.audit.name.agent",
	"open-appsec advanced model": "nginxions.audit.name.model",
	"local_policy.yaml": "nginxions.audit.name.policy",
	"local_policy.yaml (expert)": "nginxions.audit.name.expert",
	diagnostics: "nginxions.audit.name.diagnostics",
	"events.retention": "nginxions.settings.events-retention",
	pki: "nginxions.pki",
};

const getEventValue = (event: AuditLog) => {
	switch (event.objectType) {
		case "access-list":
		case "user":
		// NginxionS: System → Services events (restart, regenerate, diagnostics), WAF switch
		case "service":
		case "waf":
		case "role":
		case "setting":
		case "notification":
		case "pki":
		case "mtls":
		case "crowdsec":
		// NginxionS: labels of WAF learning
		case "waf_learning":
			return NGINXIONS_NAMES[event.meta?.name]
				? intl.formatMessage({ id: NGINXIONS_NAMES[event.meta.name] })
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
		// NginxionS: System → Services events
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
		case "pki":
			ico = <IconCertificate size={16} className={c} />;
			break;
		case "mtls":
			ico = <IconLockAccess size={16} className={c} />;
			break;
		case "crowdsec":
			ico = <IconShieldHalf size={16} className={c} />;
			break;
		// NginxionS: labels of WAF learning
		case "waf_learning":
			ico = <IconSchool size={16} className={c} />;
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
