// Names in the interface: built-in roles are translated, roles made in the GUI keep their name.
import { intl } from "src/locale";
import type { BuiltinRole } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export const roleName = (role: { name: string; builtin: BuiltinRole | null }) =>
	role.builtin ? t(`npmos.rbac.builtin.${role.builtin}`) : role.name;

export const roleDescription = (role: { description: string; builtin: BuiltinRole | null }) =>
	role.builtin ? t(`npmos.rbac.builtin.${role.builtin}.desc`) : role.description;

export const resourceLabel = (resource: string) => t(`npmos.rbac.resource.${resource}`);
export const resourceHint = (resource: string) => t(`npmos.rbac.resource.${resource}.desc`);
export const actionLabel = (action: string) => t(`npmos.rbac.action.${action}`);
export const actionHint = (resource: string, action: string) =>
	intl.messages[`npmos.rbac.hint.${resource}.${action}`]
		? t(`npmos.rbac.hint.${resource}.${action}`)
		: t(`npmos.rbac.action.${action}.desc`);
