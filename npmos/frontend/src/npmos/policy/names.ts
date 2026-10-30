// Names of the built-in objects of the policy in the language of the interface: "npmos-log" says nothing to
// someone who has not read local_policy.yaml. The technical name stays visible next to it (it is what the
// code and the agent use).
import { intl } from "src/locale";

export const BUILTIN_NAMES = [
	"npmos-recommended",
	"npmos-strict",
	"npmos-api",
	"npmos-no-rate-limit",
	"npmos-log",
	"npmos-403",
	"npmos-block-page",
] as const;

/** the readable name of an object: a translation of a built-in one, the name of the administrator's */
export const objectTitle = (o: { name: string; builtin?: boolean }) =>
	o.builtin && (BUILTIN_NAMES as readonly string[]).includes(o.name)
		? intl.formatMessage({ id: `npmos.policy.builtin.${o.name}` })
		: o.name;

/** what a built-in object does, or nothing */
export const objectHint = (o: { name: string; builtin?: boolean }) =>
	o.builtin && (BUILTIN_NAMES as readonly string[]).includes(o.name)
		? intl.formatMessage({ id: `npmos.policy.builtin.${o.name}.hint` })
		: "";
