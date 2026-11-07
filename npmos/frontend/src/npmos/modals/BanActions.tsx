// CrowdSec in the footer of the windows of Events (an event, a request): whether CrowdSec bans the address now and
// how long for, and a button to ban it (or extend the ban: "ban" again would only add a second decision).
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { useDecisions } from "../crowdsec/api";
import { showBanModal } from "../crowdsec/BanModal";
import { remaining } from "../crowdsec/labels";
import { useCan } from "../rbac/hooks";

/** "3h59m55.1s" → seconds */
const remainingSeconds = (d: string) => {
	const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(d || "");
	return m ? Number(m[1] || 0) * 3600 + Number(m[2] || 0) * 60 + Number(m[3] || 0) : 0;
};

/**
 * @param ip      the address (none: nothing is shown)
 * @param reason  the reason the ban window starts with
 * @param close   closes the window before the ban window opens
 */
export function useBan(ip: string | undefined, reason: string, close: () => void) {
	const can = useCan();
	const view = !!ip && can("crowdsec", "view");
	const decisions = useDecisions({ q: ip || "", limit: 50 }, { enabled: view });
	const active = (decisions.data?.items ?? []).filter((d) => d.value === ip);
	const longest = active.reduce<(typeof active)[number] | null>(
		(a, d) => (!a || remainingSeconds(d.duration) > remainingSeconds(a.duration) ? d : a),
		null,
	);
	const status =
		view && decisions.data ? (
			<span className="me-auto small text-secondary">
				{longest ? (
					<T
						id="npmos.events.cs-banned"
						data={{
							decision: ["ban", "captcha"].includes(longest.type)
								? intl.formatMessage({ id: `npmos.crowdsec.decision.${longest.type}` })
								: longest.type,
							left: remaining(longest.duration),
						}}
					/>
				) : (
					<T id="npmos.events.cs-not-banned" />
				)}
			</span>
		) : null;
	const button =
		ip && can("crowdsec", "decide") ? (
			<Button
				className="btn-outline-danger"
				onClick={() => {
					close();
					showBanModal({ values: [ip], reason, extend: !!longest });
				}}
			>
				<T id={longest ? "npmos.events.extend-ban" : "npmos.events.ban-ip"} />
			</Button>
		) : null;
	return { status, button };
}
