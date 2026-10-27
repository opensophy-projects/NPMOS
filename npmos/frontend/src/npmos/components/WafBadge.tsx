// WAF state of a proxy host in the host list (one shared query for all rows).
import { T } from "src/locale";
import { useWafHosts } from "../hooks";

export function WafBadge({ hostId }: { hostId: number }) {
	const { data } = useWafHosts();
	const waf = data?.[hostId];
	if (!waf?.enabled) {
		return (
			<span className="badge bg-secondary-lt">
				<T id="npmos.waf.location.off" />
			</span>
		);
	}
	return waf.mode === "prevent-learn" ? (
		<span className="badge bg-red-lt">Prevent</span>
	) : (
		<span className="badge bg-orange-lt">Detect</span>
	);
}
