// NPMOS: hardcoded strings moved to the locale (en, ru)
import { Page } from "src/components";
import { T } from "src/locale";

export function Unhealthy() {
	return (
		<Page className="page-center">
			<div className="container-tight py-4">
				<div className="empty">
					<div className="empty-img">
						<img src="/images/unhealthy.svg" alt="" />
					</div>
					<p className="empty-title">
						<T id="npmos.common.unhealthy-title" />
					</p>
					<p className="empty-subtitle text-secondary">
						<T id="npmos.common.unhealthy-subtitle" />
					</p>
				</div>
			</div>
		</Page>
	);
}
