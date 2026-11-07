// The host through which this panel is open: disabling or deleting it, or making its domain a redirect or a 404,
// cuts the panel off at this address (the browser keeps asking the same domain). The forms say so first.
import { useFormikContext } from "formik";
import Alert from "react-bootstrap/Alert";
import { T } from "src/locale";

/** the domain the panel is open on */
const panelHostname = () => window.location.hostname.toLowerCase();

/** whether the domain names of a host take the domain of the panel (exactly or by a wildcard) */
export const servesPanel = (names: string[] = [], host = panelHostname()) =>
	names.some((raw) => {
		const name = String(raw).trim().toLowerCase();
		if (name === host) return true;
		// *.example.com takes a.example.com, not a.b.example.com
		return (
			name.startsWith("*.") && host.endsWith(name.slice(1)) && host.split(".").length === name.split(".").length
		);
	});

/** the panel answers on port 81 of the server whatever the hosts are */
const directPanelUrl = () => "https://<IP>:81";

/** the warning, shown where the change would cut the panel off */
export function PanelHostWarning({ action }: { action: "disable" | "delete" | "redirect" | "dead" }) {
	return (
		<Alert variant="warning" className="text-start">
			<T id={`npmos.hosts.panel.${action}`} data={{ host: panelHostname(), direct: directPanelUrl() }} />
		</Alert>
	);
}

/** inside the form of a host: the warning when its domain names take the domain of the panel */
export function PanelDomainAlert({ action }: { action: "redirect" | "dead" }) {
	const { values } = useFormikContext<{ domainNames?: string[] }>();
	if (!servesPanel(values.domainNames)) return null;
	return <PanelHostWarning action={action} />;
}

/** a permanent redirect (301, 308) is kept by browsers: it outlives the host */
export function PermanentRedirectHint() {
	const { values } = useFormikContext<{ forwardHttpCode?: number | string }>();
	if (![301, 308].includes(Number(values.forwardHttpCode))) return null;
	return (
		<div className="form-hint text-warning">
			<T id="npmos.hosts.redirect.permanent" />
		</div>
	);
}
