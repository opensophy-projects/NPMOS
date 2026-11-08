import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ErrorNotFound, LoadingPage, Unhealthy } from "src/components";
import { useAuthState } from "src/context";
import { useHealth } from "src/hooks";
// NginxionS: the sidebar shell of opensophy.com/docs replaces the header, top menu, container and footer (phase 2)
import { Shell } from "src/nginxions/ui/Shell";

const Setup = lazy(() => import("src/pages/Setup"));
const Login = lazy(() => import("src/pages/Login"));
// NginxionS: the overview of NginxionS replaces the upstream dashboard (phase 2)
const Overview = lazy(() => import("src/nginxions/pages/Overview"));
const Roles = lazy(() => import("src/nginxions/pages/Roles"));
const Settings = lazy(() => import("src/pages/Settings"));
// NginxionS: one registry of all certificates with pages from the server (src/nginxions/pages/Certificates)
const Certificates = lazy(() => import("src/nginxions/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
// NginxionS: the audit log with pages from the server and filters (src/nginxions/pages/AuditLog)
const AuditLog = lazy(() => import("src/nginxions/pages/AuditLog"));
const Users = lazy(() => import("src/pages/Users"));
// NginxionS: proxy, redirection, stream and 404 hosts are one table (src/nginxions/pages/Hosts)
const Hosts = lazy(() => import("src/nginxions/pages/Hosts"));
// NginxionS: our pages live in src/nginxions/pages
const Services = lazy(() => import("src/nginxions/pages/Services"));
const WafEvents = lazy(() => import("src/nginxions/pages/WafEvents"));
const WafAnalytics = lazy(() => import("src/nginxions/pages/WafAnalytics"));
const Notifications = lazy(() => import("src/nginxions/pages/Notifications"));
// NginxionS: one page per agent: its policies (GUI or code) and the agent itself
const AgentOpenappsec = lazy(() => import("src/nginxions/pages/AgentOpenappsec"));
const BlockPage = lazy(() => import("src/nginxions/pages/BlockPage"));
const Pki = lazy(() => import("src/nginxions/pages/Pki"));
const Mtls = lazy(() => import("src/nginxions/pages/Mtls"));
const Crowdsec = lazy(() => import("src/nginxions/pages/Crowdsec"));
// NginxionS: the decisions of CrowdSec are in Analytics → Blocks
const Blocks = lazy(() => import("src/nginxions/pages/Crowdsec").then((m) => ({ default: m.Blocks })));

// NginxionS: the old address of the request log opens Events → Requests
/** /analytics/requests?… → /waf/events?kind=requests&… (the filters kept) */
function RequestsRedirect() {
	const params = new URLSearchParams(window.location.search);
	params.set("kind", "requests");
	return <Navigate to={`/waf/events?${params}`} replace />;
}

function Router() {
	const health = useHealth();
	const { authenticated } = useAuthState();

	if (health.isLoading) {
		return <LoadingPage />;
	}

	if (health.isError || health.data?.status !== "OK") {
		return <Unhealthy />;
	}

	if (!health.data?.setup) {
		return <Setup />;
	}

	if (!authenticated) {
		return (
			<Suspense fallback={<LoadingPage />}>
				<Login />
			</Suspense>
		);
	}

	return (
		<BrowserRouter>
			<Shell>
				<Suspense fallback={<LoadingPage noLogo />}>
					<Routes>
						<Route path="*" element={<ErrorNotFound />} />
						<Route path="/certificates" element={<Certificates />} />
						<Route path="/access" element={<Access />} />
						<Route path="/audit-log" element={<AuditLog />} />
						<Route path="/settings" element={<Settings />} />
						<Route path="/users" element={<Users />} />
						{/* NginxionS: the upstream host pages open the hosts table filtered by type */}
						<Route path="/nginx/proxy" element={<Navigate to="/hosts?f=type:is:proxy" replace />} />
						<Route
							path="/nginx/redirection"
							element={<Navigate to="/hosts?f=type:is:redirect" replace />}
						/>
						<Route path="/nginx/404" element={<Navigate to="/hosts?f=type:is:dead" replace />} />
						<Route path="/nginx/stream" element={<Navigate to="/hosts?f=type:is:stream" replace />} />
						{/* NginxionS: our pages */}
						<Route path="/hosts" element={<Hosts />} />
						{/* the glossary is gone: the documentation explains the terms */}
						<Route path="/glossary" element={<Navigate to="/" replace />} />
						<Route path="/roles" element={<Roles />} />
						<Route path="/system/services" element={<Services />} />
						<Route path="/system/notifications" element={<Notifications />} />
						<Route path="/pki" element={<Pki />} />
						<Route path="/mtls" element={<Mtls />} />
						<Route path="/crowdsec" element={<Crowdsec />} />
						<Route path="/agents/open-appsec" element={<AgentOpenappsec />} />
						<Route path="/agents/block-page" element={<BlockPage />} />
						<Route path="/analytics/blocks" element={<Blocks />} />
						{/* NginxionS: every request of the hosts is a kind of Events */}
						<Route path="/analytics/requests" element={<RequestsRedirect />} />
						{/* the pages of before open their place on the page of the agent */}
						<Route path="/waf/agent" element={<Navigate to="/agents/open-appsec?tab=agent" replace />} />
						<Route path="/waf/events" element={<WafEvents />} />
						<Route path="/waf/analytics" element={<WafAnalytics />} />
						<Route path="/waf/policy" element={<Navigate to="/agents/open-appsec" replace />} />
						<Route path="/waf/expert" element={<Navigate to="/agents/open-appsec?item=expert" replace />} />
						<Route path="/" element={<Overview />} />
					</Routes>
				</Suspense>
			</Shell>
		</BrowserRouter>
	);
}

export default Router;
