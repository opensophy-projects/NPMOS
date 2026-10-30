import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ErrorNotFound, LoadingPage, Unhealthy } from "src/components";
import { useAuthState } from "src/context";
import { useHealth } from "src/hooks";
// NPMOS: the sidebar shell of opensophy.com/docs replaces the header, top menu, container and footer (phase 2)
import { Shell } from "src/npmos/ui/Shell";

const Setup = lazy(() => import("src/pages/Setup"));
const Login = lazy(() => import("src/pages/Login"));
// NPMOS: the overview of NPMOS replaces the upstream dashboard (phase 2)
const Overview = lazy(() => import("src/npmos/pages/Overview"));
const Roles = lazy(() => import("src/npmos/pages/Roles"));
const Settings = lazy(() => import("src/pages/Settings"));
// NPMOS: one registry of all certificates with pages from the server (src/npmos/pages/Certificates)
const Certificates = lazy(() => import("src/npmos/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
// NPMOS: the audit log with pages from the server and filters (src/npmos/pages/AuditLog)
const AuditLog = lazy(() => import("src/npmos/pages/AuditLog"));
const Users = lazy(() => import("src/pages/Users"));
// NPMOS: proxy, redirection, stream and 404 hosts are one table (src/npmos/pages/Hosts)
const Hosts = lazy(() => import("src/npmos/pages/Hosts"));
// NPMOS: our pages live in src/npmos/pages
const Services = lazy(() => import("src/npmos/pages/Services"));
const WafEvents = lazy(() => import("src/npmos/pages/WafEvents"));
const WafAnalytics = lazy(() => import("src/npmos/pages/WafAnalytics"));
const Notifications = lazy(() => import("src/npmos/pages/Notifications"));
// NPMOS: one page per agent: its policies (GUI or code) and the agent itself
const AgentOpenappsec = lazy(() => import("src/npmos/pages/AgentOpenappsec"));
const BlockPage = lazy(() => import("src/npmos/pages/BlockPage"));
const Pki = lazy(() => import("src/npmos/pages/Pki"));
const Mtls = lazy(() => import("src/npmos/pages/Mtls"));
const Crowdsec = lazy(() => import("src/npmos/pages/Crowdsec"));
// NPMOS: the decisions of CrowdSec are in Analytics → Blocks
const Blocks = lazy(() => import("src/npmos/pages/Crowdsec").then((m) => ({ default: m.Blocks })));

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
						{/* NPMOS: the upstream host pages open the hosts table filtered by type */}
						<Route path="/nginx/proxy" element={<Navigate to="/hosts?f=type:is:proxy" replace />} />
						<Route
							path="/nginx/redirection"
							element={<Navigate to="/hosts?f=type:is:redirect" replace />}
						/>
						<Route path="/nginx/404" element={<Navigate to="/hosts?f=type:is:dead" replace />} />
						<Route path="/nginx/stream" element={<Navigate to="/hosts?f=type:is:stream" replace />} />
						{/* NPMOS: our pages */}
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
