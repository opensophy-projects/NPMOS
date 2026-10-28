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
const Glossary = lazy(() => import("src/npmos/pages/Glossary"));
const Roles = lazy(() => import("src/npmos/pages/Roles"));
const Settings = lazy(() => import("src/pages/Settings"));
const Certificates = lazy(() => import("src/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
const AuditLog = lazy(() => import("src/pages/AuditLog"));
const Users = lazy(() => import("src/pages/Users"));
// NPMOS: proxy, redirection, stream and 404 hosts are one table (src/npmos/pages/Hosts)
const Hosts = lazy(() => import("src/npmos/pages/Hosts"));
// NPMOS: our pages live in src/npmos/pages
const Services = lazy(() => import("src/npmos/pages/Services"));
const WafAgent = lazy(() => import("src/npmos/pages/WafAgent"));
const WafEvents = lazy(() => import("src/npmos/pages/WafEvents"));
const WafAnalytics = lazy(() => import("src/npmos/pages/WafAnalytics"));
const WafPolicy = lazy(() => import("src/npmos/pages/WafPolicy"));

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
						<Route path="/glossary" element={<Glossary />} />
						<Route path="/roles" element={<Roles />} />
						<Route path="/system/services" element={<Services />} />
						<Route path="/waf/agent" element={<WafAgent />} />
						<Route path="/waf/events" element={<WafEvents />} />
						<Route path="/waf/analytics" element={<WafAnalytics />} />
						<Route path="/waf/policy" element={<WafPolicy />} />
						<Route path="/" element={<Overview />} />
					</Routes>
				</Suspense>
			</Shell>
		</BrowserRouter>
	);
}

export default Router;
