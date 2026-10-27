import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { ErrorNotFound, LoadingPage, Unhealthy } from "src/components";
import { useAuthState } from "src/context";
import { useHealth } from "src/hooks";
// NPMOS: the sidebar shell of opensophy.com/docs replaces the header, top menu, container and footer (phase 2)
import { Shell } from "src/npmos/ui/Shell";

const Setup = lazy(() => import("src/pages/Setup"));
const Login = lazy(() => import("src/pages/Login"));
const Dashboard = lazy(() => import("src/pages/Dashboard"));
const Settings = lazy(() => import("src/pages/Settings"));
const Certificates = lazy(() => import("src/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
const AuditLog = lazy(() => import("src/pages/AuditLog"));
const Users = lazy(() => import("src/pages/Users"));
const ProxyHosts = lazy(() => import("src/pages/Nginx/ProxyHosts"));
const RedirectionHosts = lazy(() => import("src/pages/Nginx/RedirectionHosts"));
const DeadHosts = lazy(() => import("src/pages/Nginx/DeadHosts"));
const Streams = lazy(() => import("src/pages/Nginx/Streams"));
// NPMOS: our pages live in src/npmos/pages
const Services = lazy(() => import("src/npmos/pages/Services"));
const WafAgent = lazy(() => import("src/npmos/pages/WafAgent"));
const WafEvents = lazy(() => import("src/npmos/pages/WafEvents"));
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
						<Route path="/nginx/proxy" element={<ProxyHosts />} />
						<Route path="/nginx/redirection" element={<RedirectionHosts />} />
						<Route path="/nginx/404" element={<DeadHosts />} />
						<Route path="/nginx/stream" element={<Streams />} />
						{/* NPMOS: our pages */}
						<Route path="/system/services" element={<Services />} />
						<Route path="/waf/agent" element={<WafAgent />} />
						<Route path="/waf/events" element={<WafEvents />} />
						<Route path="/waf/policy" element={<WafPolicy />} />
						<Route path="/" element={<Dashboard />} />
					</Routes>
				</Suspense>
			</Shell>
		</BrowserRouter>
	);
}

export default Router;
