// System → Services: containers of the NPMOS stack (through npmos-control)
import { IconFileZip, IconRefresh, IconReload } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showSuccess } from "src/notifications";
import { useCan } from "../../rbac/hooks";
import { downloadDiagnostics, regenerateNginx, restartService, type Service } from "../../api";
import { useServices } from "../../hooks";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { showServiceLogsModal } from "../../modals/ServiceLogsModal";

const STATE_COLORS: Record<string, string> = {
	running: "green",
	restarting: "yellow",
	created: "secondary",
	paused: "secondary",
	exited: "red",
	dead: "red",
	removing: "secondary",
};

// docker reports health only inside the status text: "Up 5 minutes (healthy)"
const getHealth = (status: string): "healthy" | "unhealthy" | "starting" | null => {
	const match = status.match(/\((healthy|unhealthy|health: starting)\)/);
	if (!match) return null;
	return match[1] === "health: starting" ? "starting" : (match[1] as "healthy" | "unhealthy");
};

const HEALTH_COLORS = { healthy: "green", unhealthy: "red", starting: "yellow" };

function ServicesTable({ services }: { services: Service[] }) {
	const can = useCan();
	const queryClient = useQueryClient();

	const onRestart = (service: Service) =>
		showConfirmModal({
			tTitle: "npmos.services.restart-title",
			tConfirm: "npmos.services.restart",
			danger: true,
			children: (
				<p>
					<T
						id={
							service.service === "npmos"
								? "npmos.services.restart-npmos"
								: "npmos.services.restart-confirm"
						}
						data={{ service: service.service }}
					/>
				</p>
			),
			onConfirm: async () => {
				await restartService(service.service);
				showSuccess(
					intl.formatMessage({ id: "npmos.services.restart-requested" }, { service: service.service }),
				);
				queryClient.invalidateQueries({ queryKey: ["npmos-services"] });
			},
		});

	return (
		<div className="table-responsive">
			<table className="table table-vcenter card-table">
				<thead>
					<tr>
						<th>
							<T id="npmos.services.service" />
						</th>
						<th>
							<T id="npmos.services.state" />
						</th>
						<th>
							<T id="npmos.services.version" />
						</th>
						<th className="w-1" />
					</tr>
				</thead>
				<tbody>
					{services.map((s) => {
						const health = getHealth(s.status);
						return (
							<tr key={s.id}>
								<td>
									<div className="font-weight-medium">{s.service}</div>
									<div className="text-secondary small">{s.name}</div>
								</td>
								<td>
									<span className={`badge bg-${STATE_COLORS[s.state] || "secondary"}-lt me-1`}>
										<T id={`npmos.services.state.${s.state}`} />
									</span>
									{health && (
										<span className={`badge bg-${HEALTH_COLORS[health]}-lt`}>
											<T id={`npmos.services.health.${health}`} />
										</span>
									)}
									<div className="text-secondary small mt-1">{s.status}</div>
								</td>
								<td>
									<div>{s.version || "—"}</div>
									<div className="text-secondary small text-break">{s.image}</div>
								</td>
								<td className="text-nowrap">
									<Button size="sm" className="me-2" onClick={() => showServiceLogsModal(s.service)}>
										<T id="npmos.services.logs" />
									</Button>
									{s.restartable && can("services", "manage") && (
										<Button size="sm" actionType="warning" onClick={() => onRestart(s)}>
											<IconReload size={16} className="me-1" />
											<T id="npmos.services.restart" />
										</Button>
									)}
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
		</div>
	);
}

function ServicesCard() {
	const can = useCan();
	const { data, isLoading, isError, error } = useServices();
	const [downloading, setDownloading] = useState(false);

	const onRegenerate = () =>
		showConfirmModal({
			tTitle: "npmos.services.regenerate",
			tConfirm: "npmos.services.regenerate-confirm",
			children: (
				<p>
					<T id="npmos.services.regenerate-text" />
				</p>
			),
			onConfirm: async () => {
				await regenerateNginx();
				showSuccess(intl.formatMessage({ id: "npmos.services.regenerated" }));
			},
		});

	const onDiagnostics = async () => {
		setDownloading(true);
		try {
			await downloadDiagnostics();
		} finally {
			setDownloading(false);
		}
	};

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-blue" />
			<div className="card-header">
				<div className="row w-full">
					<div className="col">
						<h2 className="mt-1 mb-0">
							<T id="npmos.services" />
						</h2>
					</div>
					<div className="col-md-auto col-sm-12">
						<div className="ms-auto d-flex flex-wrap btn-list">
							{can("services", "manage") && (
								<>
									<Button size="sm" onClick={onRegenerate}>
										<IconRefresh size={16} className="me-1" />
										<T id="npmos.services.regenerate" />
									</Button>
									<Button size="sm" onClick={onDiagnostics} isLoading={downloading}>
										<IconFileZip size={16} className="me-1" />
										<T id="npmos.services.diagnostics" />
									</Button>
								</>
							)}
						</div>
					</div>
				</div>
			</div>
			{isLoading && <LoadingPage />}
			{isError && (
				<Alert variant="danger" className="m-3">
					{error?.message || <T id="npmos.common.unknown-error" />}
				</Alert>
			)}
			{data && <ServicesTable services={data} />}
		</div>
	);
}

const Services = () => (
	<HasPermission rbac="services" permission={VIEW} pageLoading loadingNoLogo>
		<ServicesCard />
	</HasPermission>
);

export default Services;
