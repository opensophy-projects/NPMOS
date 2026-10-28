import cn from "classnames";
import { useState } from "react";
import { T } from "src/locale";
import { useCan } from "src/npmos/rbac/hooks";
// NPMOS: sections of NPMOS (env settings of NPMplus, retention of events), see src/npmos/system
import { NPMOS_SETTINGS_SECTIONS, RestartBanner } from "src/npmos/system/sections";
import DefaultSite from "./DefaultSite";

export default function Layout() {
	// NPMOS: the selected section
	const [section, setSection] = useState("default-site");
	const can = useCan();
	// Taken from https://preview.tabler.io/settings.html
	// Refer to that when updating this content

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-teal" />
			<div className="card-table">
				<div className="card-header">
					<div className="row w-full">
						<h2 className="mt-1 mb-0">
							<T id="settings" />
						</h2>
					</div>
				</div>
				<div className="row g-0">
					<div className="col-12 col-md-3 border-end">
						<div className="card-body mt-0 pt-0">
							<div className="list-group list-group-transparent">
								<a
									href="#"
									className={cn("list-group-item list-group-item-action d-flex align-items-center", {
										active: section === "default-site",
									})}
									onClick={(e) => {
										e.preventDefault();
										setSection("default-site");
									}}
								>
									<T id="settings.default-site" />
								</a>
								{/* NPMOS: sections of NPMOS after the upstream one */}
								{NPMOS_SETTINGS_SECTIONS.map((s) => (
									<a
										key={s.id}
										href="#"
										className={cn(
											"list-group-item list-group-item-action d-flex align-items-center",
											{
												active: section === s.id,
											},
										)}
										onClick={(e) => {
											e.preventDefault();
											setSection(s.id);
										}}
									>
										<T id={s.label} />
									</a>
								))}
							</div>
						</div>
					</div>
					<div className="col-12 col-md-9 d-flex flex-column">
						<RestartBanner />
						{section === "default-site" ? (
							<DefaultSite />
						) : (
							NPMOS_SETTINGS_SECTIONS.find((s) => s.id === section)?.render(can("settings", "manage"))
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
