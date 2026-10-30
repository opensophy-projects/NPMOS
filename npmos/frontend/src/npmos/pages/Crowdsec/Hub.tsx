// CrowdSec → Hub: collections, parsers, scenarios and the rest of the hub snapshot on this node;
// install and remove (CrowdSec restarts), upgrade to the snapshot, upload a new snapshot, or take
// the index from the CrowdSec CDN when online hub updates are allowed.
import { IconUpload } from "@tabler/icons-react";
import cn from "classnames";
import { useRef, useState } from "react";
import { T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import {
	HUB_TYPES,
	type HubItem,
	type HubType,
	hubItem,
	hubOnline,
	hubUpgrade,
	uploadHubSnapshot,
	useHub,
} from "../../crowdsec/api";
import { t } from "../../crowdsec/labels";
import { useCan } from "../../rbac/hooks";
import styles from "../Pki/Pki.module.css";
import { SearchField } from "../../ui/SearchField";

const STATUS_TONE: Record<string, string> = {
	"up-to-date": "bg-green-lt",
	outdated: "bg-yellow-lt",
	tainted: "bg-orange-lt",
	local: "bg-blue-lt",
	broken: "bg-red-lt",
};

const MAX_ROWS = 300;

export function HubTab({ onlineHub, refresh }: { onlineHub: boolean; refresh: () => void }) {
	const can = useCan();
	const manage = can("crowdsec", "manage");
	const [type, setType] = useState<HubType | "">("collections");
	const [q, setQ] = useState("");
	const [installed, setInstalled] = useState(true);
	const [busy, setBusy] = useState("");
	const file = useRef<HTMLInputElement>(null);
	const hub = useHub({ type, q, installed });
	const items = hub.data ?? [];
	const outdated = items.filter((i) => i.status === "outdated").length;

	const run = async (key: string, action: () => Promise<string>) => {
		setBusy(key);
		try {
			showSuccess(await action());
		} catch (err: any) {
			showError(err.message);
		}
		setBusy("");
		hub.refetch();
		refresh();
	};

	const toggle = (i: HubItem) =>
		run(`${i.type}:${i.name}`, async () => {
			const action = i.installed ? "remove" : "install";
			const r = await hubItem({ type: i.type, name: i.name, action });
			return t(`npmos.crowdsec.hub.${action}.done`, { count: r.items.length });
		});

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.filters}>
				<SearchField
					variant="inset"
					value={q}
					onChange={(value) => setQ(value)}
					placeholder={t("npmos.crowdsec.hub.search")}
				/>
				<select
					className="form-select form-select-sm w-auto"
					aria-label={t("npmos.crowdsec.hub.type")}
					value={type}
					onChange={(e) => setType(e.target.value as HubType | "")}
				>
					<option value="">{t("npmos.crowdsec.hub.type.all")}</option>
					{HUB_TYPES.map((x) => (
						<option key={x} value={x}>
							{t(`npmos.crowdsec.hub.type.${x}`)}
						</option>
					))}
				</select>
				<label className="form-check form-switch mb-0">
					<input
						type="checkbox"
						className="form-check-input"
						checked={installed}
						onChange={(e) => setInstalled(e.target.checked)}
					/>
					<span className="form-check-label">
						<T id="npmos.crowdsec.hub.installed-only" />
					</span>
				</label>
				{manage && (
					<div className="d-flex gap-2 ms-auto">
						{outdated > 0 && (
							<button
								type="button"
								className="btn btn-sm"
								disabled={!!busy}
								onClick={() =>
									run("upgrade", async () =>
										t("npmos.crowdsec.hub.upgraded", { count: (await hubUpgrade()).items.length }),
									)
								}
							>
								<T id="npmos.crowdsec.hub.upgrade" data={{ count: outdated }} />
							</button>
						)}
						{onlineHub && (
							<button
								type="button"
								className="btn btn-sm"
								disabled={!!busy}
								onClick={() =>
									run("online", async () =>
										t("npmos.crowdsec.hub.index-updated", { count: (await hubOnline()).items }),
									)
								}
							>
								<T id="npmos.crowdsec.hub.online" />
							</button>
						)}
						<button
							type="button"
							className="btn btn-sm"
							disabled={!!busy}
							onClick={() => file.current?.click()}
						>
							<IconUpload size={16} />
							<T id="npmos.crowdsec.hub.upload" />
						</button>
						<input
							ref={file}
							type="file"
							accept=".json,.gz,.tgz,application/json,application/gzip"
							hidden
							onChange={(e) => {
								const f = e.target.files?.[0];
								e.target.value = "";
								if (f)
									run("upload", async () => {
										const r = await uploadHubSnapshot(f);
										return t("npmos.crowdsec.hub.uploaded", {
											count: r.items,
											data: r.data_files ?? 0,
										});
									});
							}}
						/>
					</div>
				)}
			</div>
			<div className="text-secondary small mb-2">
				<T id="npmos.crowdsec.hub.hint" />
			</div>
			{hub.isError ? (
				<p className="text-danger mb-0">{hub.error.message}</p>
			) : !items.length ? (
				<p className={styles.empty}>
					<T id={hub.isLoading ? "loading" : "npmos.crowdsec.none-found"} />
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.crowdsec.name" />
								</th>
								<th>
									<T id="npmos.crowdsec.hub.type" />
								</th>
								<th>
									<T id="npmos.crowdsec.status" />
								</th>
								<th>
									<T id="npmos.crowdsec.version" />
								</th>
								{manage && <th className="w-1" />}
							</tr>
						</thead>
						<tbody>
							{items.slice(0, MAX_ROWS).map((i) => {
								const key = `${i.type}:${i.name}`;
								const locked =
									i.installed && (i.required || i.neededBy.length > 0 || i.installed === "local");
								return (
									<tr key={key}>
										<td>
											<div className="font-monospace">{i.name}</div>
											<div className={styles.sub} title={i.description}>
												{i.description}
											</div>
											{i.neededBy.length > 0 && (
												<div className="small text-secondary">
													<T
														id="npmos.crowdsec.hub.needed-by"
														data={{ names: i.neededBy.join(", ") }}
													/>
												</div>
											)}
										</td>
										<td className="text-nowrap">{t(`npmos.crowdsec.hub.type.${i.type}`)}</td>
										<td>
											{i.installed ? (
												<span
													className={cn("badge", STATUS_TONE[i.status] || "bg-secondary-lt")}
												>
													{t(`npmos.crowdsec.hub.status.${i.status || "installed"}`)}
												</span>
											) : (
												<span className="text-secondary">
													<T id="npmos.crowdsec.hub.status.not-installed" />
												</span>
											)}
											{i.required && (
												<span className="badge bg-blue-lt ms-1">
													<T id="npmos.crowdsec.hub.required" />
												</span>
											)}
										</td>
										<td className="text-nowrap">
											{i.version && i.version !== i.latest
												? `${i.version} → ${i.latest}`
												: i.latest}
										</td>
										{manage && (
											<td>
												<button
													type="button"
													className={cn(
														"btn btn-sm",
														i.installed ? "btn-ghost-danger" : "btn-outline-primary",
													)}
													disabled={!!busy || !!locked}
													title={locked ? t("npmos.crowdsec.hub.locked") : undefined}
													onClick={() => toggle(i)}
												>
													{busy === key ? (
														<span className="spinner-border spinner-border-sm" />
													) : (
														<T
															id={
																i.installed
																	? "npmos.crowdsec.hub.remove"
																	: "npmos.crowdsec.hub.install"
															}
														/>
													)}
												</button>
											</td>
										)}
									</tr>
								);
							})}
						</tbody>
					</table>
					{items.length > MAX_ROWS && (
						<p className={styles.empty}>
							<T id="npmos.crowdsec.hub.more" data={{ count: items.length - MAX_ROWS }} />
						</p>
					)}
				</div>
			)}
		</section>
	);
}
