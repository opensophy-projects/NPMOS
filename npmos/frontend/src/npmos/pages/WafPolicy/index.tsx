// WAF → Policy (docs/ROADMAP.md, phase 5; ADR-0008): the open-appsec policy made of objects —
// practices, access control (rate limits), log triggers, responses, exceptions, trusted sources —
// and the default policy. Hosts take a template or own objects in their WAF settings. Every change
// is shown as the diff of local_policy.yaml first, applied at once and kept as a version.
import { IconCopy, IconDownload, IconEye, IconPencil, IconPlus, IconTrash, IconUpload } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { HasPermission, LoadingPage } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { showWafPolicyModal } from "../../modals/WafPolicyModal";
import {
	type DefaultPolicy,
	deleteObject,
	exportPolicy,
	getPolicyObjects,
	getVersions,
	KINDS,
	type Kind,
	POLICY_MODES,
	type PolicyObject,
	type PolicyObjects,
	type PolicyVersion,
	rollbackVersion,
	setDefaultPolicy,
} from "../../policy/api";
import { summary } from "../../policy/fields";
import { showImportModal } from "../../policy/ImportModal";
import { showObjectModal } from "../../policy/ObjectModal";
import { RefsEditor } from "../../policy/RefsEditor";
import { FormatNote } from "../../policy/Review";
import { showReviewModal } from "../../policy/ReviewModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown } from "../../ui/Dropdown";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../Notifications/Notifications.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

type Tab = "default" | Kind | "versions";

const QUERY = ["npmos-waf-policy-objects"];

/** the backend writes comments of versions in English: created exception/office, rollback to version 3 */
const versionComment = (comment: string) => {
	const rollback = /^rollback to version (\d+)$/.exec(comment);
	if (rollback) return t("npmos.waf.expert.rollback-comment", { id: rollback[1] });
	const change = /^(created|updated|deleted) ([a-z_]+)\/(.+)$/.exec(comment);
	if (change)
		return t(`npmos.policy.version.${change[1]}`, { kind: t(`npmos.policy.kind.${change[2]}`), name: change[3] });
	if (["initial", "import", "default policy"].includes(comment))
		return t(`npmos.policy.version.${comment.replace(" ", "-")}`);
	return comment;
};

function DefaultPolicyTab({ data, manage, refresh }: { data: PolicyObjects; manage: boolean; refresh: () => void }) {
	const [policy, setPolicy] = useState<DefaultPolicy>(data.policy);
	useEffect(() => setPolicy(data.policy), [data.policy]);
	const changed = JSON.stringify(policy) !== JSON.stringify(data.policy);

	const fromTemplate = (name: string) => setPolicy({ ...policy, ...data.templates[name], mode: policy.mode });

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<div>
					<h2 className={styles.cardTitle}>
						<T id="npmos.policy.default" />
					</h2>
					<p className="text-secondary small mb-0">
						<T id="npmos.policy.default.hint" />
					</p>
				</div>
				{manage && (
					<Dropdown
						floating
						inline
						ariaLabel={t("npmos.policy.from-template")}
						triggerClassName="btn btn-sm"
						trigger={<T id="npmos.policy.from-template" />}
						items={Object.keys(data.templates).map((name) => ({
							key: name,
							label: t(`npmos.policy.template.${name}`),
							onSelect: () => fromTemplate(name),
						}))}
					/>
				)}
			</div>
			<div className="row">
				<div className="col-md-6 mb-3">
					<label className="form-label" htmlFor="policy-default-mode">
						<T id="npmos.policy.rule.mode" />
					</label>
					<select
						id="policy-default-mode"
						className="form-select"
						disabled={!manage}
						value={policy.mode}
						onChange={(e) => setPolicy({ ...policy, mode: e.target.value as DefaultPolicy["mode"] })}
					>
						{POLICY_MODES.map((m) => (
							<option key={m} value={m}>
								{t(`npmos.policy.mode.${m}`)}
							</option>
						))}
					</select>
					<div className="form-hint">
						<T id="npmos.policy.default.mode-hint" />
					</div>
				</div>
			</div>
			<RefsEditor
				value={policy}
				onChange={(v) => setPolicy({ ...policy, ...v })}
				objects={data.objects}
				disabled={!manage}
			/>
			{manage && (
				<div className="d-flex gap-2 justify-content-end">
					<button
						type="button"
						className="btn btn-sm"
						disabled={!changed}
						onClick={() => setPolicy(data.policy)}
					>
						<T id="npmos.policy.reset" />
					</button>
					<button
						type="button"
						className="btn btn-sm btn-primary"
						disabled={!changed}
						onClick={() =>
							showReviewModal({
								change: { policy },
								title: "npmos.policy.default",
								onApply: async () => {
									await setDefaultPolicy(policy);
									showSuccess(t("npmos.policy.saved"));
									refresh();
								},
							})
						}
					>
						<T id="npmos.policy.review" />
					</button>
				</div>
			)}
		</section>
	);
}

function ObjectsTab({
	kind,
	data,
	manage,
	refresh,
}: {
	kind: Kind;
	data: PolicyObjects;
	manage: boolean;
	refresh: () => void;
}) {
	const objects = data.objects.filter((o) => o.kind === kind);
	const open = (props: { object?: PolicyObject; initial?: { name?: string; description?: string; spec?: any } }) =>
		showObjectModal({ kind, objects: data.objects, onSaved: refresh, ...props });
	const remove = (o: PolicyObject) =>
		showReviewModal({
			change: { delete: o.id },
			title: "npmos.policy.delete",
			onApply: async () => {
				await deleteObject(o.id);
				showSuccess(t("npmos.policy.deleted", { name: o.name }));
				refresh();
			},
		});

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<div>
					<h2 className={styles.cardTitle}>
						<T id={`npmos.policy.kinds.${kind}`} />
					</h2>
					<p className="text-secondary small mb-0">
						<T id={`npmos.policy.kind.${kind}.hint`} />
					</p>
				</div>
				{manage && (
					<button
						type="button"
						className={cn("btn btn-primary btn-sm", hostStyles.add)}
						onClick={() => open({})}
					>
						<IconPlus size={16} />
						<T id="npmos.policy.add" />
					</button>
				)}
			</div>
			{objects.length === 0 ? (
				<p className={styles.empty}>
					<T id="npmos.policy.no-objects" />
				</p>
			) : (
				<ul className={styles.list}>
					{objects.map((o) => (
						<li key={o.id} className={styles.item}>
							<div className={styles.main}>
								<div className={cn(styles.name, "font-monospace")}>
									{o.name}
									{o.builtin && (
										<span className="badge bg-secondary-lt ms-2">
											<T id="npmos.policy.builtin" />
										</span>
									)}
								</div>
								<div className={styles.sub}>
									{[o.description, ...summary(kind, o.spec)].filter(Boolean).join(" · ") || "—"}
								</div>
							</div>
							<button type="button" className={hostStyles.tool} onClick={() => open({ object: o })}>
								{o.builtin || !manage ? <IconEye size={16} /> : <IconPencil size={16} />}
								<span className={hostStyles.toolText}>
									<T id={o.builtin || !manage ? "npmos.policy.view" : "npmos.policy.edit"} />
								</span>
							</button>
							{manage && (
								<button
									type="button"
									className={hostStyles.tool}
									onClick={() =>
										open({
											initial: {
												name: `${o.name.replace(/^npmos-/, "")}-copy`,
												description: o.description,
												spec: o.spec,
											},
										})
									}
								>
									<IconCopy size={16} />
									<span className={hostStyles.toolText}>
										<T id="npmos.policy.duplicate" />
									</span>
								</button>
							)}
							{manage && !o.builtin && (
								<button
									type="button"
									className={cn(hostStyles.tool, hostStyles.danger)}
									onClick={() => remove(o)}
								>
									<IconTrash size={16} />
								</button>
							)}
						</li>
					))}
				</ul>
			)}
		</section>
	);
}

function VersionsTab({ manage, refresh }: { manage: boolean; refresh: () => void }) {
	const { locale } = useLocaleState();
	const { data, refetch } = useQuery<PolicyVersion[], Error>({
		queryKey: ["npmos-waf-policy-versions"],
		queryFn: getVersions,
	});
	const rollback = (id: number) =>
		showConfirmModal({
			tTitle: "npmos.waf.expert.rollback",
			tConfirm: "npmos.waf.expert.rollback",
			children: (
				<p>
					<T id="npmos.policy.rollback-confirm" data={{ id }} />
				</p>
			),
			onConfirm: async () => {
				try {
					await rollbackVersion(id);
					showSuccess(t("npmos.policy.saved"));
					refresh();
					refetch();
				} catch (err: any) {
					showError(err.message);
				}
			},
		});
	if (!data) return <LoadingPage noLogo />;
	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<h2 className={styles.cardTitle}>
					<T id="npmos.policy.versions" />
				</h2>
			</div>
			{data.length === 0 ? (
				<p className={styles.empty}>
					<T id="npmos.policy.versions.none" />
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>#</th>
								<th>
									<T id="npmos.waf.expert.saved-on" />
								</th>
								<th>
									<T id="npmos.waf.expert.user" />
								</th>
								<th>
									<T id="npmos.waf.expert.comment" />
								</th>
								<th />
							</tr>
						</thead>
						<tbody>
							{data.map((v, i) => (
								<tr key={v.id}>
									<td>{v.id}</td>
									<td className="text-nowrap">{formatDateTime(v.created_on, locale)}</td>
									<td>{v.user || "—"}</td>
									<td>{versionComment(v.comment)}</td>
									<td className="text-end">
										{i === 0 ? (
											<span className="badge bg-green-lt">
												<T id="npmos.waf.expert.in-force" />
											</span>
										) : (
											manage && (
												<button
													type="button"
													className="btn btn-sm"
													onClick={() => rollback(v.id)}
												>
													<T id="npmos.waf.expert.rollback" />
												</button>
											)
										)}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			)}
		</section>
	);
}

function WafPolicyPage() {
	const can = useCan();
	const manage = can("waf_policy", "manage");
	const queryClient = useQueryClient();
	const [tab, setTab] = useState<Tab>("default");
	const { data, isLoading, isError, error } = useQuery<PolicyObjects, Error>({
		queryKey: QUERY,
		queryFn: getPolicyObjects,
	});
	const refresh = () => {
		queryClient.invalidateQueries({ queryKey: QUERY });
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-policy-versions"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-policy"] });
	};

	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;

	const tabs: Tab[] = ["default", ...KINDS, "versions"];
	const applied = data.state.applied;

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.policy" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.policy.subtitle" />
					</p>
				</div>
				<div className={hostStyles.toolbar}>
					<button type="button" className={hostStyles.tool} onClick={showWafPolicyModal}>
						<IconEye size={16} />
						<span className={hostStyles.toolText}>
							<T id="npmos.waf.policy-show" />
						</span>
					</button>
					<Dropdown
						floating
						inline
						ariaLabel={t("npmos.policy.export")}
						triggerClassName={hostStyles.tool}
						trigger={
							<>
								<IconDownload size={16} />
								<span className={hostStyles.toolText}>
									<T id="npmos.policy.export" />
								</span>
							</>
						}
						items={(["v1beta2", "v1beta1"] as const).map((format) => ({
							key: format,
							label: format,
							onSelect: () => exportPolicy(format).catch((err) => showError(err.message)),
						}))}
					/>
					{manage && (
						<button
							type="button"
							className={hostStyles.tool}
							onClick={() => showImportModal({ onImported: refresh })}
						>
							<IconUpload size={16} />
							<span className={hostStyles.toolText}>
								<T id="npmos.policy.import" />
							</span>
						</button>
					)}
				</div>
			</div>

			<section className={cn("card", styles.card)}>
				<FormatNote format={data.state.format} reasons={data.state.reasons} warnings={data.state.warnings} />
				<p className="text-secondary small mb-0">
					<T id="npmos.policy.hosts" data={{ count: data.state.hosts }} />
					{applied && !applied.ok && (
						<span className="text-warning ms-2">
							<T id="npmos.waf.policy-not-sent" /> ({applied.error})
						</span>
					)}
				</p>
			</section>

			<ul className="nav nav-tabs flex-nowrap overflow-auto">
				{tabs.map((x) => (
					<li className="nav-item" key={x}>
						<button
							type="button"
							className={cn("nav-link text-nowrap", { active: tab === x })}
							onClick={() => setTab(x)}
						>
							<T
								id={
									x === "default" || x === "versions"
										? `npmos.policy.tab.${x}`
										: `npmos.policy.kinds.${x}`
								}
							/>
						</button>
					</li>
				))}
			</ul>

			{tab === "default" && <DefaultPolicyTab data={data} manage={manage} refresh={refresh} />}
			{tab === "versions" && <VersionsTab manage={manage} refresh={refresh} />}
			{tab !== "default" && tab !== "versions" && (
				<ObjectsTab kind={tab} data={data} manage={manage} refresh={refresh} />
			)}
		</div>
	);
}

const WafPolicy = () => (
	<HasPermission rbac="waf_policy" permission={VIEW} pageLoading loadingNoLogo>
		<WafPolicyPage />
	</HasPermission>
);

export default WafPolicy;
