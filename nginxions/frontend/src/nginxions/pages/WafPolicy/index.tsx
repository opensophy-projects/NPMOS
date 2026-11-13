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
import { objectHint, objectTitle } from "../../policy/names";
import { showImportModal } from "../../policy/ImportModal";
import { showObjectModal } from "../../policy/ObjectModal";
import { RefsEditor } from "../../policy/RefsEditor";
import { AppliedCheckNote, FormatNote } from "../../policy/Review";
import { showReviewModal } from "../../policy/ReviewModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown } from "../../ui/Dropdown";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "../Notifications/Notifications.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

type Tab = "default" | Kind | "versions";

export const QUERY = ["nginxions-waf-policy-objects"];

/** the backend writes comments of versions in English: created exception/office, rollback to version 3 */
const versionComment = (comment: string) => {
	const rollback = /^rollback to version (\d+)$/.exec(comment);
	if (rollback) return t("nginxions.waf.expert.rollback-comment", { id: rollback[1] });
	const change = /^(created|updated|deleted) ([a-z_]+)\/(.+)$/.exec(comment);
	if (change)
		return t(`nginxions.policy.version.${change[1]}`, {
			kind: t(`nginxions.policy.kind.${change[2]}`),
			name: change[3],
		});
	if (["initial", "import", "default policy"].includes(comment))
		return t(`nginxions.policy.version.${comment.replace(" ", "-")}`);
	return comment;
};

export function DefaultPolicyTab({
	data,
	manage,
	refresh,
}: {
	data: PolicyObjects;
	manage: boolean;
	refresh: () => void;
}) {
	const [policy, setPolicy] = useState<DefaultPolicy>(data.policy);
	useEffect(() => setPolicy(data.policy), [data.policy]);
	const changed = JSON.stringify(policy) !== JSON.stringify(data.policy);

	const fromTemplate = (name: string) => setPolicy({ ...policy, ...data.templates[name], mode: policy.mode });

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<div>
					<h2 className={styles.cardTitle}>
						<T id="nginxions.policy.default" />
					</h2>
					<p className="text-secondary small mb-0">
						<T id="nginxions.policy.default.hint" />
					</p>
				</div>
				{manage && (
					<Dropdown
						floating
						inline
						ariaLabel={t("nginxions.policy.from-template")}
						triggerClassName="btn btn-sm"
						trigger={<T id="nginxions.policy.from-template" />}
						items={Object.keys(data.templates).map((name) => ({
							key: name,
							label: t(`nginxions.policy.template.${name}`),
							onSelect: () => fromTemplate(name),
						}))}
					/>
				)}
			</div>
			<div className="row">
				<div className="col-md-6 mb-3">
					<label className="form-label" htmlFor="policy-default-mode">
						<T id="nginxions.policy.rule.mode" />
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
								{t(`nginxions.policy.mode.${m}`)}
							</option>
						))}
					</select>
					<div className="form-hint">
						<T id="nginxions.policy.default.mode-hint" />
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
						<T id="nginxions.policy.reset" />
					</button>
					<button
						type="button"
						className="btn btn-sm btn-primary"
						disabled={!changed}
						onClick={() =>
							showReviewModal({
								change: { policy },
								title: "nginxions.policy.default",
								onApply: async () => {
									await setDefaultPolicy(policy);
									showSuccess(t("nginxions.policy.saved"));
									refresh();
								},
							})
						}
					>
						<T id="nginxions.policy.review" />
					</button>
				</div>
			)}
		</section>
	);
}

export function ObjectsTab({
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
			title: "nginxions.policy.delete",
			onApply: async () => {
				await deleteObject(o.id);
				showSuccess(t("nginxions.policy.deleted", { name: o.name }));
				refresh();
			},
		});

	return (
		<section className={cn("card", styles.card)}>
			<div className={styles.cardHead}>
				<div>
					<h2 className={styles.cardTitle}>
						<T id={`nginxions.policy.kinds.${kind}`} />
					</h2>
					<p className="text-secondary small mb-0">
						<T id={`nginxions.policy.kind.${kind}.hint`} />
					</p>
				</div>
				{manage && (
					<button
						type="button"
						className={cn("btn btn-primary btn-sm", hostStyles.add)}
						onClick={() => open({})}
					>
						<IconPlus size={16} />
						<T id="nginxions.policy.add" />
					</button>
				)}
			</div>
			{objects.length === 0 ? (
				<p className={styles.empty}>
					<T id="nginxions.policy.no-objects" />
				</p>
			) : (
				<ul className={styles.list}>
					{objects.map((o) => (
						<li key={o.id} className={styles.item}>
							<div className={styles.main}>
								<div className={styles.name}>
									{objectTitle(o)}
									{o.builtin && (
										<span className="text-secondary font-monospace small ms-2">{o.name}</span>
									)}
									{o.builtin && (
										<span className="badge bg-secondary-lt ms-2">
											<T id="nginxions.policy.builtin" />
										</span>
									)}
								</div>
								<div className={styles.sub}>
									{[o.description || objectHint(o), ...summary(kind, o.spec)]
										.filter(Boolean)
										.join(" · ") || "—"}
								</div>
							</div>
							<button type="button" className={hostStyles.tool} onClick={() => open({ object: o })}>
								{o.builtin || !manage ? <IconEye size={16} /> : <IconPencil size={16} />}
								<span className={hostStyles.toolText}>
									<T id={o.builtin || !manage ? "nginxions.policy.view" : "nginxions.policy.edit"} />
								</span>
							</button>
							{manage && (
								<button
									type="button"
									className={hostStyles.tool}
									onClick={() =>
										open({
											initial: {
												name: `${o.name.replace(/^nginxions-/, "")}-copy`,
												description: o.description,
												spec: o.spec,
											},
										})
									}
								>
									<IconCopy size={16} />
									<span className={hostStyles.toolText}>
										<T id="nginxions.policy.duplicate" />
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

export function VersionsTab({ manage, refresh }: { manage: boolean; refresh: () => void }) {
	const { locale } = useLocaleState();
	const { data, refetch } = useQuery<PolicyVersion[], Error>({
		queryKey: ["nginxions-waf-policy-versions"],
		queryFn: getVersions,
	});
	const rollback = (id: number) =>
		showConfirmModal({
			tTitle: "nginxions.waf.expert.rollback",
			tConfirm: "nginxions.waf.expert.rollback",
			children: (
				<p>
					<T id="nginxions.policy.rollback-confirm" data={{ id }} />
				</p>
			),
			onConfirm: async () => {
				try {
					await rollbackVersion(id);
					showSuccess(t("nginxions.policy.saved"));
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
					<T id="nginxions.policy.versions" />
				</h2>
			</div>
			{data.length === 0 ? (
				<p className={styles.empty}>
					<T id="nginxions.policy.versions.none" />
				</p>
			) : (
				<div className="table-responsive">
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>#</th>
								<th>
									<T id="nginxions.waf.expert.saved-on" />
								</th>
								<th>
									<T id="nginxions.waf.expert.user" />
								</th>
								<th>
									<T id="nginxions.waf.expert.comment" />
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
												<T id="nginxions.waf.expert.in-force" />
											</span>
										) : (
											manage && (
												<button
													type="button"
													className="btn btn-sm"
													onClick={() => rollback(v.id)}
												>
													<T id="nginxions.waf.expert.rollback" />
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
		queryClient.invalidateQueries({ queryKey: ["nginxions-waf-policy-versions"] });
		queryClient.invalidateQueries({ queryKey: ["nginxions-waf-policy"] });
	};

	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="nginxions.common.unknown-error" />}</Alert>;

	const tabs: Tab[] = ["default", ...KINDS, "versions"];
	const applied = data.state.applied;

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="nginxions.policy" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="nginxions.policy.subtitle" />
					</p>
				</div>
				<div className={hostStyles.toolbar}>
					<button type="button" className={hostStyles.tool} onClick={showWafPolicyModal}>
						<IconEye size={16} />
						<span className={hostStyles.toolText}>
							<T id="nginxions.waf.policy-show" />
						</span>
					</button>
					<Dropdown
						floating
						inline
						ariaLabel={t("nginxions.policy.export")}
						triggerClassName={hostStyles.tool}
						trigger={
							<>
								<IconDownload size={16} />
								<span className={hostStyles.toolText}>
									<T id="nginxions.policy.export" />
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
								<T id="nginxions.policy.import" />
							</span>
						</button>
					)}
				</div>
			</div>

			<section className={cn("card", styles.card)}>
				<FormatNote format={data.state.format} warnings={data.state.warnings} />
				<AppliedCheckNote check={data.state.check} />
				<p className="text-secondary small mb-0">
					<T id="nginxions.policy.hosts" data={{ count: data.state.hosts }} />
					{applied && !applied.ok && (
						<span className="text-warning ms-2">
							<T id="nginxions.waf.policy-not-sent" /> ({applied.error})
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
										? `nginxions.policy.tab.${x}`
										: `nginxions.policy.kinds.${x}`
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
