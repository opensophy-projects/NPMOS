// Administration → Roles: roles with their permissions, who has them, OIDC groups → roles
// (docs/ROADMAP.md, phase 3). The role editor: ../../rbac/RoleModal.tsx.
import { IconCopy, IconDots, IconEye, IconPencil, IconPlus, IconTrash } from "@tabler/icons-react";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { deleteRole, type OidcMapping, type Role, setOidcMapping } from "../../rbac/api";
import { useCan, useOidcMapping, useRbacRefresh, useRoles } from "../../rbac/hooks";
import { roleDescription, roleName } from "../../rbac/labels";
import { showRoleModal } from "../../rbac/RoleModal";
import { Dropdown } from "../../ui/Dropdown";
import styles from "./Roles.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

function OidcCard({ canManage }: { canManage: boolean }) {
	const { data } = useOidcMapping();
	const [form, setForm] = useState<OidcMapping | null>(null);
	const [saving, setSaving] = useState(false);
	useEffect(() => {
		if (data) setForm(data);
	}, [data]);
	if (!form) return null;
	const save = async () => {
		setSaving(true);
		try {
			setForm(await setOidcMapping(form));
			showSuccess(t("npmos.rbac.oidc.saved"));
		} catch (err: any) {
			showError(err.message);
		}
		setSaving(false);
	};
	return (
		<section className={cn("card", styles.oidc)}>
			<h2 className={styles.cardTitle}>
				<T id="npmos.rbac.oidc" />
			</h2>
			<p className={styles.muted}>
				<T id="npmos.rbac.oidc.hint" />
			</p>
			<div className={styles.oidcRow}>
				<label className={styles.field}>
					<span>
						<T id="npmos.rbac.oidc.claim" />
					</span>
					<input
						className="form-control"
						value={form.claim}
						disabled={!canManage}
						maxLength={100}
						onChange={(e) => setForm({ ...form, claim: e.target.value })}
					/>
				</label>
				<label className={cn("form-check form-switch", styles.switch)}>
					<input
						type="checkbox"
						className="form-check-input"
						checked={form.requestScope}
						disabled={!canManage}
						onChange={(e) => setForm({ ...form, requestScope: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="npmos.rbac.oidc.scope" />
					</span>
				</label>
				{canManage && (
					<Button
						actionType="primary"
						isLoading={saving}
						disabled={saving || !form.claim.trim()}
						onClick={save}
					>
						<T id="save" />
					</Button>
				)}
			</div>
		</section>
	);
}

export default function Roles() {
	const can = useCan();
	const { data: roles, isLoading, error } = useRoles({ enabled: can("roles", "view") });
	const refresh = useRbacRefresh();
	const canManage = can("roles", "manage");

	if (isLoading) return <LoadingPage />;
	if (!can("roles", "view")) {
		return (
			<Alert variant="danger">
				<T id="no-permission-error" />
			</Alert>
		);
	}

	const remove = (role: Role) =>
		showConfirmModal({
			tTitle: "npmos.rbac.delete",
			tConfirm: "action.delete",
			danger: true,
			children: (
				<p className="mb-0">
					<T id="npmos.rbac.delete.text" data={{ name: role.name, count: role.users.length }} />
				</p>
			),
			onConfirm: async () => {
				await deleteRole(role.id);
				refresh();
				showSuccess(t("npmos.rbac.deleted", { name: role.name }));
			},
		});

	return (
		<div className={styles.page}>
			<div className={styles.head}>
				<div>
					<h1 className={styles.title}>
						<T id="npmos.rbac.roles" />
					</h1>
					<p className={styles.muted}>
						<T id="npmos.rbac.subtitle" />
					</p>
				</div>
				{canManage && (
					<Button actionType="primary" onClick={() => showRoleModal()}>
						<IconPlus size={16} className="me-1" />
						<T id="npmos.rbac.new" />
					</Button>
				)}
			</div>

			{error && <Alert variant="danger">{error.message}</Alert>}

			<div className={cn("card", styles.tableCard)}>
				<div className={styles.scroller}>
					<table className="table table-vcenter card-table">
						<thead>
							<tr>
								<th>
									<T id="npmos.rbac.name" />
								</th>
								<th>
									<T id="npmos.rbac.scope" />
								</th>
								<th>
									<T id="npmos.rbac.permissions" />
								</th>
								<th>
									<T id="npmos.rbac.users" />
								</th>
								<th>
									<T id="npmos.rbac.oidc-groups" />
								</th>
								<th className={styles.actions} />
							</tr>
						</thead>
						<tbody>
							{(roles ?? []).map((role) => (
								<tr key={role.id}>
									<td>
										<button
											type="button"
											className={styles.name}
											onClick={() => showRoleModal({ role })}
										>
											{roleName(role)}
										</button>
										{role.builtin && (
											<span className={styles.badge}>
												<T id="npmos.rbac.builtin" />
											</span>
										)}
										<div className={styles.desc}>{roleDescription(role)}</div>
									</td>
									<td className={styles.nowrap}>
										<T id={`npmos.rbac.scope.${role.scope}`} />
									</td>
									<td className={styles.nowrap}>
										<T
											id="npmos.rbac.permissions.count"
											data={{ count: role.permissions.length }}
										/>
									</td>
									<td>
										<span title={role.users.map((u) => `${u.name} <${u.email}>`).join("\n")}>
											{role.users.length ? role.users.map((u) => u.name).join(", ") : "—"}
										</span>
									</td>
									<td className={styles.muted}>{role.oidcGroups.join(", ") || "—"}</td>
									<td className={styles.actions}>
										<Dropdown
											floating
											inline
											ariaLabel={t("npmos.hosts.actions")}
											triggerClassName={styles.iconTrigger}
											trigger={<IconDots size={18} />}
											items={[
												{
													key: "open",
													icon:
														role.builtin || !canManage ? (
															<IconEye size={16} />
														) : (
															<IconPencil size={16} />
														),
													label: (
														<T
															id={
																role.builtin || !canManage
																	? "npmos.rbac.open"
																	: "action.edit"
															}
														/>
													),
													onSelect: () => showRoleModal({ role }),
												},
												...(canManage
													? [
															{
																key: "copy",
																icon: <IconCopy size={16} />,
																label: <T id="npmos.rbac.duplicate" />,
																onSelect: () => showRoleModal({ from: role }),
															},
														]
													: []),
												...(canManage && !role.builtin
													? [
															{
																key: "delete",
																divider: true,
																icon: <IconTrash size={16} />,
																label: <T id="action.delete" />,
																onSelect: () => remove(role),
															},
														]
													: []),
											]}
										/>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</div>

			<OidcCard canManage={canManage} />
		</div>
	);
}
