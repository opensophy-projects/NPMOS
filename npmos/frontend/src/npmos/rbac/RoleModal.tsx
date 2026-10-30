// Create or edit a role (Administration → Roles): name, description, template and scope at the
// top, below a card per resource with a switch per action. Built-in roles are read-only except
// their OIDC groups; "Duplicate" starts a new role from them.
import { IconCopy } from "@tabler/icons-react";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useMemo, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { Button, Loading } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { createRole, type Role, type RoleInput, type Scope, updateRole } from "./api";
import { useCan, useRbacMe, useRbacModel, useRbacRefresh, useRoles } from "./hooks";
import { actionHint, actionLabel, resourceHint, resourceLabel, roleName } from "./labels";
import styles from "./RoleModal.module.css";
import { HostPicker } from "./HostPicker";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props extends InnerModalProps {
	/** the role to edit; without it a new role */
	role?: Role;
	/** a new role filled from this one */
	from?: Role;
}

const EMPTY: RoleInput = { name: "", description: "", scope: "all", oidcGroups: [], permissions: [], hosts: [] };

const RoleModal = EasyModal.create(({ role, from, visible, remove }: Props) => {
	const { data: model } = useRbacModel();
	const { data: roles } = useRoles();
	const { data: me } = useRbacMe();
	const can = useCan();
	const refresh = useRbacRefresh();
	const readOnly = !!role?.builtin || !can("roles", "manage");
	const [form, setForm] = useState<RoleInput>(() => {
		const source = role ?? from;
		if (!source) return EMPTY;
		return {
			name: role ? source.name : t("npmos.rbac.copy-of", { name: roleName(source) }),
			description: source.builtin && !role ? "" : source.description,
			scope: source.scope,
			oidcGroups: role ? source.oidcGroups : [],
			permissions: source.permissions,
			hosts: source.hosts ?? [],
		};
	});
	const [groupsText, setGroupsText] = useState(form.oidcGroups.join(", "));
	const [error, setError] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);

	const resources = useMemo(() => (model?.resources ?? []).map((r) => [r.id, r.actions] as const), [model]);
	const total = resources.reduce((n, [, actions]) => n + actions.length, 0);
	const chosen = new Set(form.permissions);
	/** a role cannot give what its editor lacks (the backend refuses it too) */
	const mine = (permission: string) => !!me && (me.admin || me.permissions.includes(permission));

	const set = (permissions: Iterable<string>) => setForm({ ...form, permissions: [...new Set(permissions)] });
	const toggle = (resource: string, action: string, on: boolean) => {
		const next = new Set(chosen);
		const actions = model?.resources.find((r) => r.id === resource)?.actions ?? [];
		if (on) {
			next.add(`${resource}:${action}`);
			// any action needs to see the resource
			next.add(`${resource}:view`);
		} else if (action === "view") {
			for (const a of actions) next.delete(`${resource}:${a}`);
		} else {
			next.delete(`${resource}:${action}`);
		}
		set(next);
	};
	const all = (filter: (action: string) => boolean) =>
		set(
			resources
				.flatMap(([resource, actions]) => actions.filter(filter).map((a) => `${resource}:${a}`))
				.filter(mine),
		);

	const applyTemplate = (value: string) => {
		if (!value) return setForm({ ...form, permissions: [], scope: "all" });
		const [kind, id] = value.split(":");
		const source =
			kind === "builtin" ? model?.builtin.find((b) => b.key === id) : roles?.find((r) => String(r.id) === id);
		if (source) setForm({ ...form, scope: source.scope, permissions: source.permissions.filter(mine) });
	};

	const save = async () => {
		setSaving(true);
		setError(null);
		const data = { ...form, oidcGroups: groupsText.split(/[,\s]+/).filter(Boolean) };
		try {
			// a built-in role changes only its OIDC groups
			if (role) await updateRole(role.id, role.builtin ? { ...role, oidcGroups: data.oidcGroups } : data);
			else await createRole(data);
			refresh();
			showSuccess(t(role ? "npmos.rbac.saved" : "npmos.rbac.created", { name: data.name }));
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setSaving(false);
	};

	const title = role ? roleName(role) : t("npmos.rbac.new");

	return (
		<Modal show={visible} onHide={remove} size="xl" scrollable>
			<Modal.Header closeButton>
				<Modal.Title>
					{title}
					{role?.builtin && (
						<span className={styles.builtin}>
							<T id="npmos.rbac.builtin" />
						</span>
					)}
				</Modal.Title>
			</Modal.Header>
			<Modal.Body className={styles.body}>
				{!model ? (
					<Loading noLogo />
				) : (
					<>
						{error && (
							<Alert variant="danger" onClose={() => setError(null)} dismissible>
								{error}
							</Alert>
						)}
						{role?.builtin && (
							<p className={styles.note}>
								<T id="npmos.rbac.builtin.note" />
							</p>
						)}
						<section className={cn("card", styles.info)}>
							<div className={styles.infoGrid}>
								{!role && (
									<label className={styles.field}>
										<span>
											<T id="npmos.rbac.template" />
										</span>
										<select
											className="form-select"
											defaultValue=""
											onChange={(e) => applyTemplate(e.target.value)}
										>
											<option value="">{t("npmos.rbac.template.empty")}</option>
											<optgroup label={t("npmos.rbac.builtin.many")}>
												{model.builtin.map(({ key }) => (
													<option key={key} value={`builtin:${key}`}>
														{t(`npmos.rbac.builtin.${key}`)}
													</option>
												))}
											</optgroup>
											{roles?.some((r) => !r.builtin) && (
												<optgroup label={t("npmos.rbac.custom.many")}>
													{roles
														.filter((r) => !r.builtin)
														.map((r) => (
															<option key={r.id} value={`role:${r.id}`}>
																{r.name}
															</option>
														))}
												</optgroup>
											)}
										</select>
									</label>
								)}
								<label className={styles.field}>
									<span>
										<T id="npmos.rbac.name" />
									</span>
									<input
										className="form-control"
										value={role?.builtin ? title : form.name}
										disabled={readOnly}
										maxLength={100}
										required
										onChange={(e) => setForm({ ...form, name: e.target.value })}
									/>
								</label>
								<label className={cn(styles.field, styles.wide)}>
									<span>
										<T id="npmos.rbac.description" />
									</span>
									<textarea
										className="form-control"
										rows={2}
										maxLength={500}
										value={
											role?.builtin
												? t(`npmos.rbac.builtin.${role.builtin}.desc`)
												: form.description
										}
										disabled={readOnly}
										onChange={(e) => setForm({ ...form, description: e.target.value })}
									/>
								</label>
								<div className={styles.field}>
									<span>
										<T id="npmos.rbac.scope" />
									</span>
									<div className={styles.segment} role="radiogroup">
										{(["all", "own", "hosts"] as Scope[]).map((scope) => (
											<label
												key={scope}
												className={cn(
													styles.segmentItem,
													form.scope === scope && styles.segmentOn,
												)}
											>
												<input
													type="radio"
													name="scope"
													checked={form.scope === scope}
													disabled={readOnly || (scope !== "own" && me?.scope !== "all")}
													onChange={() => setForm({ ...form, scope })}
												/>
												<T id={`npmos.rbac.scope.${scope}`} />
											</label>
										))}
									</div>
									<small className={styles.hint}>
										<T id={`npmos.rbac.scope.${form.scope}.hint`} />
									</small>
								</div>
								{form.scope === "hosts" && (
									<HostPicker
										value={form.hosts}
										disabled={readOnly}
										onChange={(hosts) => setForm({ ...form, hosts })}
									/>
								)}
								<label className={styles.field}>
									<span>
										<T id="npmos.rbac.oidc-groups" />
									</span>
									<input
										className="form-control"
										value={groupsText}
										disabled={
											!can("roles", "manage") || (role?.builtin === "administrator" && !me?.admin)
										}
										placeholder={t("npmos.rbac.oidc-groups.placeholder")}
										onChange={(e) => setGroupsText(e.target.value)}
									/>
									<small className={styles.hint}>
										<T id="npmos.rbac.oidc-groups.hint" />
									</small>
								</label>
							</div>
						</section>

						<div className={styles.permHead}>
							<h3 className={styles.permTitle}>
								<T id="npmos.rbac.permissions" />
								<span className={styles.counter}>
									<T id="npmos.rbac.chosen" data={{ count: chosen.size, total }} />
								</span>
							</h3>
							{!readOnly && (
								<div className={styles.permActions}>
									<button type="button" className="btn btn-sm" onClick={() => all(() => true)}>
										<T id="npmos.rbac.all" />
									</button>
									<button
										type="button"
										className="btn btn-sm"
										onClick={() => all((a) => a === "view")}
									>
										<T id="npmos.rbac.view-only" />
									</button>
									<button type="button" className="btn btn-sm" onClick={() => set([])}>
										<T id="npmos.rbac.none" />
									</button>
								</div>
							)}
						</div>

						<div className={styles.grid}>
							{resources.map(([resource, actions]) => (
								<section key={resource} className={styles.resource}>
									<div className={styles.resourceHead}>
										<div className={styles.resourceTitle}>{resourceLabel(resource)}</div>
										<div className={styles.resourceHint}>{resourceHint(resource)}</div>
									</div>
									{actions.map((action) => {
										const permission = `${resource}:${action}`;
										const allowed = mine(permission);
										return (
											<label
												key={action}
												className={cn(styles.action, !allowed && styles.actionLocked)}
												title={
													allowed || readOnly
														? actionHint(resource, action)
														: t("npmos.rbac.not-yours")
												}
											>
												<span className="form-check form-switch m-0">
													<input
														type="checkbox"
														className="form-check-input"
														checked={chosen.has(permission)}
														disabled={readOnly || !allowed}
														onChange={(e) => toggle(resource, action, e.target.checked)}
													/>
												</span>
												<span>{actionLabel(action)}</span>
											</label>
										);
									})}
								</section>
							))}
						</div>
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={saving}>
					<T id={readOnly && !role?.builtin ? "action.close" : "cancel"} />
				</Button>
				{role?.builtin && can("roles", "manage") && (
					<Button
						className="ms-auto"
						onClick={() => {
							remove();
							showRoleModal({ from: role });
						}}
					>
						<IconCopy size={16} className="me-1" />
						<T id="npmos.rbac.duplicate" />
					</Button>
				)}
				{(!readOnly || (role?.builtin && can("roles", "manage"))) && (
					<Button
						actionType="primary"
						className={role?.builtin ? "" : "ms-auto"}
						isLoading={saving}
						disabled={saving || (!role?.builtin && !form.name.trim())}
						onClick={save}
					>
						<T id={role ? "save" : "npmos.rbac.create"} />
					</Button>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showRoleModal = (props: { role?: Role; from?: Role } = {}) =>
	EasyModal.show(RoleModal, props as Omit<Props, "visible" | "remove">);
