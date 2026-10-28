// Roles of a user (Users → Permissions). Several roles add up; Administrator is everything.
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { Button, Loading } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { setUserRoles } from "./api";
import { useRbacMe, useRbacRefresh, useRoleAssignments, useRoles } from "./hooks";
import { roleDescription, roleName } from "./labels";
import styles from "./UserRolesModal.module.css";

interface Props extends InnerModalProps {
	userId: number;
	name: string;
}

const UserRolesModal = EasyModal.create(({ userId, name, visible, remove }: Props) => {
	const { data: roles } = useRoles();
	const { data: assignments } = useRoleAssignments();
	const { data: me } = useRbacMe();
	const refresh = useRbacRefresh();
	const [chosen, setChosen] = useState<Set<number> | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const current = new Set((assignments?.[userId] ?? []).map((r) => r.id));
	const selected = chosen ?? current;
	const mine = (permissions: string[]) => !!me && (me.admin || permissions.every((p) => me.permissions.includes(p)));

	const save = async () => {
		setSaving(true);
		setError(null);
		try {
			await setUserRoles(userId, [...selected]);
			refresh();
			showSuccess(intl.formatMessage({ id: "npmos.rbac.user-saved" }, { name }));
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setSaving(false);
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.rbac.user-roles" />
					<div className={styles.subject}>{name}</div>
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				{!roles || !assignments ? (
					<Loading noLogo />
				) : (
					<div className={styles.list}>
						{roles.map((role) => {
							const allowed = role.builtin === "administrator" ? !!me?.admin : mine(role.permissions);
							return (
								<label key={role.id} className={cn(styles.item, !allowed && styles.locked)}>
									<input
										type="checkbox"
										className="form-check-input m-0"
										checked={selected.has(role.id)}
										disabled={!allowed}
										onChange={(e) => {
											const next = new Set(selected);
											if (e.target.checked) next.add(role.id);
											else next.delete(role.id);
											setChosen(next);
										}}
									/>
									<span className={styles.text}>
										<span className={styles.name}>{roleName(role)}</span>
										<span className={styles.desc}>
											{roleDescription(role) || (
												<T
													id="npmos.rbac.permissions.count"
													data={{ count: role.permissions.length }}
												/>
											)}
										</span>
									</span>
								</label>
							);
						})}
					</div>
				)}
				<p className={styles.note}>
					<T id="npmos.rbac.user-roles.note" />
				</p>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={saving}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" className="ms-auto" isLoading={saving} disabled={saving} onClick={save}>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showUserRolesModal = (userId: number, name: string) =>
	EasyModal.show(UserRolesModal, { userId, name } as Omit<Props, "visible" | "remove">);
