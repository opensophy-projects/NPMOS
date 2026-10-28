// Roles of a user in the users table (instead of the upstream admin / standard user badge).
import { T } from "src/locale";
import { useRoleAssignments } from "./hooks";
import { roleName } from "./labels";

export function UserRoleBadges({ userId }: { userId: number }) {
	const { data } = useRoleAssignments();
	const roles = data?.[userId];
	if (!roles) return null;
	if (!roles.length) {
		return (
			<span className="badge bg-secondary-lt">
				<T id="npmos.rbac.no-roles" />
			</span>
		);
	}
	return (
		<>
			{roles.map((role) => (
				<span key={role.id} className="badge bg-primary-lt me-1">
					{roleName(role)}
				</span>
			))}
		</>
	);
}
