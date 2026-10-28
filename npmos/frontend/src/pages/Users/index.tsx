import { HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";
import TableWrapper from "./TableWrapper";

const Users = () => {
	// NPMOS: opened by roles with users:view (phase 3)
	return (
		<HasPermission section={ADMIN} rbac="users" permission={VIEW} pageLoading loadingNoLogo>
			<TableWrapper />
		</HasPermission>
	);
};

export default Users;
