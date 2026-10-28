import { HasPermission } from "src/components";
import { ADMIN, VIEW } from "src/modules/Permissions";
import TableWrapper from "./TableWrapper";

const AuditLog = () => {
	// NPMOS: opened by roles with audit_log:view (phase 3)
	return (
		<HasPermission section={ADMIN} rbac="audit_log" permission={VIEW} pageLoading loadingNoLogo>
			<TableWrapper />
		</HasPermission>
	);
};

export default AuditLog;
