import type { ReactNode } from "react";
import Alert from "react-bootstrap/Alert";
import { Loading, LoadingPage } from "src/components";
import { useUser } from "src/hooks";
import { T } from "src/locale";
import { type ADMIN, hasPermission, type Permission, type Section } from "src/modules/Permissions";
// NginxionS: sections that only the admin flag opened are opened by roles (rbac="users")
import { useCan, useRbacMe } from "src/nginxions/rbac/hooks";

interface Props {
	section?: Section | typeof ADMIN;
	permission: Permission;
	hideError?: boolean;
	children?: ReactNode;
	pageLoading?: boolean;
	loadingNoLogo?: boolean;
	/** NginxionS: an RBAC resource ("users", "waf_policy:apply", or any of several: "certificates|pki"); with `permission` it
	 * decides instead of `section` */
	rbac?: string;
}
function HasPermission({
	section,
	permission,
	children,
	hideError = false,
	pageLoading = false,
	loadingNoLogo = false,
	rbac,
}: Props) {
	const { data, isLoading: userIsLoading } = useUser("me");
	const { isLoading: rbacIsLoading } = useRbacMe();
	const can = useCan();
	const isLoading = userIsLoading || (!!rbac && rbacIsLoading);

	// NginxionS: a page of NginxionS names only its RBAC resource: without a section it is still checked
	if (!section && !rbac) {
		return <>{children}</>;
	}

	if (isLoading) {
		if (hideError) {
			return null;
		}
		if (pageLoading) {
			return <LoadingPage noLogo={loadingNoLogo} />;
		}
		return <Loading noLogo={loadingNoLogo} />;
	}

	// NginxionS: "certificates|pki" — any of the resources
	const allowed = rbac
		? rbac.split("|").some((one) => {
				const [resource, action] = one.split(":");
				return can(resource, action || permission);
			})
		: !!section && hasPermission(section, permission, data?.permissions, data?.roles);
	if (allowed) {
		return <>{children}</>;
	}

	return !hideError ? (
		<Alert variant="danger">
			<T id="no-permission-error" />
		</Alert>
	) : null;
}

export { HasPermission };
