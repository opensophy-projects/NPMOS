// RBAC API (/api/npmos/rbac/*, npmos/backend/npmos/rbac): roles, their permissions, who has them.
import * as api from "src/api/backend/base";

export type Scope = "all" | "own";
export type BuiltinRole = "administrator" | "operator" | "security_analyst" | "viewer";

export interface RbacModel {
	resources: { id: string; actions: string[] }[];
	scopes: Scope[];
	builtin: { key: BuiltinRole; name: string; scope: Scope; permissions: string[] }[];
}

export interface RbacMe {
	admin: boolean;
	scope: Scope;
	/** "resource:action" */
	permissions: string[];
	roles: RoleRef[];
}

export interface Role {
	id: number;
	name: string;
	description: string;
	builtin: BuiltinRole | null;
	scope: Scope;
	oidcGroups: string[];
	permissions: string[];
	users: { id: number; name: string; email: string }[];
	createdOn: string;
	modifiedOn: string;
}

export type RoleInput = Pick<Role, "name" | "description" | "scope" | "oidcGroups" | "permissions">;

export interface OidcMapping {
	claim: string;
	requestScope: boolean;
}

export const getRbacModel = (): Promise<RbacModel> => api.get({ url: "/npmos/rbac/model" });
export const getRbacMe = (): Promise<RbacMe> => api.get({ url: "/npmos/rbac/me" });
export const getRoles = (): Promise<Role[]> => api.get({ url: "/npmos/rbac/roles" });
export const createRole = (data: RoleInput): Promise<Role> => api.post({ url: "/npmos/rbac/roles", data });
export const updateRole = (id: number, data: RoleInput): Promise<Role> =>
	api.put({ url: `/npmos/rbac/roles/${id}`, data });
export const deleteRole = (id: number) => api.del({ url: `/npmos/rbac/roles/${id}` });
export type RoleRef = { id: number; name: string; builtin: BuiltinRole | null };
/** {user id: roles}; the Administrator role for admins */
export const getRoleAssignments = (): Promise<Record<string, RoleRef[]>> => api.get({ url: "/npmos/rbac/users" });
export const setUserRoles = (userId: number, roles: number[]): Promise<number[]> =>
	api.put({ url: `/npmos/rbac/users/${userId}`, data: { roles } });
export const getOidcMapping = (): Promise<OidcMapping> => api.get({ url: "/npmos/rbac/oidc" });
export const setOidcMapping = (data: OidcMapping): Promise<OidcMapping> => api.put({ url: "/npmos/rbac/oidc", data });
