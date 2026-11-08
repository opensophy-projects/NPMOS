import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";
import { getOidcMapping, getRbacMe, getRbacModel, getRoleAssignments, getRoles } from "./api";

export const useRbacModel = () =>
	useQuery({ queryKey: ["nginxions-rbac-model"], queryFn: getRbacModel, staleTime: Number.POSITIVE_INFINITY });

export const useRbacMe = () => useQuery({ queryKey: ["nginxions-rbac-me"], queryFn: getRbacMe, staleTime: 30000 });

export const useRoles = (options = {}) => useQuery({ queryKey: ["nginxions-roles"], queryFn: getRoles, ...options });

export const useRoleAssignments = (options = {}) =>
	useQuery({ queryKey: ["nginxions-role-assignments"], queryFn: getRoleAssignments, ...options });

export const useOidcMapping = (options = {}) =>
	useQuery({ queryKey: ["nginxions-rbac-oidc"], queryFn: getOidcMapping, ...options });

/**
 * can("waf_policy", "manage"): may the current user do it. false while the permissions load.
 * The backend checks the same on every request; this only hides what would be refused.
 */
export function useCan() {
	const { data } = useRbacMe();
	return useCallback(
		(resource: string, action = "view") =>
			!!data && (data.admin || data.permissions.includes(`${resource}:${action}`)),
		[data],
	);
}

/** after roles or assignments change: the lists and the current user's permissions */
export function useRbacRefresh() {
	const queryClient = useQueryClient();
	return useCallback(() => {
		for (const key of ["nginxions-roles", "nginxions-role-assignments", "nginxions-rbac-me", "users", "user"]) {
			queryClient.invalidateQueries({ queryKey: [key] });
		}
	}, [queryClient]);
}
