import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";
import { getOidcMapping, getRbacMe, getRbacModel, getRoleAssignments, getRoles } from "./api";

export const useRbacModel = () =>
	useQuery({ queryKey: ["npmos-rbac-model"], queryFn: getRbacModel, staleTime: Number.POSITIVE_INFINITY });

export const useRbacMe = () => useQuery({ queryKey: ["npmos-rbac-me"], queryFn: getRbacMe, staleTime: 30000 });

export const useRoles = (options = {}) => useQuery({ queryKey: ["npmos-roles"], queryFn: getRoles, ...options });

export const useRoleAssignments = (options = {}) =>
	useQuery({ queryKey: ["npmos-role-assignments"], queryFn: getRoleAssignments, ...options });

export const useOidcMapping = (options = {}) =>
	useQuery({ queryKey: ["npmos-rbac-oidc"], queryFn: getOidcMapping, ...options });

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
		for (const key of ["npmos-roles", "npmos-role-assignments", "npmos-rbac-me", "users", "user"]) {
			queryClient.invalidateQueries({ queryKey: [key] });
		}
	}, [queryClient]);
}
