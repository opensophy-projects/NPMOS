// Which hosts a user sees: all, or their own plus the hosts given to their roles (role scope
// "hosts", table npmos_role_host). Used by the upstream host modules instead of their owner filter.

export const HOST_TABLES = ["proxy_host", "redirection_host", "dead_host", "stream"];

/**
 * Limits a host query to what the user may see.
 * @param {object} query  knex/objection query on `table`
 * @param {{permission_visibility: string, npmos_hosts?: Record<string, number[]>}} accessData
 * @param {string} table  proxy_host | redirection_host | dead_host | stream
 * @param {number} userId
 */
export const scopeHosts = (query, accessData, table, userId) => {
	if (accessData?.permission_visibility === "all") return query;
	const ids = accessData?.npmos_hosts?.[table] ?? [];
	return query.andWhere((q) => {
		q.where(`${table}.owner_user_id`, userId);
		if (ids.length) q.orWhereIn(`${table}.id`, ids);
	});
};
