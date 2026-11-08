// NginxionS: nginxions-control repairs containers that share the network namespace of another (server.js runs it).
/**
 * Watchdog of shared network namespaces: nginxions lives in the namespaces of openappsec. After a restart of openappsec
 * outside this service (an update, docker restart, a crash), nginxions either fails to start ("cannot join network
 * namespace", exit 128) or keeps the dead namespace of the old openappsec and loses the network.
 * Both are repaired here by a restart; a container someone stopped (another exit code) is left alone.
 * @param {() => Promise<Array<{id, service, state, networkMode}>>} list  the managed containers
 * @param {(id: string) => Promise<object>} inspectId  docker inspect
 * @param {(id: string) => Promise<unknown>} restartId
 * @returns {Promise<string[]>} the services restarted
 */
export const repairNamespaces = async (list, inspectId, restartId) => {
	const all = await list();
	const repaired = [];
	for (const c of all) {
		const ownerId = /^container:(.+)$/.exec(c.networkMode || "")?.[1];
		if (!ownerId) continue;
		const owner = all.find((o) => o.id === ownerId || o.id.startsWith(ownerId));
		if (owner?.state !== "running") continue;
		const [dep, own] = await Promise.all([inspectId(c.id), inspectId(owner.id)]);
		const stale =
			c.state === "running"
				? Date.parse(dep.State?.StartedAt) < Date.parse(own.State?.StartedAt)
				: dep.State?.ExitCode === 128 || /namespace/i.test(dep.State?.Error || "");
		if (!stale) continue;
		await restartId(c.id);
		repaired.push(c.service);
	}
	return repaired;
};
