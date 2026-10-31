// open-appsec agent status. The agent runs in the network namespace of the npmos container
// (network_mode: service:npmos), so its local orchestration API is reachable on 127.0.0.1.
const ORCHESTRATION_URL = process.env.NPMOS_APPSEC_ORCHESTRATION_URL || "http://127.0.0.1:7777";
const TIMEOUT_MS = 3000;

const none = (value) => (value === undefined || value === "" || value === "None" ? null : value);

/**
 * An agent without the patch 0003 (deploy/openappsec/agent/patches) applies a new policy and then fails to
 * reconnect to the Fog (there is none in local-only mode): it reports the applied policy as failed with this
 * message and keeps no version. The policy is in force, so the status says so.
 */
const FOG_RECONNECT = /Failed to load Orchestration new policy file/;
const updateStatus = (value) => {
	const status = none(value);
	return status && FOG_RECONNECT.test(status) ? "Succeeded" : status;
};

/**
 * @returns {Promise<{reachable: boolean, error?: string, policyVersion?: string|null,
 *   lastPolicyUpdate?: string|null, lastUpdateStatus?: string|null, mode?: string}>}
 */
const getAgentStatus = async () => {
	let raw;
	try {
		const response = await fetch(`${ORCHESTRATION_URL}/show-orchestration-status`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: "{}",
			signal: AbortSignal.timeout(TIMEOUT_MS),
		});
		raw = await response.json();
	} catch (err) {
		return { reachable: false, error: err.cause?.code || err.message };
	}
	return {
		reachable: true,
		policyVersion: none(raw["Policy version"]),
		lastPolicyUpdate: none(raw["Last policy update"]),
		lastUpdate: none(raw["Last update"]),
		lastUpdateStatus: updateStatus(raw["Last update status"]),
		// with NPMOS_LOCAL_ONLY the agent never registers at the Fog; "Registration status" is meaningless
		mode: "local",
	};
};

export { getAgentStatus };
