import assert from "node:assert/strict";
import { test } from "node:test";
import { repairNamespaces } from "./watchdog.js";

const run = async (agent, inspect) => {
	const restarted = [];
	const list = async () => [
		{ id: "npm1", service: "npmos", state: "running", networkMode: "bridge" },
		{ id: "ag1", service: "appsec-agent", networkMode: "container:npm1", ...agent },
	];
	const result = await repairNamespaces(
		list,
		async (id) => inspect[id],
		async (id) => restarted.push(id),
	);
	return { result, restarted };
};

test("an agent that could not join the namespace (exit 128) is restarted", async () => {
	const { result } = await run({ state: "exited" }, { ag1: { State: { ExitCode: 128 } }, npm1: { State: {} } });
	assert.deepEqual(result, ["appsec-agent"]);
});

test("an agent started before npmos (old namespace) is restarted, a later one is not", async () => {
	const npm1 = { State: { StartedAt: "2026-11-04T10:00:00Z" } };
	const stale = await run({ state: "running" }, { ag1: { State: { StartedAt: "2026-11-04T09:00:00Z" } }, npm1 });
	assert.deepEqual(stale.restarted, ["ag1"]);
	const fresh = await run({ state: "running" }, { ag1: { State: { StartedAt: "2026-11-04T10:00:05Z" } }, npm1 });
	assert.deepEqual(fresh.restarted, []);
});

test("an agent someone stopped stays stopped", async () => {
	const { restarted } = await run({ state: "exited" }, { ag1: { State: { ExitCode: 143 } }, npm1: { State: {} } });
	assert.deepEqual(restarted, []);
});
