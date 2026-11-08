import assert from "node:assert/strict";
import { test } from "node:test";
import { repairNamespaces } from "./watchdog.js";

const run = async (nginxions, inspect) => {
	const restarted = [];
	const list = async () => [
		{ id: "oa1", service: "openappsec", state: "running", networkMode: "nginxions_edge" },
		{ id: "npm1", service: "nginxions", networkMode: "container:oa1", ...nginxions },
	];
	const result = await repairNamespaces(
		list,
		async (id) => inspect[id],
		async (id) => restarted.push(id),
	);
	return { result, restarted };
};

test("nginxions that could not join the namespace of openappsec (exit 128) is restarted", async () => {
	const { result } = await run({ state: "exited" }, { npm1: { State: { ExitCode: 128 } }, oa1: { State: {} } });
	assert.deepEqual(result, ["nginxions"]);
});

test("nginxions started before openappsec (old namespace) is restarted, a later one is not", async () => {
	const oa1 = { State: { StartedAt: "2026-11-04T10:00:00Z" } };
	const stale = await run({ state: "running" }, { npm1: { State: { StartedAt: "2026-11-04T09:00:00Z" } }, oa1 });
	assert.deepEqual(stale.restarted, ["npm1"]);
	const fresh = await run({ state: "running" }, { npm1: { State: { StartedAt: "2026-11-04T10:00:05Z" } }, oa1 });
	assert.deepEqual(fresh.restarted, []);
});

test("nginxions someone stopped stays stopped", async () => {
	const { restarted } = await run({ state: "exited" }, { npm1: { State: { ExitCode: 143 } }, oa1: { State: {} } });
	assert.deepEqual(restarted, []);
});
