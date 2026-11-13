import assert from "node:assert/strict";
import { test } from "node:test";
import { render } from "../notifications/rules.js";
import { MAX_HOURS, TRIAL_MODE, trialState } from "./trial.js";

test("a trial runs until its end, then waits for a decision, closed once decided", () => {
	const now = new Date("2026-11-13T12:00:00Z");
	const row = (endsOn, outcome = "") => ({ ends_on: endsOn, outcome });
	assert.equal(trialState(row("2026-11-13T13:00:00Z"), now), "running");
	assert.equal(trialState(row("2026-11-13T12:00:00Z"), now), "finished");
	assert.equal(trialState(row("2026-11-13T11:00:00Z", "enabled"), now), "closed");
	assert.equal(trialState(row("2026-11-13T13:00:00Z", "cancelled"), now), "closed");
	assert.equal(TRIAL_MODE, "prevent-learn");
	assert.equal(MAX_HOURS, 168);
});

test("the end of a trial is told with its report", () => {
	const values = { name: "app.example.com", hours: 24, events: 40, toBlock: 12, toPass: 0 };
	assert.match(render("waf_trial", "firing", values, "ru").text, /блокировка дополнительно заблокировала бы 12/);
	assert.match(render("waf_trial", "firing", values, "en").title, /^Trial of blocking on app\.example\.com/);
});
