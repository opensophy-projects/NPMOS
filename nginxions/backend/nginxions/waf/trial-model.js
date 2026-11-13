// Trial mode of a host (waf/trial.js): what does not need the database, for the tests.

export const TRIAL_MODE = "prevent-learn";
export const MAX_HOURS = 7 * 24;

/** the state of a trial at a time: running before its end, finished after it, closed once decided */
export const trialState = (row, now = new Date()) =>
	row.outcome ? "closed" : new Date(row.ends_on) > now ? "running" : "finished";
