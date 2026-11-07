// Filters that only the requests of the log have in Events → All. No database here: tested without one.

const list = (value) =>
	String(value ?? "")
		.split(",")
		.map((v) => v.trim())
		.filter(Boolean)
		.slice(0, 50);

/** the class of the answer (4xx or 404), refused or passed, who sent it (client.js) */
export const requestFilters = (query = {}) => ({
	status: list(query.status).filter((s) => /^[1-5](\d\d|xx)$/i.test(s)),
	outcome: ["refused", "passed"].includes(query.outcome) ? query.outcome : "",
	client: list(query.client).filter((c) => ["human", "bot", "scanner"].includes(c)),
});

/** filters only requests have: with one of them, Events → All shows no events */
export const requestOnly = (f) => f.status.length > 0 || !!f.outcome || f.client.length > 0;
