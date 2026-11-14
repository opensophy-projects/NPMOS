import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMetrics } from "./metrics.js";

test("metrics of the agent: the Prometheus text format with help, type and labels", () => {
	const text = `# HELP nano_service_restarts_counter Restarts of the nano services
# TYPE nano_service_restarts_counter counter
nano_service_restarts_counter{serviceName="HTTP Transaction Handler",id="1"} 2
nano_service_restarts_counter{serviceName="Orchestration"} 0

# TYPE waap_requests gauge
waap_requests{asset="a \\"b\\""} 12.5
waap_requests NaN
garbage line
`;
	assert.deepEqual(parseMetrics(text), [
		{
			name: "nano_service_restarts_counter",
			help: "Restarts of the nano services",
			type: "counter",
			samples: [
				{
					labels: [
						["serviceName", "HTTP Transaction Handler"],
						["id", "1"],
					],
					value: 2,
				},
				{ labels: [["serviceName", "Orchestration"]], value: 0 },
			],
		},
		{ name: "waap_requests", help: "", type: "gauge", samples: [{ labels: [["asset", 'a "b"']], value: 12.5 }] },
	]);
	assert.deepEqual(parseMetrics(""), []);
});
