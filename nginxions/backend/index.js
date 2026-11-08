#!/usr/bin/env node

import app from "./app.js";
import internalNginx from "./internal/nginx.js";
import internalCertificate from "./internal/certificate.js";
import internalIpRanges from "./internal/ip_ranges.js";
import { global as logger } from "./logger.js";
import { migrateUp } from "./migrate.js";
// NginxionS: ACME servers, open-appsec policy and agent settings from the database, security events of the agent, CRLs of
// the PKI
import { bootstrap as bootstrapAcmeServers } from "./nginxions/acme/servers.js";
import { bootstrap as bootstrapBlockPage } from "./nginxions/block-page.js";
import { bootstrap as bootstrapCrowdsec } from "./nginxions/crowdsec/index.js";
import { bootstrap as bootstrapGeo } from "./nginxions/geo/index.js";
import { start as startEventIngest } from "./nginxions/events/ingest.js";
import { start as startLearning } from "./nginxions/learning/index.js";
import { start as startNotifications } from "./nginxions/notifications/index.js";
import { bootstrap as bootstrapPki } from "./nginxions/pki/index.js";
import { bootstrap as bootstrapWafAgent } from "./nginxions/waf/agent-settings.js";
import { bootstrap as bootstrapWafPolicy } from "./nginxions/waf/policy.js";
import { getCompiledSchema } from "./schema/index.js";
import setup from "./setup.js";

// NginxionS: a promise nobody awaited (a route of NPMplus answered before its work, see routes/nginx/dead_hosts.js) must
// not stop the backend for every user: Node ends the process on an unhandled rejection by default
process.on("unhandledRejection", (err) => {
	logger.error(`Unhandled rejection: ${err?.message || err}`);
});

async function appStart() {
	return (
		migrateUp()
			.then(setup)
			// NginxionS: never fails the start (errors are logged and shown in the GUI)
			.then(bootstrapAcmeServers)
			.then(bootstrapWafPolicy)
			.then(bootstrapWafAgent)
			.then(bootstrapPki)
			.then(bootstrapBlockPage)
			.then(bootstrapCrowdsec)
			.then(bootstrapGeo)
			.then(startEventIngest)
			.then(startLearning)
			.then(startNotifications)
			.then(getCompiledSchema)
			.then(() => {
				if (process.env.TRUST_CLOUDFLARE === "false") {
					logger.info("Cloudflares IPs are NOT trusted");
					return;
				}
				logger.info("Cloudflares IPs are trusted");
				internalIpRanges.initTimer();
				return internalIpRanges.fetch();
			})
			.then(() => {
				internalCertificate.initTimer();
				internalNginx.reload();

				const server = app.listen("/run/npmplus.sock", () => {
					logger.info(`Backend PID ${process.pid} listening on unix socket...`);

					process.on("SIGTERM", () => {
						logger.info(`PID ${process.pid} received SIGTERM`);
						server.close(() => {
							logger.info("Stopping.");
							process.exit(0);
						});
					});
				});
				// NginxionS: nginx keeps idle connections to the backend up to 60 s; Node closed them after 5 s,
				// and a request nginx sent on a connection just being closed failed with 502 (Broken pipe)
				server.keepAliveTimeout = 65000;
				server.headersTimeout = 66000;
			})
			.catch((err) => {
				logger.error(`Startup Error: ${err.message}`, err);
				setTimeout(appStart, 1000);
			})
	);
}

try {
	appStart();
} catch (err) {
	logger.fatal(err);
	process.exit(1);
}
