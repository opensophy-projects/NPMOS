// Applies the settings of CrowdSec: generated files in the config volume, hub items they need, then
// a reload (SIGHUP: CrowdSec rereads acquisition, parsers, scenarios and profiles in seconds, the
// LAPI and the bouncers keep working) or, for config.yaml.local or when the reload fails, a restart
// of the crowdsec container through npmos-control. If CrowdSec does not come up healthy, the
// previous files are restored and it is restarted again (ADR-0010).
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { global as logger } from "../../logger.js";
import control from "../control/client.js";
import {
	renderAcquis,
	renderAllowlist,
	renderConfigLocal,
	renderProfiles,
	renderScenario,
	renderSimulation,
	requiredItems,
	fatalMessages,
	unwantedItems,
} from "./config.js";
import { CONF_DIR, install, remove } from "./hub.js";
import { health, registrationToken } from "./lapi.js";

export const SERVICE = "crowdsec";
const HEALTH_TIMEOUT_MS = Number(process.env.NPMOS_CROWDSEC_HEALTH_TIMEOUT_MS || 60000);
// CrowdSec answers /health before its agent has loaded every parser; a broken file stops it later
const SETTLE_MS = Number(process.env.NPMOS_CROWDSEC_SETTLE_MS || 4000);

// files whose change a reload picks up; config.yaml.local (LAPI, AppSec listener...) needs a restart
const RELOADED = ["acquis", "profiles", "allowlist", "scenario", "simulation"];

/** files NPMOS owns in the config volume */
export const FILES = {
	acquis: "acquis.d/npmos.yaml",
	profiles: "profiles.yaml",
	allowlist: "parsers/s02-enrich/npmos-allowlist.yaml",
	scenario: "scenarios/npmos-openappsec-prevent.yaml",
	simulation: "npmos-simulation.yaml",
	config: "config.yaml.local",
};

const read = async (rel) => {
	try {
		return await readFile(path.join(CONF_DIR, rel), "utf8");
	} catch {
		return null;
	}
};

const put = async (rel, content) => {
	const file = path.join(CONF_DIR, rel);
	if (content === null) {
		await rm(file, { force: true });
		return;
	}
	await mkdir(path.dirname(file), { recursive: true });
	await writeFile(`${file}.tmp`, content, { mode: rel === FILES.config ? 0o600 : 0o644 });
	await rename(`${file}.tmp`, file);
};

/** contents of the files for these settings */
export const render = async (settings) => ({
	acquis: renderAcquis(settings),
	profiles: renderProfiles(settings),
	allowlist: renderAllowlist(settings),
	scenario: renderScenario(settings),
	simulation: renderSimulation(settings),
	config: renderConfigLocal(settings, { registrationToken: await registrationToken() }),
});

/** files that differ from what is on disk: {key: {old, new}} */
export const pending = async (settings) => {
	const wanted = await render(settings);
	const diff = {};
	for (const [key, content] of Object.entries(wanted)) {
		const old = await read(FILES[key]);
		if (old !== content) diff[key] = { old, new: content };
	}
	return diff;
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Waits for the LAPI after a restart; false if it does not answer in time or the container
 * restarts again (CrowdSec exits on a broken file and Docker starts it over)
 */
const restarts = async () => (await control.getService(SERVICE).catch(() => ({}))).restartCount ?? null;

export const waitHealthy = async (timeout = HEALTH_TIMEOUT_MS, since = null) => {
	const until = Date.now() + timeout;
	// since: the restart count before a reload (CrowdSec may exit on a broken file right away)
	const base = since ?? (await restarts());
	while (Date.now() < until) {
		try {
			await health();
			await sleep(SETTLE_MS);
			await health();
			const now = await restarts();
			if (base === null || now === null || now === base) return true;
			return false;
		} catch {
			const now = await restarts();
			if (base !== null && now !== null && now > base) return false;
			await sleep(1000);
		}
	}
	return false;
};

const lastLogs = async () => {
	try {
		const lines = await control.getLogs(SERVICE, { tail: 60 });
		return fatalMessages(Array.isArray(lines) ? lines : []);
	} catch {
		return [];
	}
};

/**
 * SIGHUP and a check that CrowdSec took it: it did not exit and logged nothing fatal.
 * false: the caller restarts instead (and rolls back if that fails too).
 */
const reload = async (actor) => {
	try {
		const base = await restarts();
		const since = Math.floor(Date.now() / 1000);
		await control.reloadService(SERVICE, actor);
		await sleep(1000);
		if (!(await waitHealthy(HEALTH_TIMEOUT_MS, base))) return false;
		const lines = await control.getLogs(SERVICE, { tail: 300, since });
		const fatal = (Array.isArray(lines) ? lines : []).filter((l) => /level=fatal/.test(String(l.line ?? l)));
		if (fatal.length) {
			logger.warn(`NPMOS CrowdSec: reload failed, restarting. ${fatalMessages(fatal).join(" | ")}`);
			return false;
		}
		return true;
	} catch (err) {
		logger.warn(`NPMOS CrowdSec: reload not possible (${err.message}), restarting`);
		return false;
	}
};

let running = Promise.resolve();

/**
 * Writes the files, installs the hub items they need and restarts CrowdSec when anything changed.
 * @param {object} settings  normalized (config.js)
 * @param {{actor?: number, force?: boolean, online?: boolean}} [options]
 * @returns {Promise<{changed: string[], installed: string[], restarted: boolean, reloaded?: boolean, healthy: boolean}>}
 */
export const apply = (settings, options = {}) => {
	// one apply at a time: two restarts in a row would mix up the rollback
	const next = running.then(() => applyNow(settings, options));
	running = next.catch(() => {});
	return next;
};

const applyNow = async (settings, { actor, force = false, online = false }) => {
	const diff = await pending(settings);
	// hub items installed or removed for the settings
	const installed = [];
	for (const [type, name] of requiredItems(settings)) {
		installed.push(...(await install(type, name, { online })));
	}
	for (const [type, name] of unwantedItems(settings)) {
		installed.push(...(await remove(type, name)));
	}
	const changed = Object.keys(diff);
	if (!changed.length && !installed.length && !force) {
		return { changed, installed, restarted: false, healthy: true };
	}
	for (const [key, { new: content }] of Object.entries(diff)) await put(FILES[key], content);
	if (!force && changed.every((key) => RELOADED.includes(key)) && (await reload(actor))) {
		logger.info(`NPMOS CrowdSec: reloaded ${[...changed, ...installed].join(", ")}`);
		return { changed, installed, restarted: false, reloaded: true, healthy: true };
	}
	await control.restartService(SERVICE, actor);
	if (await waitHealthy()) {
		logger.info(`NPMOS CrowdSec: applied ${[...changed, ...installed].join(", ") || "restart"}`);
		return { changed, installed, restarted: true, healthy: true };
	}

	const errors = await lastLogs();
	logger.error(`NPMOS CrowdSec: not healthy after the change, restoring the previous files. ${errors.join(" | ")}`);
	for (const [key, { old }] of Object.entries(diff)) await put(FILES[key], old);
	await control.restartService(SERVICE, actor);
	const recovered = await waitHealthy();
	const error = new Error(
		`CrowdSec did not start with the new settings; the previous ones are restored${recovered ? "" : " (CrowdSec is still not healthy)"}.${errors.length ? ` ${errors.join(" ")}` : ""}`,
	);
	error.rolledBack = true;
	error.logs = errors;
	throw error;
};
