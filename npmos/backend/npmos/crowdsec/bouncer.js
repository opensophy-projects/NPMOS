// The CrowdSec bouncer of NPMOS: the Lua bouncer of NPMplus in nginx, configured from the GUI
// instead of /data/crowdsec/crowdsec.conf by hand. The nginx part (conf.d/crowdsec.conf) is the
// one of NPMplus with a check of $npmos_crowdsec_off, so that single hosts can be left out
// (set in _common.conf from npmos_crowdsec_host).
import { copyFile, readFile, rename, rm, writeFile } from "node:fs/promises";
import db from "../../db.js";
import internalNginx from "../../internal/nginx.js";
import { global as logger } from "../../logger.js";
import { decrypt } from "../secrets.js";
import { renderBouncer, renderNginx } from "./config.js";
import { bouncerKey } from "./lapi.js";

const DATA_CONF = process.env.NPMOS_CROWDSEC_BOUNCER_CONF || "/data/crowdsec/crowdsec.conf";
const NGINX_DIR = process.env.NPMOS_NGINX_CONF_D || "/usr/local/nginx/conf/conf.d";
const NGINX_CONF = `${NGINX_DIR}/crowdsec.conf`;
const NGINX_TEMPLATE = `${NGINX_DIR}/crowdsec.conf.disabled`;

export const HOST_TYPES = ["proxy_host", "redirection_host", "dead_host"];

const readText = async (file) => {
	try {
		return await readFile(file, "utf8");
	} catch {
		return null;
	}
};

const writeAtomic = async (file, text) => {
	await writeFile(`${file}.tmp`, text, { mode: 0o600 });
	await rename(`${file}.tmp`, file);
};

let perHost = null;

/** whether single hosts can be left out (null: not known yet) */
export const perHostSupported = () => perHost;

/**
 * Writes the bouncer files; reloads nginx when they changed. A config nginx rejects is undone.
 * @param {object} settings  normalized (config.js)
 * @param {{reload?: boolean}} [options]
 * @returns {Promise<{changed: boolean}>}
 */
export const applyBouncer = async (settings, { reload = true } = {}) => {
	const conf = renderBouncer(settings, {
		apiKey: await bouncerKey(),
		captchaSecret: decrypt(settings.bouncer.captcha.secret_key),
	});
	const oldConf = await readText(DATA_CONF);
	const oldNginx = await readText(NGINX_CONF);
	let nginx = null;
	if (settings.bouncer.enabled) {
		const template = await readText(NGINX_TEMPLATE);
		if (template === null) throw new Error(`${NGINX_TEMPLATE} is missing: the image has no CrowdSec bouncer`);
		const rendered = renderNginx(template);
		perHost = rendered.perHost;
		if (!rendered.perHost) logger.warn("NPMOS CrowdSec: unknown bouncer code, hosts cannot be left out");
		nginx = rendered.text;
	}
	if (oldConf === conf && oldNginx === nginx) return { changed: false };

	// the file of NPMplus before NPMOS took it over
	if (oldConf !== null && !oldConf.startsWith(HEADER)) await copyFile(DATA_CONF, `${DATA_CONF}.npmplus`);
	await writeAtomic(DATA_CONF, conf);
	if (nginx === null) await rm(NGINX_CONF, { force: true });
	else await writeAtomic(NGINX_CONF, nginx);
	if (!reload) return { changed: true };
	try {
		await internalNginx.reload();
	} catch (err) {
		if (oldConf === null) await rm(DATA_CONF, { force: true });
		else await writeAtomic(DATA_CONF, oldConf);
		if (oldNginx === null) await rm(NGINX_CONF, { force: true });
		else await writeAtomic(NGINX_CONF, oldNginx);
		await internalNginx.reload().catch(() => {});
		throw new Error(`nginx rejected the bouncer configuration: ${err.message}`);
	}
	return { changed: true };
};

/** hook of internal/nginx.js: npmos_crowdsec_off of the templates */
export const prepareHost = async (hostType, host) => {
	if (!HOST_TYPES.includes(hostType) || !host?.id) return;
	try {
		const row = await db()("npmos_crowdsec_host").where({ host_type: hostType, host_id: host.id }).first();
		host.npmos_crowdsec_off = row ? !row.bouncer : false;
	} catch {
		// before the migration (first start of an upgrade)
		host.npmos_crowdsec_off = false;
	}
};
