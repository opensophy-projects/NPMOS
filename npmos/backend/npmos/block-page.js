// Agents → Block page: what a visitor sees when a request is refused by nginx itself (open-appsec, the CrowdSec
// bouncer, an access list). The page is rendered here into /data/npmos/block-page.html; nginx puts it in place of
// the refusal (conf.d/npmos-block-page.conf), filling in the IP, the time, the host and the request ID. Off: no
// file, each component answers with its own page.
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import YAML from "yaml";

/** loaded on use: they read the configuration of NPMplus (the renderer stays testable on its own) */
const deps = async () => ({
	audit: (await import("../internal/audit-log.js")).default,
	logger: (await import("../logger.js")).global,
	...(await import("./settings.js")),
});

export const PAGE_FILE = process.env.NPMOS_BLOCK_PAGE || "/data/npmos/block-page.html";

const html = (s) =>
	String(s ?? "").replace(
		/[&<>"']/g,
		(c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
	);

/** paragraphs of a text: empty lines separate them, single line breaks stay */
const paragraphs = (text) =>
	String(text ?? "")
		.split(/\n\s*\n/)
		.map((p) => p.trim())
		.filter(Boolean)
		.map((p) => `<p>${html(p).replaceAll("\n", "<br />")}</p>`)
		.join("\n      ");

/** the labels of the details, in the language of the page */
const LABELS = {
	en: { code: "Error 403", id: "Request ID", ip: "IP address", host: "Site", time: "Time" },
	ru: { code: "Ошибка 403", id: "ID запроса", ip: "IP-адрес", host: "Сайт", time: "Время" },
};

/**
 * The HTML of the page; {{ip}}, {{time}}, {{host}} and {{id}} are filled in by nginx.
 * @param {{title, text, contact, details, accent}} s
 */
export const render = (s) => {
	const l = LABELS[s.language] ?? LABELS.en;
	return `<!DOCTYPE html>
<!-- NPMOS: block page (Agents → Block page) -->
<html lang="${s.language === "ru" ? "ru" : "en"}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex" />
    <title>${html(s.title)}</title>
    <style>
      :root { color-scheme: light dark; --accent: ${s.accent}; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px; box-sizing: border-box;
        font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #f6f6f7; color: #18181b; }
      main { max-width: 34rem; width: 100%; padding: 2rem; border-radius: 16px; background: #fff;
        box-shadow: 0 1px 2px rgba(0,0,0,.06), 0 8px 24px rgba(0,0,0,.06); border-top: 4px solid var(--accent); }
      .code { color: var(--accent); font-weight: 600; letter-spacing: .04em; font-size: .8125rem; }
      h1 { margin: .25rem 0 1rem; font-size: 1.5rem; font-weight: 600; }
      p { margin: 0 0 .75rem; line-height: 1.55; color: #3f3f46; }
      .contact { margin-top: 1rem; }
      dl { display: grid; grid-template-columns: auto 1fr; gap: .25rem 1rem; margin: 1.25rem 0 0; padding-top: 1rem;
        border-top: 1px solid #e4e4e7; font-size: .8125rem; color: #71717a; }
      dd { margin: 0; font-family: ui-monospace, Menlo, Consolas, monospace; color: #3f3f46; word-break: break-all; }
      @media (prefers-color-scheme: dark) {
        body { background: #0f0f11; color: #f4f4f5; }
        main { background: #18181b; box-shadow: none; }
        p, dd { color: #d4d4d8; }
        dl { border-color: #27272a; }
      }
    </style>
  </head>
  <body>
    <main>
      <div class="code">${l.code}</div>
      <h1>${html(s.title)}</h1>
      ${paragraphs(s.text)}
      ${s.contact ? `<div class="contact">${paragraphs(s.contact)}</div>` : ""}
      ${
			s.details
				? `<dl>
        <dt>${l.id}</dt><dd>{{id}}</dd>
        <dt>${l.ip}</dt><dd>{{ip}}</dd>
        <dt>${l.host}</dt><dd>{{host}}</dd>
        <dt>${l.time}</dt><dd>{{time}}</dd>
      </dl>`
				: ""
}
    </main>
  </body>
</html>
`;
};

/** writes the page of the settings (or removes it when the page is off) */
export const writePage = async (settings) => {
	if (!settings.enabled) {
		await rm(PAGE_FILE, { force: true });
		return;
	}
	await mkdir(PAGE_FILE.replace(/\/[^/]+$/, ""), { recursive: true });
	const tmp = `${PAGE_FILE}.tmp`;
	await writeFile(tmp, render(settings));
	await rename(tmp, PAGE_FILE);
};

/** at the start: the page of the stored settings (never fails the start) */
export const bootstrap = async () => {
	const { getSetting, logger } = await deps();
	try {
		await writePage(await getSetting("block.page"));
	} catch (err) {
		logger.error(`NPMOS block page: ${err.message}`);
	}
};

const internalBlockPage = {
	get: async (access) => {
		await access.can("waf_policy:view");
		const { getSetting } = await deps();
		const settings = await getSetting("block.page");
		return { settings, preview: render(settings) };
	},

	/** @param {{enabled, title, text, contact, details, accent}} data */
	set: async (access, data) => {
		await access.can("waf_policy:manage");
		const { setSetting, audit } = await deps();
		await setSetting("block.page", data);
		await writePage(data);
		await audit.add(access, {
			action: "updated",
			object_type: "setting",
			meta: { name: "block.page", enabled: data.enabled },
		});
		return internalBlockPage.get(access);
	},

	/** the settings as YAML (Agents → Block page → Code) */
	getCode: async (access) => {
		const { settings } = await internalBlockPage.get(access);
		return {
			content: `# NPMOS: the block page; {{id}} {{ip}} {{host}} {{time}} are filled in by nginx\n${YAML.stringify(settings, { lineWidth: 0 })}`,
		};
	},

	/**
	 * Checks (dry run) or saves the settings of a YAML document.
	 * @param {Access} access
	 * @param {{content: string, dry_run?: boolean}} data
	 * @param {(data: object) => Promise<object>} validate  the schema of the route
	 */
	setCode: async (access, data, validate) => {
		await access.can(data.dry_run ? "waf_policy:view" : "waf_policy:manage");
		let settings;
		try {
			settings = await validate(YAML.parse(data.content));
		} catch (err) {
			return { valid: false, error: err.message };
		}
		if (data.dry_run) return { valid: true };
		await internalBlockPage.set(access, settings);
		return { valid: true, applied: true };
	},

	/** the page of settings not saved yet */
	preview: async (access, data) => {
		await access.can("waf_policy:view");
		return { preview: render(data) };
	},
};

export default internalBlockPage;
