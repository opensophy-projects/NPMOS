// Rules of notifications: what is checked, with which parameters, and the text of the messages.
// A check returns the alerts active now ({key, severity, values}); the engine sends a message when
// an alert appears (and, if asked, again later and when it is resolved).
// Messages are written in the language of the channel (ru/en); they are not part of the GUI.
import db from "../../db.js";
import control from "../control/client.js";
import { EVENT_TABLE } from "../events/store.js";
import { getSetting } from "../settings.js";
import { getAgentStatus } from "../waf/agent.js";
import { getPolicyState } from "../waf/policy.js";

const int = (min, max, fallback) => (v) => (Number.isInteger(v) && v >= min && v <= max ? v : fallback);

/** rule type → default parameters and their check */
export const RULE_TYPES = {
	attack_spike: {
		params: {
			threshold: int(1, 1000000, 50),
			window: int(1, 1440, 5),
			host: (v) => (typeof v === "string" ? v.trim().toLowerCase().slice(0, 255) : ""),
		},
		severity: "critical",
	},
	agent_down: { params: { minutes: int(1, 1440, 3) }, severity: "critical" },
	policy_error: { params: {}, severity: "critical" },
	service_down: { params: {}, severity: "critical" },
	cert_expiry: { params: { days: int(1, 365, 14) }, severity: "warning" },
	host_problem: { params: {}, severity: "warning" },
};

/** parameters of a rule with defaults for what is missing or invalid */
export const normalizeParams = (type, params = {}) =>
	Object.fromEntries(Object.entries(RULE_TYPES[type].params).map(([name, check]) => [name, check(params[name])]));

const TEXT = {
	attack_spike: {
		en: (v) => ({
			title: `Attack spike: ${v.count} attacks in ${v.window} min${v.host ? ` on ${v.host}` : ""}`,
			text: `The WAF recorded ${v.count} important events (Critical, High) in the last ${v.window} minutes, the threshold is ${v.threshold}. Top source: ${v.top || "—"}.`,
		}),
		ru: (v) => ({
			title: `Всплеск атак: ${v.count} за ${v.window} мин${v.host ? ` на ${v.host}` : ""}`,
			text: `WAF записал ${v.count} важных событий (Critical, High) за последние ${v.window} минут, порог — ${v.threshold}. Главный источник: ${v.top || "—"}.`,
		}),
	},
	agent_down: {
		en: (v) => ({
			title: "The WAF agent does not answer",
			text: `The open-appsec agent has not answered for ${v.minutes} min (${v.error}). Depending on fail-open, requests pass unchecked or are refused.`,
		}),
		ru: (v) => ({
			title: "Агент WAF не отвечает",
			text: `Агент open-appsec не отвечает ${v.minutes} мин (${v.error}). В зависимости от fail-open запросы проходят без проверки или отклоняются.`,
		}),
	},
	policy_error: {
		en: (v) => ({
			title: "The WAF policy was not applied",
			text: `The agent did not take the new policy: ${v.error}. The previous policy stays in force.`,
		}),
		ru: (v) => ({
			title: "Политика WAF не применена",
			text: `Агент не принял новую политику: ${v.error}. Действует предыдущая политика.`,
		}),
	},
	service_down: {
		en: (v) => ({
			title: `Service ${v.name} is down`,
			text: `The service ${v.name} is ${v.state}. System → Services shows its logs.`,
		}),
		ru: (v) => ({
			title: `Сервис ${v.name} не работает`,
			text: `Сервис ${v.name}: ${v.state}. Логи — в «Система → Сервисы».`,
		}),
	},
	cert_expiry: {
		en: (v) => ({
			title: `Certificate ${v.name} expires ${v.days < 0 ? "— expired" : `in ${v.days} d`}`,
			text: `The certificate ${v.name} (${v.domains}) expires on ${v.expires}. Let's Encrypt certificates are renewed automatically; others must be replaced.`,
		}),
		ru: (v) => ({
			title: `Сертификат ${v.name} ${v.days < 0 ? "истёк" : `истекает через ${v.days} дн.`}`,
			text: `Сертификат ${v.name} (${v.domains}) действует до ${v.expires}. Let's Encrypt продлевается сам; свои сертификаты нужно заменить.`,
		}),
	},
	host_problem: {
		en: (v) => ({
			title: `Host ${v.name}: nginx error`,
			text: `nginx did not take the configuration of ${v.name}: ${v.error}`,
		}),
		ru: (v) => ({
			title: `Хост ${v.name}: ошибка nginx`,
			text: `nginx не принял конфигурацию ${v.name}: ${v.error}`,
		}),
	},
};

const RESOLVED = { en: "Resolved", ru: "Решено" };

/**
 * Title and text of an alert in a language.
 * @param {string} type
 * @param {"firing"|"resolved"|"test"} status
 */
export const render = (type, status, values, language = "ru") => {
	const lang = language === "en" ? "en" : "ru";
	const { title, text } = TEXT[type][lang](values);
	return status === "resolved" ? { title: `${RESOLVED[lang]}: ${title}`, text } : { title, text };
};

/** how long the agent has been unreachable (in this process) */
const agentDown = { since: null };

const parseJson = (value) => (typeof value === "string" ? JSON.parse(value) : value) || {};

const CHECKS = {
	attack_spike: async (p, now) => {
		const from = new Date(now.getTime() - p.window * 60000);
		const base = () => {
			const b = db()(EVENT_TABLE)
				.where("kind", "security")
				.where("time", ">=", from)
				.whereRaw("lower(severity) in ('critical', 'high')");
			if (p.host) b.where("host", p.host);
			return b;
		};
		const row = await base().count({ n: "*" }).first();
		const count = Number(row?.n ?? 0);
		if (count < p.threshold) return [];
		const top = await base()
			.select("source_ip")
			.count({ n: "*" })
			.groupBy("source_ip")
			.orderBy("n", "desc")
			.first();
		return [
			{
				key: `spike${p.host ? `:${p.host}` : ""}`,
				values: { count, window: p.window, threshold: p.threshold, host: p.host, top: top?.source_ip },
			},
		];
	},

	agent_down: async (p, now) => {
		if (!(await getSetting("waf.enabled"))) {
			agentDown.since = null;
			return [];
		}
		const status = await getAgentStatus();
		if (status.reachable) {
			agentDown.since = null;
			return [];
		}
		agentDown.since ??= now.getTime();
		const minutes = Math.floor((now.getTime() - agentDown.since) / 60000);
		// pending: not long enough to fire, but an alert already sent stays (the count restarts with NPMOS)
		return [{ key: "agent", values: { minutes, error: status.error }, pending: minutes < p.minutes }];
	},

	policy_error: async () => {
		if (!(await getSetting("waf.enabled"))) return [];
		const { applied } = getPolicyState();
		return applied && !applied.ok ? [{ key: "policy", values: { error: applied.error } }] : [];
	},

	service_down: async () => {
		let services;
		try {
			services = await control.listServices();
		} catch (err) {
			return [{ key: "service:npmos-control", values: { name: "npmos-control", state: err.message } }];
		}
		return services
			.filter((s) => s.state !== "running" || /\(unhealthy\)/.test(s.status))
			.map((s) => ({
				key: `service:${s.service}`,
				values: { name: s.name || s.service, state: s.status || s.state },
			}));
	},

	cert_expiry: async (p, now) => {
		const until = new Date(now.getTime() + p.days * 86400000);
		const daysLeft = (date) => Math.floor((new Date(date).getTime() - now.getTime()) / 86400000);
		// messages at 30, 7 and 1 day left and when expired (within the days of the rule)
		const stage = (days) => (days < 0 ? "expired" : String([1, 7, 30].find((s) => days <= s) ?? p.days));
		const rows = await db()("certificate")
			.where("is_deleted", 0)
			.whereNotNull("expires_on")
			.where("expires_on", "<=", until)
			.select("id", "nice_name", "domain_names", "expires_on");
		const alerts = rows.map((c) => {
			const domains = parseJson(c.domain_names);
			const days = daysLeft(c.expires_on);
			return {
				key: `cert:${c.id}`,
				values: {
					name: c.nice_name || domains[0] || `#${c.id}`,
					domains: Array.isArray(domains) ? domains.join(", ") : "",
					expires: new Date(c.expires_on).toISOString().slice(0, 10),
					days,
					stage: stage(days),
				},
			};
		});
		// PKI and mTLS: certificates in use (not revoked or renewed) and CAs of NPMOS
		const pki = await db()("npmos_pki_cert")
			.whereNull("revoked_on")
			.whereNull("deleted_on")
			.whereNull("replaced_by")
			.whereNull("certificate_id")
			.where("not_after", "<=", until)
			.select("id", "common_name", "profile", "not_after");
		for (const c of pki) {
			const days = daysLeft(c.not_after);
			if (days < -30) continue;
			alerts.push({
				key: `pki:${c.id}`,
				values: {
					name: c.common_name,
					domains: c.profile === "client" ? "PKI, client" : "PKI, server",
					expires: new Date(c.not_after).toISOString().slice(0, 10),
					days,
					stage: stage(days),
				},
			});
		}
		const cas = await db()("npmos_pki_ca")
			.where("not_after", "<=", until)
			.select("id", "name", "kind", "not_after");
		for (const ca of cas) {
			const days = daysLeft(ca.not_after);
			alerts.push({
				key: `pki-ca:${ca.id}`,
				values: {
					name: ca.name,
					domains: `CA, ${ca.kind}`,
					expires: new Date(ca.not_after).toISOString().slice(0, 10),
					days,
					stage: stage(days),
				},
			});
		}
		return alerts;
	},

	host_problem: async () => {
		const alerts = [];
		for (const [table, prefix] of [
			["proxy_host", "proxy"],
			["redirection_host", "redirect"],
			["dead_host", "dead"],
		]) {
			const rows = await db()(table).where({ is_deleted: 0, enabled: 1 }).select("id", "domain_names", "meta");
			for (const row of rows) {
				const meta = parseJson(row.meta);
				if (meta.nginx_online !== false) continue;
				const domains = parseJson(row.domain_names);
				alerts.push({
					key: `${prefix}:${row.id}`,
					values: { name: domains[0] || `#${row.id}`, error: String(meta.nginx_err || "").slice(0, 300) },
				});
			}
		}
		return alerts;
	},
};

/**
 * Alerts of a rule active now. `pending`: the condition holds but has not lasted long enough to
 * fire; an alert already sent for it is not resolved.
 * @returns {Promise<{key: string, values: object, pending?: boolean}[]>}
 */
export const check = (type, params, now = new Date()) => CHECKS[type](normalizeParams(type, params), now);
