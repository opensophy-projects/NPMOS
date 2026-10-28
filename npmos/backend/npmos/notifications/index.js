// Notifications (docs/ROADMAP.md, phase 4; ADR-11): channels, rules and the engine that checks the
// rules every minute and sends what changed. RBAC: notifications:view / notifications:manage.
import db from "../../db.js";
import internalAuditLog from "../../internal/audit-log.js";
import errs from "../../lib/error.js";
import { global as logger } from "../../logger.js";
import { decrypt } from "../secrets.js";
import { CHANNEL_TYPES, channelConfig, deliver, SECRET_FIELDS } from "./channels.js";
import { check, normalizeParams, RULE_TYPES, render } from "./rules.js";

const INTERVAL_MS = 60 * 1000;
const LOG_KEEP = 1000;

const parse = (value) => (typeof value === "string" ? JSON.parse(value) : value);

const decrypted = (channel) => {
	const config = { ...parse(channel.config) };
	for (const field of SECRET_FIELDS[channel.type] ?? []) config[field] = decrypt(config[field]);
	return { ...channel, config };
};

/** a channel as the API shows it: secrets replaced by has_<field> */
const masked = (channel) => {
	const config = { ...parse(channel.config) };
	for (const field of SECRET_FIELDS[channel.type] ?? []) {
		config[`has_${field}`] = !!config[field];
		delete config[field];
	}
	return { ...channel, enabled: !!channel.enabled, config };
};

const ruleApi = (rule) => ({
	...rule,
	enabled: !!rule.enabled,
	notify_resolved: !!rule.notify_resolved,
	params: normalizeParams(rule.type, parse(rule.params)),
	channel_ids: parse(rule.channel_ids),
	active: Object.keys(parse(rule.state) || {}),
	state: undefined,
});

const writeLog = async (rows) => {
	if (!rows.length) return;
	const knex = db();
	await knex("npmos_notification_log").insert(rows);
	const [{ max }] = await knex("npmos_notification_log").max({ max: "id" });
	if (max > LOG_KEEP)
		await knex("npmos_notification_log")
			.where("id", "<=", max - LOG_KEEP)
			.delete();
};

/**
 * Sends a message of a rule to its channels and logs each delivery.
 * @returns {Promise<{channel: number, ok: boolean, error: string}[]>}
 */
const send = async (rule, channels, status, alert, now) => {
	const results = [];
	for (const channel of channels) {
		const { title, text } = render(rule.type, status, alert.values, channel.config.language);
		const message = {
			status,
			rule: { id: rule.id, name: rule.name, type: rule.type },
			severity: RULE_TYPES[rule.type]?.severity ?? "warning",
			key: alert.key,
			title,
			text,
			time: now.toISOString(),
			node_id: "local",
			values: alert.values,
		};
		try {
			await deliver(channel, message);
			results.push({ channel: channel.id, ok: true, error: "", title });
		} catch (err) {
			results.push({ channel: channel.id, ok: false, error: err.message, title });
		}
	}
	await writeLog(
		results.map((r) => ({
			created_on: now,
			rule_id: rule.id,
			channel_id: r.channel,
			status,
			title: r.title.slice(0, 255),
			ok: r.ok,
			error: r.error.slice(0, 500),
		})),
	);
	return results;
};

/**
 * One round of the engine: checks every enabled rule, sends what appeared, repeats and what was
 * resolved. Exported for tests and "check now".
 */
export const evaluate = async (now = new Date()) => {
	const knex = db();
	const rules = await knex("npmos_notification_rule").where("enabled", true);
	if (!rules.length) return;
	const channels = (await knex("npmos_notification_channel").where("enabled", true)).map(decrypted);
	for (const rule of rules) {
		let alerts;
		try {
			alerts = await check(rule.type, parse(rule.params), now);
		} catch (err) {
			logger.warn(`NPMOS notifications: rule ${rule.id} (${rule.type}) failed: ${err.message}`);
			continue;
		}
		const targets = channels.filter((c) => parse(rule.channel_ids).includes(c.id));
		const state = { ...(parse(rule.state) || {}) };
		let changed = false;
		for (const alert of alerts) {
			const previous = state[alert.key];
			if (alert.pending) continue;
			const repeat =
				rule.repeat_minutes > 0 && previous && now - new Date(previous.at) >= rule.repeat_minutes * 60000;
			if (!previous || repeat) {
				if (targets.length) await send(rule, targets, "firing", alert, now);
				state[alert.key] = { at: now.toISOString(), values: alert.values };
				changed = true;
			}
		}
		const active = new Set(alerts.map((a) => a.key));
		for (const [key, previous] of Object.entries(state)) {
			if (active.has(key)) continue;
			if (rule.notify_resolved && targets.length) {
				await send(rule, targets, "resolved", { key, values: previous.values }, now);
			}
			delete state[key];
			changed = true;
		}
		if (changed) {
			await knex("npmos_notification_rule")
				.where("id", rule.id)
				.update({ state: JSON.stringify(state) });
		}
	}
};

const engine = { timer: null, running: false };

/** starts the engine (first round a minute after the start: services are still coming up) */
export const start = () => {
	if (engine.running) return;
	engine.running = true;
	const round = async () => {
		try {
			await evaluate();
		} catch (err) {
			logger.error(`NPMOS notifications: ${err.message}`);
		} finally {
			if (engine.running) engine.timer = setTimeout(round, INTERVAL_MS);
		}
	};
	engine.timer = setTimeout(round, INTERVAL_MS);
};

export const stop = () => {
	engine.running = false;
	clearTimeout(engine.timer);
};

const audit = (access, action, object, meta) =>
	internalAuditLog.add(access, {
		action,
		object_type: "notification",
		object_id: object.id,
		meta: { name: object.name, ...meta },
	});

const getChannel = async (id) => {
	const channel = await db()("npmos_notification_channel").where("id", id).first();
	if (!channel) throw new errs.ItemNotFoundError(id);
	return channel;
};

const getRule = async (id) => {
	const rule = await db()("npmos_notification_rule").where("id", id).first();
	if (!rule) throw new errs.ItemNotFoundError(id);
	return rule;
};

const checkChannelIds = async (ids) => {
	const found = await db()("npmos_notification_channel").whereIn("id", ids).pluck("id");
	const missing = ids.filter((id) => !found.includes(id));
	if (missing.length) throw new errs.ValidationError(`Unknown channels: ${missing.join(", ")}`);
};

const internalNotifications = {
	/** channels (without secrets), rules, the last deliveries, rule types and their defaults */
	get: async (access) => {
		await access.can("notifications:view");
		const knex = db();
		const [channels, rules, log] = await Promise.all([
			knex("npmos_notification_channel").orderBy("id"),
			knex("npmos_notification_rule").orderBy("id"),
			knex("npmos_notification_log").orderBy("id", "desc").limit(100),
		]);
		return {
			channels: channels.map(masked),
			rules: rules.map(ruleApi),
			log: log.map((l) => ({ ...l, ok: !!l.ok })),
			// lists, not maps: the API client camelizes keys
			rule_types: Object.keys(RULE_TYPES).map((type) => ({
				type,
				severity: RULE_TYPES[type].severity,
				defaults: normalizeParams(type, {}),
			})),
			channel_types: CHANNEL_TYPES,
		};
	},

	createChannel: async (access, data) => {
		await access.can("notifications:manage");
		const now = new Date();
		const [inserted] = await db()("npmos_notification_channel")
			.insert({
				name: data.name,
				type: data.type,
				enabled: data.enabled !== false,
				config: JSON.stringify(channelConfig(data.type, data.config)),
				created_on: now,
				modified_on: now,
			})
			.returning("id");
		const id = typeof inserted === "object" ? inserted.id : inserted;
		await audit(access, "created", { id, name: data.name }, { type: data.type });
		return masked(await getChannel(id));
	},

	updateChannel: async (access, id, data) => {
		await access.can("notifications:manage");
		const channel = await getChannel(id);
		if (data.type && data.type !== channel.type)
			throw new errs.ValidationError("The type of a channel can't change");
		await db()("npmos_notification_channel")
			.where("id", id)
			.update({
				name: data.name ?? channel.name,
				enabled: data.enabled ?? channel.enabled,
				config: JSON.stringify(
					data.config
						? channelConfig(channel.type, data.config, parse(channel.config))
						: parse(channel.config),
				),
				modified_on: new Date(),
			});
		await audit(access, "updated", { id, name: data.name ?? channel.name }, { type: channel.type });
		return masked(await getChannel(id));
	},

	deleteChannel: async (access, id) => {
		await access.can("notifications:manage");
		const channel = await getChannel(id);
		const knex = db();
		await knex("npmos_notification_channel").where("id", id).delete();
		// rules forget the channel
		for (const rule of await knex("npmos_notification_rule")) {
			const ids = parse(rule.channel_ids);
			if (ids.includes(id)) {
				await knex("npmos_notification_rule")
					.where("id", rule.id)
					.update({ channel_ids: JSON.stringify(ids.filter((c) => c !== id)) });
			}
		}
		await audit(access, "deleted", channel, { type: channel.type });
		return true;
	},

	/** sends a test message through a channel now */
	testChannel: async (access, id) => {
		await access.can("notifications:manage");
		const channel = decrypted(await getChannel(id));
		const now = new Date();
		const ru = channel.config.language !== "en";
		const message = {
			status: "test",
			rule: null,
			severity: "info",
			key: "test",
			title: ru ? "Проверка уведомлений" : "Test notification",
			text: ru
				? `Канал «${channel.name}» работает: NPMOS доставил это сообщение.`
				: `The channel "${channel.name}" works: NPMOS delivered this message.`,
			time: now.toISOString(),
			node_id: "local",
			values: {},
		};
		let error = "";
		try {
			await deliver(channel, message);
		} catch (err) {
			error = err.message;
		}
		await writeLog([
			{ created_on: now, rule_id: null, channel_id: id, status: "test", title: message.title, ok: !error, error },
		]);
		return { ok: !error, error };
	},

	createRule: async (access, data) => {
		await access.can("notifications:manage");
		await checkChannelIds(data.channel_ids);
		const now = new Date();
		const [inserted] = await db()("npmos_notification_rule")
			.insert({
				name: data.name,
				type: data.type,
				enabled: data.enabled !== false,
				params: JSON.stringify(normalizeParams(data.type, data.params)),
				channel_ids: JSON.stringify(data.channel_ids),
				repeat_minutes: data.repeat_minutes ?? 0,
				notify_resolved: data.notify_resolved !== false,
				state: "{}",
				created_on: now,
				modified_on: now,
			})
			.returning("id");
		const id = typeof inserted === "object" ? inserted.id : inserted;
		await audit(access, "created", { id, name: data.name }, { type: data.type });
		return ruleApi(await getRule(id));
	},

	updateRule: async (access, id, data) => {
		await access.can("notifications:manage");
		const rule = await getRule(id);
		if (data.type && data.type !== rule.type) throw new errs.ValidationError("The type of a rule can't change");
		if (data.channel_ids) await checkChannelIds(data.channel_ids);
		await db()("npmos_notification_rule")
			.where("id", id)
			.update({
				name: data.name ?? rule.name,
				enabled: data.enabled ?? rule.enabled,
				params: JSON.stringify(normalizeParams(rule.type, data.params ?? parse(rule.params))),
				channel_ids: JSON.stringify(data.channel_ids ?? parse(rule.channel_ids)),
				repeat_minutes: data.repeat_minutes ?? rule.repeat_minutes,
				notify_resolved: data.notify_resolved ?? rule.notify_resolved,
				// a disabled rule forgets its alerts: when enabled again they are new
				state: data.enabled === false ? "{}" : JSON.stringify(parse(rule.state) || {}),
				modified_on: new Date(),
			});
		await audit(access, "updated", { id, name: data.name ?? rule.name }, { type: rule.type });
		return ruleApi(await getRule(id));
	},

	deleteRule: async (access, id) => {
		await access.can("notifications:manage");
		const rule = await getRule(id);
		await db()("npmos_notification_rule").where("id", id).delete();
		await audit(access, "deleted", rule, { type: rule.type });
		return true;
	},
};

export default internalNotifications;
