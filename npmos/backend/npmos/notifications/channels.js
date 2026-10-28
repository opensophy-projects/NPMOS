// Delivery of notifications (ADR-11): email over the admin's SMTP server, a webhook with an HMAC
// signature, a Telegram bot (needs internet: an option the admin turns on). Every call has a
// timeout; an unreachable server never blocks NPMOS.
import { createHmac } from "node:crypto";
import nodemailer from "nodemailer";
import errs from "../../lib/error.js";
import pjson from "../../package.json" with { type: "json" };
import { encrypt } from "../secrets.js";

export const CHANNEL_TYPES = ["email", "webhook", "telegram"];
/** config fields kept encrypted and never returned by the API */
export const SECRET_FIELDS = { email: ["password"], webhook: ["secret"], telegram: ["token"] };

/** API body (snake_case) → stored config of a channel type; secrets kept when not sent */
export const channelConfig = (type, data, previous = {}) => {
	const secret = (name, value) => (value === undefined || value === null ? previous[name] || "" : encrypt(value));
	const language = data.language === "en" ? "en" : "ru";
	switch (type) {
		case "email":
			return {
				host: data.host,
				port: data.port,
				security: data.security,
				verifyTls: data.verify_tls !== false,
				username: data.username || "",
				password: secret("password", data.password),
				from: data.from,
				to: data.to,
				language,
			};
		case "webhook":
			return { url: data.url, secret: secret("secret", data.secret), language };
		case "telegram":
			return {
				token: secret("token", data.token),
				chatId: data.chat_id,
				apiUrl: data.api_url || "",
				language,
			};
		default:
			throw new errs.ValidationError(`Unknown channel type ${type}`);
	}
};

const TIMEOUT_MS = 10000;
const USER_AGENT = `NPMOS/${pjson.version}`;

/**
 * The message of an alert as text.
 * @param {{status: string, title: string, text: string, time: string}} message
 */
export const plainText = (message) => `${message.title}\n\n${message.text}\n\n${message.time}`;

/** signature of a webhook body: hex HMAC-SHA256 of "<timestamp>.<body>" */
export const sign = (secret, timestamp, body) =>
	createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");

const email = async (config, message) => {
	const transport = nodemailer.createTransport({
		host: config.host,
		port: config.port,
		// tls: TLS from the start (465); starttls: upgrade required; none: plain (local relay)
		secure: config.security === "tls",
		requireTLS: config.security === "starttls",
		ignoreTLS: config.security === "none",
		auth: config.username ? { user: config.username, pass: config.password } : undefined,
		tls: { rejectUnauthorized: config.verifyTls !== false },
		connectionTimeout: TIMEOUT_MS,
		greetingTimeout: TIMEOUT_MS,
		socketTimeout: TIMEOUT_MS,
	});
	try {
		await transport.sendMail({
			from: config.from,
			to: config.to.join(", "),
			subject: `[NPMOS] ${message.title}`,
			text: plainText(message),
			headers: { "X-NPMOS-Status": message.status },
		});
	} finally {
		transport.close();
	}
};

const webhook = async (config, message) => {
	const body = JSON.stringify({ source: "npmos", ...message });
	const timestamp = String(Math.floor(Date.now() / 1000));
	const headers = { "Content-Type": "application/json", "User-Agent": USER_AGENT, "X-NPMOS-Timestamp": timestamp };
	if (config.secret) headers["X-NPMOS-Signature"] = `sha256=${sign(config.secret, timestamp, body)}`;
	const response = await fetch(config.url, {
		method: "POST",
		headers,
		body,
		redirect: "error",
		signal: AbortSignal.timeout(TIMEOUT_MS),
	});
	if (!response.ok) throw new Error(`HTTP ${response.status}`);
};

const telegram = async (config, message) => {
	const api = (config.apiUrl || "https://api.telegram.org").replace(/\/+$/, "");
	const response = await fetch(`${api}/bot${config.token}/sendMessage`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT },
		body: JSON.stringify({ chat_id: config.chatId, text: plainText(message), disable_web_page_preview: true }),
		signal: AbortSignal.timeout(TIMEOUT_MS),
	});
	if (!response.ok) {
		const data = await response.json().catch(() => ({}));
		// the token is part of the URL: never in the error
		throw new Error(`Telegram: ${data.description || `HTTP ${response.status}`}`);
	}
};

const SENDERS = { email, webhook, telegram };

/**
 * @param {{type: string, config: object}} channel  config with decrypted secrets
 * @param {object} message
 */
export const deliver = async (channel, message) => {
	const send = SENDERS[channel.type];
	if (!send) throw new Error(`Unknown channel type ${channel.type}`);
	try {
		await send(channel.config, message);
	} catch (err) {
		// fetch: "fetch failed" with the reason in its cause (or the causes of an AggregateError)
		const cause = err.cause?.errors?.[0] ?? err.cause;
		let reason = String(cause?.code || cause?.message || err.message || err);
		if (channel.config.token) reason = reason.replaceAll(channel.config.token, "***");
		throw new Error(reason.slice(0, 480));
	}
};
