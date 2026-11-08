// A notification channel: email (SMTP of the admin), webhook (JSON signed with HMAC) or a Telegram
// bot (needs internet). Secrets are write-only: empty keeps the stored one.
import { useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import {
	type Channel,
	type ChannelConfig,
	type ChannelType,
	createChannel,
	type EmailConfig,
	type Language,
	type TelegramConfig,
	updateChannel,
	type WebhookConfig,
} from "./api";
import { HiddenUsername } from "../ui/HiddenUsername";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const DEFAULTS: Record<ChannelType, ChannelConfig> = {
	email: {
		host: "",
		port: 587,
		security: "starttls",
		verifyTls: true,
		username: "",
		from: "",
		to: [],
		language: "ru",
	},
	webhook: { url: "", language: "ru" },
	telegram: { chatId: "", apiUrl: "", language: "ru" },
};

/** placeholders of technical values (not translated) */
const EXAMPLE = {
	host: "smtp.example.com",
	from: "nginxions@example.com",
	to: "admin@example.com, soc@example.com",
	url: "https://siem.example.com/hooks/nginxions",
	token: "123456789:AA…",
	chat: "-1001234567890",
	api: "https://api.telegram.org",
};

interface Props extends InnerModalProps {
	type: ChannelType;
	channel?: Channel;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
	return (
		<div className="mb-3">
			<span className="form-label">
				<T id={label} />
			</span>
			{children}
			{hint && (
				<div className="form-hint">
					<T id={hint} />
				</div>
			)}
		</div>
	);
}

const ChannelModal = EasyModal.create(({ type, channel, visible, remove }: Props) => {
	const queryClient = useQueryClient();
	const [name, setName] = useState(channel?.name ?? t(`nginxions.notifications.channel.${type}`));
	const [config, setConfig] = useState<ChannelConfig>(() => ({ ...DEFAULTS[type], ...channel?.config }));
	const [secret, setSecret] = useState("");
	const [to, setTo] = useState(((channel?.config as EmailConfig | undefined)?.to ?? []).join(", "));
	const [error, setError] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const set = (patch: Partial<EmailConfig & WebhookConfig & TelegramConfig>) =>
		setConfig({ ...config, ...patch } as ChannelConfig);
	const email = config as EmailConfig;
	const webhook = config as WebhookConfig;
	const telegram = config as TelegramConfig;
	const hasSecret = !!(
		(config as EmailConfig).hasPassword ||
		(config as WebhookConfig).hasSecret ||
		(config as TelegramConfig).hasToken
	);

	const save = async () => {
		setSaving(true);
		setError(null);
		const body: Record<string, any> = { ...config };
		for (const key of ["hasPassword", "hasSecret", "hasToken"]) delete body[key];
		const secretKey = type === "email" ? "password" : type === "webhook" ? "secret" : "token";
		if (secret) body[secretKey] = secret;
		else delete body[secretKey];
		if (type === "email") {
			body.to = to
				.split(/[\s,;]+/)
				.map((s) => s.trim())
				.filter(Boolean);
			if (!body.username) delete body.password;
		}
		if (type === "telegram" && !body.apiUrl) body.apiUrl = "";
		try {
			if (channel) await updateChannel(channel.id, { name, config: body as ChannelConfig });
			else await createChannel({ name, type, config: body as ChannelConfig });
			queryClient.invalidateQueries({ queryKey: ["nginxions-notifications"] });
			showSuccess(t("nginxions.notifications.saved"));
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setSaving(false);
	};

	const secretLabel =
		type === "email"
			? "nginxions.notifications.email.password"
			: type === "webhook"
				? "nginxions.notifications.webhook.secret"
				: "nginxions.notifications.telegram.token";

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={channel ? "nginxions.notifications.channel.edit" : "nginxions.notifications.channel.new"} />
					{" · "}
					<T id={`nginxions.notifications.channel.${type}`} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{/* NginxionS: a form wrapper so the browser does not warn about password fields outside a form */}
				<form autoComplete="off" onSubmit={(e) => e.preventDefault()}>
					<HiddenUsername />
					{error && <Alert variant="danger">{error}</Alert>}
					{type === "telegram" && (
						<Alert variant="warning">
							<T id="nginxions.notifications.telegram.internet" />
						</Alert>
					)}
					<Field label="nginxions.notifications.name">
						<input
							autoComplete="off"
							className="form-control"
							value={name}
							maxLength={100}
							onChange={(e) => setName(e.target.value)}
						/>
					</Field>
					{type === "email" && (
						<>
							<div className="row">
								<div className="col-md-6">
									<Field label="nginxions.notifications.email.host">
										<input
											autoComplete="off"
											className="form-control"
											value={email.host}
											placeholder={EXAMPLE.host}
											onChange={(e) => set({ host: e.target.value.trim() })}
										/>
									</Field>
								</div>
								<div className="col-md-2">
									<Field label="nginxions.notifications.email.port">
										<input
											autoComplete="off"
											type="number"
											className="form-control"
											value={email.port}
											min={1}
											max={65535}
											onChange={(e) => set({ port: Number.parseInt(e.target.value, 10) || 0 })}
										/>
									</Field>
								</div>
								<div className="col-md-4">
									<Field label="nginxions.notifications.email.security">
										<select
											className="form-select"
											value={email.security}
											onChange={(e) => {
												const security = e.target.value as EmailConfig["security"];
												set({
													security,
													port: security === "tls" ? 465 : security === "starttls" ? 587 : 25,
												});
											}}
										>
											{(["starttls", "tls", "none"] as const).map((s) => (
												<option key={s} value={s}>
													{t(`nginxions.notifications.email.security.${s}`)}
												</option>
											))}
										</select>
									</Field>
								</div>
							</div>
							<div className="row">
								<div className="col-md-6">
									<Field label="nginxions.notifications.email.username">
										<input
											className="form-control"
											value={email.username}
											autoComplete="off"
											onChange={(e) => set({ username: e.target.value })}
										/>
									</Field>
								</div>
								<div className="col-md-6">
									<Field
										label={secretLabel}
										hint={hasSecret ? "nginxions.notifications.secret.keep" : undefined}
									>
										<input
											type="password"
											className="form-control"
											value={secret}
											autoComplete="new-password"
											placeholder={hasSecret ? "••••••••" : ""}
											onChange={(e) => setSecret(e.target.value)}
										/>
									</Field>
								</div>
							</div>
							<Field label="nginxions.notifications.email.from">
								<input
									autoComplete="off"
									className="form-control"
									value={email.from}
									placeholder={EXAMPLE.from}
									onChange={(e) => set({ from: e.target.value.trim() })}
								/>
							</Field>
							<Field
								label="nginxions.notifications.email.to"
								hint="nginxions.notifications.email.to.hint"
							>
								<input
									autoComplete="off"
									className="form-control"
									value={to}
									placeholder={EXAMPLE.to}
									onChange={(e) => setTo(e.target.value)}
								/>
							</Field>
							{email.security !== "none" && (
								<label className="form-check mb-3">
									<input
										type="checkbox"
										className="form-check-input"
										checked={email.verifyTls}
										onChange={(e) => set({ verifyTls: e.target.checked })}
									/>
									<span className="form-check-label">
										<T id="nginxions.notifications.email.verify-tls" />
									</span>
								</label>
							)}
						</>
					)}
					{type === "webhook" && (
						<>
							<Field label="nginxions.notifications.webhook.url">
								<input
									autoComplete="off"
									className="form-control"
									value={webhook.url}
									placeholder={EXAMPLE.url}
									onChange={(e) => set({ url: e.target.value.trim() })}
								/>
							</Field>
							<Field
								label={secretLabel}
								hint={
									hasSecret
										? "nginxions.notifications.secret.keep"
										: "nginxions.notifications.webhook.secret.hint"
								}
							>
								<input
									type="password"
									className="form-control"
									value={secret}
									autoComplete="new-password"
									placeholder={hasSecret ? "••••••••" : ""}
									onChange={(e) => setSecret(e.target.value)}
								/>
							</Field>
						</>
					)}
					{type === "telegram" && (
						<>
							<Field
								label={secretLabel}
								hint={hasSecret ? "nginxions.notifications.secret.keep" : undefined}
							>
								<input
									type="password"
									className="form-control"
									value={secret}
									autoComplete="new-password"
									placeholder={hasSecret ? "••••••••" : EXAMPLE.token}
									onChange={(e) => setSecret(e.target.value.trim())}
								/>
							</Field>
							<Field
								label="nginxions.notifications.telegram.chat"
								hint="nginxions.notifications.telegram.chat.hint"
							>
								<input
									autoComplete="off"
									className="form-control"
									value={telegram.chatId}
									placeholder={EXAMPLE.chat}
									onChange={(e) => set({ chatId: e.target.value.trim() })}
								/>
							</Field>
							<Field
								label="nginxions.notifications.telegram.api"
								hint="nginxions.notifications.telegram.api.hint"
							>
								<input
									autoComplete="off"
									className="form-control"
									value={telegram.apiUrl}
									placeholder={EXAMPLE.api}
									onChange={(e) => set({ apiUrl: e.target.value.trim() })}
								/>
							</Field>
						</>
					)}
					<Field label="nginxions.notifications.language">
						<select
							className="form-select"
							value={config.language}
							onChange={(e) => set({ language: e.target.value as Language })}
						>
							<option value="ru">{t("nginxions.notifications.language.ru")}</option>
							<option value="en">{t("nginxions.notifications.language.en")}</option>
						</select>
					</Field>
				</form>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" isLoading={saving} disabled={!name.trim()} onClick={save}>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showChannelModal = (type: ChannelType, channel?: Channel) =>
	EasyModal.show(ChannelModal, { type, channel });
