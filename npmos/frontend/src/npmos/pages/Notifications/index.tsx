// System → Notifications (docs/ROADMAP.md, phase 4; ADR-11): channels (email, webhook, Telegram),
// rules (attack spike, agent down, policy not applied, service down, certificates, nginx errors of
// hosts) and the last deliveries.
import { IconDots, IconMail, IconPencil, IconPlus, IconSend, IconTrash, IconWebhook } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import Alert from "react-bootstrap/Alert";
import { HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { showConfirmModal } from "../../modals/ConfirmModal";
import {
	type Channel,
	type ChannelType,
	deleteChannel,
	deleteRule,
	getNotifications,
	type Notifications,
	type Rule,
	testChannel,
	updateChannel,
	updateRule,
} from "../../notifications/api";
import { showChannelModal } from "../../notifications/ChannelModal";
import { showRuleModal } from "../../notifications/RuleModal";
import { useCan } from "../../rbac/hooks";
import { Dropdown } from "../../ui/Dropdown";
import { dateTime } from "../../ui/time";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "./Notifications.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const CHANNEL_ICON: Record<ChannelType, React.ReactNode> = {
	email: <IconMail size={16} />,
	webhook: <IconWebhook size={16} />,
	telegram: <IconSend size={16} />,
};

/** where a channel delivers, without secrets */
const channelTarget = (c: Channel) => {
	const config = c.config as any;
	if (c.type === "email") return `${config.to.join(", ")} · ${config.host}:${config.port}`;
	if (c.type === "webhook") return config.url;
	return `chat ${config.chatId}`;
};

/** short description of a rule's parameters */
const ruleParams = (r: Rule) => {
	const p = r.params;
	switch (r.type) {
		case "attack_spike":
			return t("npmos.notifications.rule.attack_spike.params", {
				threshold: p.threshold,
				window: p.window,
				host: p.host || t("npmos.analytics.all-hosts"),
			});
		case "agent_down":
			return t("npmos.notifications.rule.agent_down.params", { minutes: p.minutes });
		case "cert_expiry":
			return t("npmos.notifications.rule.cert_expiry.params", { days: p.days });
		default:
			return "";
	}
};

function NotificationsPage() {
	const can = useCan();
	const manage = can("notifications", "manage");
	const queryClient = useQueryClient();
	const { data, isLoading, isError, error } = useQuery<Notifications, Error>({
		queryKey: ["npmos-notifications"],
		queryFn: getNotifications,
		refetchInterval: 15000,
	});
	const refresh = () => queryClient.invalidateQueries({ queryKey: ["npmos-notifications"] });

	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;

	const channelName = (id: number | null) => data.channels.find((c) => c.id === id)?.name ?? "—";
	const ruleName = (id: number | null) => data.rules.find((r) => r.id === id)?.name ?? "—";

	const run = async (action: () => Promise<unknown>, message?: string) => {
		try {
			await action();
			if (message) showSuccess(message);
		} catch (err: any) {
			showError(err.message);
		}
		refresh();
	};

	const test = (c: Channel) =>
		run(async () => {
			const result = await testChannel(c.id);
			if (result.ok) showSuccess(t("npmos.notifications.test.ok", { name: c.name }));
			else showError(t("npmos.notifications.test.failed", { name: c.name, error: result.error }));
		});

	const remove = (kind: "channel" | "rule", name: string, action: () => Promise<unknown>) =>
		showConfirmModal({
			tTitle: `npmos.notifications.${kind}.delete`,
			tConfirm: `npmos.notifications.${kind}.delete`,
			danger: true,
			children: (
				<p>
					<T id={`npmos.notifications.${kind}.delete.text`} data={{ name }} />
				</p>
			),
			onConfirm: () => run(action, t("npmos.notifications.deleted")),
		});

	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.notifications" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.notifications.subtitle" />
					</p>
				</div>
			</div>

			<section className={cn("card", styles.card)}>
				<div className={styles.cardHead}>
					<h2 className={styles.cardTitle}>
						<T id="npmos.notifications.channels" />
					</h2>
					{manage && (
						<Dropdown
							floating
							inline
							ariaLabel={t("npmos.notifications.channel.add")}
							triggerClassName={cn("btn btn-primary btn-sm", hostStyles.add)}
							trigger={
								<>
									<IconPlus size={16} />
									<T id="npmos.notifications.channel.add" />
								</>
							}
							items={data.channelTypes.map((type) => ({
								key: type,
								icon: CHANNEL_ICON[type],
								label: t(`npmos.notifications.channel.${type}`),
								onSelect: () => showChannelModal(type),
							}))}
						/>
					)}
				</div>
				{data.channels.length === 0 ? (
					<p className={styles.empty}>
						<T id="npmos.notifications.channels.none" />
					</p>
				) : (
					<ul className={styles.list}>
						{data.channels.map((c) => (
							<li key={c.id} className={styles.item}>
								<span className={styles.icon}>{CHANNEL_ICON[c.type]}</span>
								<div className={styles.main}>
									<div className={styles.name}>
										{c.name}
										{!c.enabled && (
											<span className="badge bg-secondary-lt ms-2">
												<T id="npmos.notifications.off" />
											</span>
										)}
									</div>
									<div className={styles.sub}>
										<T id={`npmos.notifications.channel.${c.type}`} /> · {channelTarget(c)}
									</div>
								</div>
								{manage && (
									<>
										<button type="button" className={hostStyles.tool} onClick={() => test(c)}>
											<IconSend size={16} />
											<span className={hostStyles.toolText}>
												<T id="npmos.notifications.test" />
											</span>
										</button>
										<Dropdown
											floating
											inline
											ariaLabel={t("npmos.notifications.actions")}
											triggerClassName={styles.more}
											trigger={<IconDots size={16} />}
											items={[
												{
													key: "edit",
													icon: <IconPencil size={16} />,
													label: t("npmos.notifications.edit"),
													onSelect: () => showChannelModal(c.type, c),
												},
												{
													key: "toggle",
													label: t(
														c.enabled
															? "npmos.notifications.disable"
															: "npmos.notifications.enable",
													),
													onSelect: () =>
														run(() => updateChannel(c.id, { enabled: !c.enabled })),
												},
												{
													key: "delete",
													divider: true,
													icon: <IconTrash size={16} />,
													label: t("npmos.notifications.delete"),
													onSelect: () =>
														remove("channel", c.name, () => deleteChannel(c.id)),
												},
											]}
										/>
									</>
								)}
							</li>
						))}
					</ul>
				)}
			</section>

			<section className={cn("card", styles.card)}>
				<div className={styles.cardHead}>
					<h2 className={styles.cardTitle}>
						<T id="npmos.notifications.rules" />
					</h2>
					{manage && (
						<button
							type="button"
							className={cn("btn btn-primary btn-sm", hostStyles.add)}
							onClick={() => showRuleModal(data)}
						>
							<IconPlus size={16} />
							<T id="npmos.notifications.rule.add" />
						</button>
					)}
				</div>
				{data.rules.length === 0 ? (
					<p className={styles.empty}>
						<T id="npmos.notifications.rules.none" />
					</p>
				) : (
					<ul className={styles.list}>
						{data.rules.map((r) => (
							<li key={r.id} className={styles.item}>
								<label className="form-check form-switch m-0" title={t("npmos.notifications.enabled")}>
									<input
										type="checkbox"
										className="form-check-input"
										checked={r.enabled}
										disabled={!manage}
										aria-label={t("npmos.notifications.enabled")}
										onChange={(e) => run(() => updateRule(r.id, { enabled: e.target.checked }))}
									/>
								</label>
								<div className={styles.main}>
									<div className={styles.name}>
										{r.name}
										{r.active.length > 0 && (
											<span className="badge bg-red-lt ms-2">
												<T id="npmos.notifications.active" data={{ n: r.active.length }} />
											</span>
										)}
									</div>
									<div className={styles.sub}>
										<T id={`npmos.notifications.rule.${r.type}`} />
										{ruleParams(r) && ` · ${ruleParams(r)}`}
										{" → "}
										{r.channelIds.length
											? r.channelIds.map(channelName).join(", ")
											: t("npmos.notifications.rule.no-channels")}
									</div>
								</div>
								{manage && (
									<Dropdown
										floating
										inline
										ariaLabel={t("npmos.notifications.actions")}
										triggerClassName={styles.more}
										trigger={<IconDots size={16} />}
										items={[
											{
												key: "edit",
												icon: <IconPencil size={16} />,
												label: t("npmos.notifications.edit"),
												onSelect: () => showRuleModal(data, r),
											},
											{
												key: "delete",
												divider: true,
												icon: <IconTrash size={16} />,
												label: t("npmos.notifications.delete"),
												onSelect: () => remove("rule", r.name, () => deleteRule(r.id)),
											},
										]}
									/>
								)}
							</li>
						))}
					</ul>
				)}
			</section>

			<section className={cn("card", styles.card)}>
				<div className={styles.cardHead}>
					<h2 className={styles.cardTitle}>
						<T id="npmos.notifications.log" />
					</h2>
				</div>
				{data.log.length === 0 ? (
					<p className={styles.empty}>
						<T id="npmos.notifications.log.none" />
					</p>
				) : (
					<div className={hostStyles.scroller}>
						<table className={cn("table table-vcenter card-table", hostStyles.table)}>
							<tbody>
								{data.log.map((l) => (
									<tr key={l.id}>
										<td className="text-secondary">{dateTime(l.createdOn)}</td>
										<td>
											<span
												className={cn(
													"badge",
													l.status === "firing"
														? "bg-red-lt"
														: l.status === "resolved"
															? "bg-green-lt"
															: "bg-secondary-lt",
												)}
											>
												<T id={`npmos.notifications.status.${l.status}`} />
											</span>
										</td>
										<td className={styles.title}>{l.title}</td>
										<td className="text-secondary">{l.ruleId ? ruleName(l.ruleId) : ""}</td>
										<td>{channelName(l.channelId)}</td>
										<td>
											{l.ok ? (
												<span className="text-green">
													<T id="npmos.notifications.delivered" />
												</span>
											) : (
												<span className="text-red" title={l.error}>
													<T id="npmos.notifications.failed" /> {l.error}
												</span>
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</section>
		</div>
	);
}

const NotificationsRoute = () => (
	<HasPermission rbac="notifications" permission={VIEW} pageLoading loadingNoLogo>
		<NotificationsPage />
	</HasPermission>
);

export default NotificationsRoute;
