// How long security events are kept (setting events.retention), next to the events they apply to.
import { IconDatabase } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { setEventsSettings } from "../../api";
import { useEventsSettings } from "../../hooks";
import { Popover } from "../../ui/Popover";
import { dateTime } from "../../ui/time";
import hostStyles from "../Hosts/Hosts.module.css";
import styles from "./Events.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const size = (bytes: number) =>
	bytes >= 1024 ** 3
		? `${(bytes / 1024 ** 3).toFixed(1)} GB`
		: bytes >= 1024 ** 2
			? `${(bytes / 1024 ** 2).toFixed(1)} MB`
			: `${Math.ceil(bytes / 1024)} KB`;

export function RetentionForm({ canManage, close }: { canManage: boolean; close?: () => void }) {
	const queryClient = useQueryClient();
	const { data } = useEventsSettings();
	const [days, setDays] = useState("");
	const [aggregateDays, setAggregateDays] = useState("");
	const [requestDays, setRequestDays] = useState("");
	const [busy, setBusy] = useState(false);

	useEffect(() => {
		if (data) {
			setDays(String(data.retention.days));
			setAggregateDays(String(data.retention.aggregateDays));
			setRequestDays(String(data.retention.requestDays ?? 7));
		}
	}, [data]);

	if (!data) return <div className="spinner-border spinner-border-sm text-secondary" />;

	const d = Number.parseInt(days, 10);
	const a = Number.parseInt(aggregateDays, 10);
	const r = Number.parseInt(requestDays, 10);
	const valid = d >= 1 && d <= 365 && a >= d && a <= 1830 && r >= 1 && r <= 90 && r <= a;
	const changed =
		d !== data.retention.days || a !== data.retention.aggregateDays || r !== (data.retention.requestDays ?? 7);

	const save = async () => {
		setBusy(true);
		try {
			const result = await setEventsSettings({ days: d, aggregateDays: a, requestDays: r });
			queryClient.setQueryData(["npmos-events-settings"], result);
			queryClient.invalidateQueries({ queryKey: ["npmos-events"] });
			queryClient.invalidateQueries({ queryKey: ["npmos-traffic"] });
			showSuccess(t("npmos.events.retention.saved"));
			close?.();
		} catch (err: any) {
			showError(err.message);
		} finally {
			setBusy(false);
		}
	};

	return (
		<div>
			<div className={styles.retention}>
				<label htmlFor="npmos-retention-days">
					<T id="npmos.events.retention.days" />
				</label>
				<input
					id="npmos-retention-days"
					type="number"
					min={1}
					max={365}
					className="form-control form-control-sm"
					value={days}
					disabled={!canManage}
					onChange={(e) => setDays(e.target.value)}
				/>
				<label htmlFor="npmos-retention-aggregates">
					<T id="npmos.events.retention.aggregate-days" />
				</label>
				<input
					id="npmos-retention-aggregates"
					type="number"
					min={1}
					max={1830}
					className="form-control form-control-sm"
					value={aggregateDays}
					disabled={!canManage}
					onChange={(e) => setAggregateDays(e.target.value)}
				/>
				<label htmlFor="npmos-retention-requests">
					<T id="npmos.events.retention.request-days" />
				</label>
				<input
					id="npmos-retention-requests"
					type="number"
					min={1}
					max={90}
					className="form-control form-control-sm"
					value={requestDays}
					disabled={!canManage}
					onChange={(e) => setRequestDays(e.target.value)}
				/>
			</div>
			{!valid && (
				<div className="text-danger small mt-2">
					<T id="npmos.events.retention.invalid" />
				</div>
			)}
			<div className={styles.facts}>
				<T id="npmos.events.retention.stored" data={{ events: data.storage.events }} />
				{data.storage.bytes !== null && ` · ${size(data.storage.bytes)}`}
				<div>
					<T id="npmos.events.retention.requests-stored" data={{ requests: data.storage.requests ?? 0 }} />
				</div>
				{data.storage.oldest && (
					<div>
						<T id="npmos.events.retention.oldest" data={{ time: dateTime(data.storage.oldest) }} />
					</div>
				)}
				<div>
					<T id="npmos.events.retention.hint" />
				</div>
			</div>
			{canManage && (
				<div className="mt-3 text-end">
					<Button
						size="sm"
						actionType="primary"
						disabled={!valid || !changed}
						isLoading={busy}
						onClick={save}
					>
						<T id="save" />
					</Button>
				</div>
			)}
		</div>
	);
}

export function RetentionPopover({ canManage }: { canManage: boolean }) {
	return (
		<Popover
			ariaLabel={t("npmos.events.retention")}
			title={<T id="npmos.events.retention" />}
			width="22rem"
			triggerClassName={hostStyles.tool}
			activeClassName={hostStyles.toolOn}
			trigger={
				<>
					<IconDatabase size={16} />
					<span className={hostStyles.toolText}>
						<T id="npmos.events.retention" />
					</span>
				</>
			}
		>
			{(close) => <RetentionForm canManage={canManage} close={close} />}
		</Popover>
	);
}
