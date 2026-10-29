// Hosts of a role of scope "hosts": its members see their own hosts and these.
import { useQueries } from "@tanstack/react-query";
import { useState } from "react";
import * as api from "src/api/backend/base";
import { intl, T } from "src/locale";
import type { RoleHost, RoleHostType } from "./api";
import styles from "./RoleModal.module.css";

const SOURCES: { type: RoleHostType; url: string; object: string }[] = [
	{ type: "proxy_host", url: "/nginx/proxy-hosts", object: "proxy-host" },
	{ type: "redirection_host", url: "/nginx/redirection-hosts", object: "redirection-host" },
	{ type: "dead_host", url: "/nginx/dead-hosts", object: "dead-host" },
	{ type: "stream", url: "/nginx/streams", object: "stream" },
];

const t = (id: string) => intl.formatMessage({ id });

const label = (host: any) => (host.domainNames?.length ? host.domainNames.join(", ") : `:${host.incomingPort}`);

export function HostPicker({
	value,
	disabled,
	onChange,
}: {
	value: RoleHost[];
	disabled?: boolean;
	onChange: (hosts: RoleHost[]) => void;
}) {
	const [filter, setFilter] = useState("");
	const lists = useQueries({
		queries: SOURCES.map((s) => ({
			queryKey: ["npmos-rbac-hosts", s.type],
			queryFn: () => api.get({ url: s.url }) as Promise<any[]>,
			staleTime: 30000,
		})),
	});
	const has = (type: RoleHostType, id: number) => value.some((h) => h.hostType === type && h.hostId === id);
	const toggle = (type: RoleHostType, id: number, on: boolean) =>
		onChange(
			on
				? [...value, { hostType: type, hostId: id }]
				: value.filter((h) => !(h.hostType === type && h.hostId === id)),
		);
	const q = filter.trim().toLowerCase();

	return (
		<div className={styles.field}>
			<span>
				<T id="npmos.rbac.hosts" data={{ count: value.length }} />
			</span>
			<input
				className="form-control form-control-sm mb-2"
				type="search"
				value={filter}
				disabled={disabled}
				onChange={(e) => setFilter(e.target.value)}
				placeholder={t("npmos.rbac.hosts.filter")}
			/>
			<div className={styles.hostList}>
				{SOURCES.map((s, i) => {
					const hosts = (lists[i].data ?? []).filter((h) => !q || label(h).toLowerCase().includes(q));
					if (!hosts.length) return null;
					return (
						<div key={s.type}>
							<div className={styles.hostGroup}>
								<T id={s.object} />
							</div>
							{hosts.map((h) => (
								<label key={h.id} className="form-check mb-1">
									<input
										type="checkbox"
										className="form-check-input"
										checked={has(s.type, h.id)}
										disabled={disabled}
										onChange={(e) => toggle(s.type, h.id, e.target.checked)}
									/>
									<span className="form-check-label">{label(h)}</span>
								</label>
							))}
						</div>
					);
				})}
			</div>
		</div>
	);
}
