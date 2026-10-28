// Who changed a host and when: its entries in the audit log, newest first, with the settings
// each update changed (docs/ROADMAP.md, phase 2, hosts table).
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { Button, Loading } from "src/components";
import { intl, T } from "src/locale";
import type { HostChange, HostObjectType } from "../api";
import { useHostHistory } from "../hooks";
import { dateTime, timeAgo } from "../ui/time";
import styles from "./HostHistoryModal.module.css";

const ACTIONS = ["created", "updated", "enabled", "disabled", "deleted", "updated-waf"];

const wafLabel = (waf: NonNullable<HostChange["waf"]>) =>
	intl.formatMessage({
		id: !waf.enabled
			? "npmos.hosts.waf.off"
			: waf.mode === "prevent-learn"
				? "npmos.hosts.waf.prevent"
				: "npmos.hosts.waf.detect",
	});

interface Props extends InnerModalProps {
	type: HostObjectType;
	id: number;
	name: string;
}

const HostHistoryModal = EasyModal.create(({ type, id, name, visible, remove }: Props) => {
	const { data, isLoading, error } = useHostHistory(type, id);
	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.hosts.history" />
					<div className={styles.subject}>{name}</div>
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{isLoading && <Loading />}
				{error && <Alert variant="danger">{error.message}</Alert>}
				{data && !data.length && (
					<p className={styles.muted}>
						<T id="npmos.hosts.history.empty" />
					</p>
				)}
				{data && data.length > 0 && (
					<ol className={styles.list}>
						{data.map((change) => (
							<li key={change.id} className={styles.item}>
								<div className={styles.when} title={dateTime(change.createdOn)}>
									{timeAgo(change.createdOn)}
								</div>
								<div className={styles.what}>
									<div>
										<strong>{change.user?.name ?? <T id="npmos.hosts.history.system" />}</strong>{" "}
										<T
											id={
												ACTIONS.includes(change.action)
													? `npmos.hosts.history.action.${change.action}`
													: "npmos.hosts.history.action.other"
											}
											data={{ action: change.action }}
										/>
										{change.waf && <span className={styles.value}>{wafLabel(change.waf)}</span>}
									</div>
									{change.fields.length > 0 && (
										<div className={styles.fields}>
											{change.fields.map((field) => (
												<code key={field}>{field}</code>
											))}
										</div>
									)}
								</div>
							</li>
						))}
					</ol>
				)}
				<p className={styles.note}>
					<T id="npmos.hosts.history.note" />
				</p>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showHostHistoryModal = (type: HostObjectType, id: number, name: string) =>
	EasyModal.show(HostHistoryModal, { type, id, name } as Omit<Props, "visible" | "remove">);
