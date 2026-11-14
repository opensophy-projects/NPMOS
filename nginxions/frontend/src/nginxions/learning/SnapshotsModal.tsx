// Snapshots of what the agent learned (Agents → open-appsec → Learning): taken every day and on demand, compared with
// the one before (a sharp shift of the norm of an asset can be poisoning), restored in place of the learned state,
// downloaded for a backup and uploaded on another NginxionS.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { showConfirmModal } from "../modals/ConfirmModal";
import { dateTime } from "../ui/time";
import {
	deleteLearningSnapshot,
	downloadLearningSnapshot,
	getLearningSnapshots,
	type LearningSnapshot,
	restoreLearningSnapshot,
	takeLearningSnapshot,
	uploadLearningSnapshot,
} from "./api";
import styles from "./Learning.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
export const SNAPSHOTS_KEY = "nginxions-learning-snapshots";

const size = (bytes: number) =>
	bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;

/** the shift of a snapshot from the one before, one line per asset */
export function ShiftList({ snapshot }: { snapshot: LearningSnapshot }) {
	return (
		<ul className="mb-0">
			{snapshot.shift.map((s) => (
				<li key={s.asset}>
					<T
						id={`nginxions.learning.snapshots.shift.${s.direction}`}
						data={{ asset: s.asset, before: s.before, after: s.after }}
					/>
				</li>
			))}
		</ul>
	);
}

interface Props extends InnerModalProps {
	/** takes and downloads (waf_learning:label) */
	label: boolean;
	/** restores, uploads, deletes (also waf_policy:manage) */
	manage: boolean;
}

const SnapshotsModal = EasyModal.create(({ label, manage, visible, remove }: Props) => {
	const queryClient = useQueryClient();
	const { data, isLoading, error } = useQuery({ queryKey: [SNAPSHOTS_KEY], queryFn: getLearningSnapshots });
	const [failure, setFailure] = useState<string | null>(null);
	const [busy, setBusy] = useState<string | null>(null);
	const fileRef = useRef<HTMLInputElement>(null);
	const refresh = () => queryClient.invalidateQueries({ queryKey: [SNAPSHOTS_KEY] });

	const run = async (key: string, action: () => Promise<unknown>, done?: string) => {
		setBusy(key);
		setFailure(null);
		try {
			await action();
			if (done) showSuccess(t(done));
			refresh();
		} catch (err: any) {
			setFailure(err.message);
		}
		setBusy(null);
	};

	const restore = (s: LearningSnapshot) =>
		showConfirmModal({
			tTitle: "nginxions.learning.snapshots.restore.title",
			tConfirm: "nginxions.learning.snapshots.restore",
			danger: true,
			onConfirm: () =>
				run(`restore-${s.id}`, () => restoreLearningSnapshot(s.id), "nginxions.learning.snapshots.restored"),
			children: (
				<p className="mb-0">
					<T id="nginxions.learning.snapshots.restore.text" data={{ time: dateTime(s.takenOn) }} />
				</p>
			),
		});

	const removeSnapshot = (s: LearningSnapshot) =>
		showConfirmModal({
			tTitle: "nginxions.learning.snapshots.delete.title",
			tConfirm: "nginxions.common.remove",
			danger: true,
			onConfirm: () => run(`delete-${s.id}`, () => deleteLearningSnapshot(s.id)),
			children: (
				<p className="mb-0">
					<T id="nginxions.learning.snapshots.delete.text" data={{ time: dateTime(s.takenOn) }} />
				</p>
			),
		});

	const upload = (file: File | undefined) => {
		if (fileRef.current) fileRef.current.value = "";
		if (file) run("upload", () => uploadLearningSnapshot(file), "nginxions.learning.snapshots.uploaded");
	};

	return (
		<Modal show={visible} onHide={remove} size="xl">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="nginxions.learning.snapshots.title" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={!!(failure || error)} onClose={() => setFailure(null)} dismissible>
					{failure || (error as Error)?.message}
				</Alert>
				<p className="text-secondary">
					<T id="nginxions.learning.snapshots.text" data={{ keep: data?.keepAuto ?? 14 }} />
				</p>
				{isLoading ? (
					<LoadingPage noLogo />
				) : !data?.snapshots.length ? (
					<p className="text-secondary mb-0">
						<T id="nginxions.learning.snapshots.empty" />
					</p>
				) : (
					<div className="table-responsive">
						<table className="table table-vcenter table-sm">
							<thead>
								<tr>
									<th>
										<T id="nginxions.learning.snapshots.taken" />
									</th>
									<th>
										<T id="nginxions.learning.snapshots.reason" />
									</th>
									<th>
										<T id="nginxions.learning.snapshots.learned" />
									</th>
									<th>
										<T id="nginxions.learning.snapshots.shift" />
									</th>
									<th />
								</tr>
							</thead>
							<tbody>
								{data.snapshots.map((s) => (
									<tr key={s.id}>
										<td>
											{dateTime(s.takenOn)}
											<div className={styles.muted}>{size(s.size)}</div>
											{s.restoredOn && (
												<div className={styles.muted}>
													<T
														id="nginxions.learning.snapshots.restored-on"
														data={{ time: dateTime(s.restoredOn) }}
													/>
												</div>
											)}
										</td>
										<td>
											<T id={`nginxions.learning.snapshots.reason.${s.reason}`} />
											{s.sourceTakenOn && (
												<div className={styles.muted}>
													<T
														id="nginxions.learning.snapshots.source"
														data={{ time: dateTime(s.sourceTakenOn) }}
													/>
												</div>
											)}
										</td>
										<td>
											<T
												id="nginxions.learning.snapshots.learned.value"
												data={{
													assets: s.assets.length,
													values: s.assets.reduce((n, a) => n + a.values, 0),
												}}
											/>
										</td>
										<td>
											{s.shift.length ? (
												<span className="text-warning">
													<ShiftList snapshot={s} />
												</span>
											) : (
												<span className={styles.muted}>
													<T
														id={
															s.comparedWith
																? "nginxions.learning.snapshots.shift.none"
																: "nginxions.learning.snapshots.shift.first"
														}
													/>
												</span>
											)}
										</td>
										<td className="text-end text-nowrap">
											{label && (
												<button
													type="button"
													className="btn btn-sm"
													onClick={() => downloadLearningSnapshot(s.id)}
												>
													<T id="nginxions.learning.snapshots.download" />
												</button>
											)}
											{manage && (
												<>
													<button
														type="button"
														className="btn btn-sm ms-1"
														disabled={!!busy}
														onClick={() => restore(s)}
													>
														<T id="nginxions.learning.snapshots.restore" />
													</button>
													<button
														type="button"
														className="btn btn-sm btn-ghost-danger ms-1"
														disabled={!!busy}
														onClick={() => removeSnapshot(s)}
													>
														<T id="nginxions.common.remove" />
													</button>
												</>
											)}
										</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="nginxions.common.close" />
				</Button>
				{manage && (
					<>
						<input
							ref={fileRef}
							type="file"
							accept=".gz,application/gzip"
							className="d-none"
							aria-label={t("nginxions.learning.snapshots.upload")}
							onChange={(e) => upload(e.target.files?.[0])}
						/>
						<Button
							className="ms-auto"
							isLoading={busy === "upload"}
							disabled={!!busy}
							onClick={() => fileRef.current?.click()}
						>
							<T id="nginxions.learning.snapshots.upload" />
						</Button>
					</>
				)}
				{label && (
					<Button
						actionType="primary"
						className={manage ? "" : "ms-auto"}
						isLoading={busy === "take"}
						disabled={!!busy}
						onClick={() => run("take", takeLearningSnapshot, "nginxions.learning.snapshots.taken-now")}
					>
						<T id="nginxions.learning.snapshots.take" />
					</Button>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showSnapshotsModal = (props: Omit<Props, keyof InnerModalProps>) => {
	EasyModal.show(SnapshotsModal, props);
};
