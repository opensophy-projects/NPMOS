// What the agent learned on a host (Agents → open-appsec → Learning): the statistics of the tuning service and what
// the WAF counts as normal per parameter (indicators and types of values, also from trusted sources).
import { useQuery } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { dateTime } from "../ui/time";
import { getLearned, type LearnedAsset, type LearnedParam, type LearningHost } from "./api";
import styles from "./Learning.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const KINDS = ["indicators", "types", "trustedIndicators", "trustedTypes"] as const;
const SHOWN = 50;

function Params({ params }: { params: LearnedParam[] }) {
	const [all, setAll] = useState(false);
	const shown = all ? params : params.slice(0, SHOWN);
	return (
		<>
			<table className="table table-sm">
				<tbody>
					{shown.map((p) => (
						<tr key={p.param}>
							<td className={styles.learnedParam}>{p.param}</td>
							<td>
								<code>{p.values.join(", ")}</code>
							</td>
						</tr>
					))}
				</tbody>
			</table>
			{params.length > SHOWN && !all && (
				<button type="button" className="btn btn-sm" onClick={() => setAll(true)}>
					<T id="nginxions.learning.learned.more" data={{ count: params.length - SHOWN }} />
				</button>
			)}
		</>
	);
}

function Asset({ asset }: { asset: LearnedAsset }) {
	const empty = KINDS.every((k) => !asset[k]?.length);
	return (
		<div className="mb-4">
			<h4>
				{asset.asset}
				{asset.updatedOn && (
					<span className={styles.muted}>
						{" "}
						<T id="nginxions.learning.learned.updated" data={{ time: dateTime(asset.updatedOn) }} />
					</span>
				)}
			</h4>
			{empty ? (
				<p className="text-secondary small">
					<T id="nginxions.learning.learned.nothing" />
				</p>
			) : (
				KINDS.filter((k) => asset[k]?.length).map((k) => (
					<div key={k} className="mb-2">
						<div className="fw-bold small">
							<T id={`nginxions.learning.learned.${k}`} data={{ count: asset[k]?.length ?? 0 }} />
						</div>
						<Params params={asset[k] ?? []} />
					</div>
				))
			)}
		</div>
	);
}

interface Props extends InnerModalProps {
	host: LearningHost;
}

const LearnedModal = EasyModal.create(({ host, visible, remove }: Props) => {
	const { data, isLoading, error } = useQuery({
		queryKey: ["nginxions-learning-learned", host.id],
		queryFn: () => getLearned(host.id),
	});
	const stats = data?.stats;
	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="nginxions.learning.learned.title" data={{ name: host.name }} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{isLoading ? (
					<LoadingPage noLogo />
				) : error ? (
					<Alert variant="danger">{(error as Error).message}</Alert>
				) : (
					<>
						{data?.error && (
							<Alert variant="warning">
								<T id="nginxions.learning.learned.error" data={{ error: data.error }} />
							</Alert>
						)}
						<p className="text-secondary">
							<T id="nginxions.learning.learned.text" />
						</p>
						{stats && (
							<p>
								<T
									id="nginxions.learning.learned.stats"
									data={{
										requests: stats.requests,
										sources: stats.sources ?? 0,
										urls: stats.urls ?? 0,
										legitimate: stats.legitimate ?? 0,
										readiness: t(`nginxions.learning.readiness.${stats.readiness}`),
									}}
								/>
							</p>
						)}
						{data?.assets.length ? (
							data.assets.map((a) => <Asset key={a.asset} asset={a} />)
						) : (
							<p className="text-secondary mb-0">
								<T id="nginxions.learning.learned.none" />
							</p>
						)}
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="nginxions.common.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showLearnedModal = (props: Omit<Props, keyof InnerModalProps>) => {
	EasyModal.show(LearnedModal, props);
};
