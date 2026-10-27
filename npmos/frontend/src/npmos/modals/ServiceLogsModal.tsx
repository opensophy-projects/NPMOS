import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useEffect, useRef, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { Button, Loading } from "src/components";
import { T } from "src/locale";
import { useServiceLogs } from "../hooks";

const TAILS = [100, 500, 2000];

interface Props extends InnerModalProps {
	service: string;
}

const ServiceLogsModal = EasyModal.create(({ service, visible, remove }: Props) => {
	const [tail, setTail] = useState(TAILS[0]);
	const [follow, setFollow] = useState(true);
	const { data, isLoading, error } = useServiceLogs(service, tail, follow);
	const bottom = useRef<HTMLDivElement>(null);

	useEffect(() => {
		if (follow && data) {
			bottom.current?.scrollIntoView({ block: "end" });
		}
	}, [data, follow]);

	return (
		<Modal show={visible} onHide={remove} size="xl">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.services.logs-title" data={{ service }} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<div className="d-flex flex-wrap gap-3 mb-3 align-items-center">
					<select
						className="form-select form-select-sm w-auto"
						value={tail}
						onChange={(e) => setTail(Number.parseInt(e.target.value, 10))}
					>
						{TAILS.map((n) => (
							<option key={n} value={n}>
								{n}
							</option>
						))}
					</select>
					<label className="form-check form-switch m-0">
						<input
							className="form-check-input"
							type="checkbox"
							checked={follow}
							onChange={(e) => setFollow(e.target.checked)}
						/>
						<span className="form-check-label">
							<T id="npmos.services.follow" />
						</span>
					</label>
				</div>
				{error && <Alert variant="danger">{error.message}</Alert>}
				{isLoading && <Loading noLogo />}
				{data && (
					<pre className="mb-0" style={{ maxHeight: "60vh", overflow: "auto", whiteSpace: "pre-wrap" }}>
						{data.length === 0 && <T id="npmos.services.no-logs" />}
						{data.map((l) => l.line).join("\n")}
						<div ref={bottom} />
					</pre>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showServiceLogsModal = (service: string) => {
	EasyModal.show(ServiceLogsModal, { service });
};
