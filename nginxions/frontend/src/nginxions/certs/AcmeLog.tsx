// The full log of the last failed ACME request (certbot output and its debug log, secrets masked): the error in a
// form shows only the gist, the log shows every step of the request.
import { useQuery } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useFormikContext } from "formik";
import Modal from "react-bootstrap/Modal";
import * as api from "src/api/backend/base";
import { Button, Loading } from "src/components";
import { formatDateTime, T } from "src/locale";

const getLastLog = () => api.get({ url: "/nginxions/acme/last-log" }) as Promise<{ log: string | null; time?: string }>;

const AcmeLogModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const { data, isLoading, error } = useQuery({
		queryKey: ["nginxions-acme-log"],
		queryFn: getLastLog,
		staleTime: 0,
	});
	return (
		<Modal show={visible} onHide={remove} size="xl">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="nginxions.acme.log.title" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{isLoading && <Loading noLogo />}
				{error && <p className="text-danger mb-0">{(error as Error).message}</p>}
				{data && !data.log && (
					<p className="text-secondary mb-0">
						<T id="nginxions.acme.log.none" />
					</p>
				)}
				{data?.log && (
					<>
						<p className="text-secondary small">
							<T id="nginxions.acme.log.time" data={{ time: formatDateTime(data.time ?? "") }} />
						</p>
						<pre className="mb-0 small" style={{ maxHeight: "60vh", whiteSpace: "pre-wrap" }}>
							<code>{data.log}</code>
						</pre>
					</>
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

export const showAcmeLogModal = () => EasyModal.show(AcmeLogModal);

/** under the error of a failed request */
export function AcmeLogButton() {
	return (
		<button type="button" className="btn btn-sm btn-outline-danger mt-2" onClick={showAcmeLogModal}>
			<T id="nginxions.acme.log.open" />
		</button>
	);
}

/** in the form of a host: the button, when the host asked for a new certificate */
export function AcmeLogIfRequested() {
	const { values } = useFormikContext<{ certificateId?: number | string }>();
	return values.certificateId === "new" ? <AcmeLogButton /> : null;
}
