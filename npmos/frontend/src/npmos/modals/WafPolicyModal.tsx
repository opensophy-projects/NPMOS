// The generated local_policy.yaml, read-only (it is rebuilt from the WAF settings of the hosts).
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { Button, Loading } from "src/components";
import { T } from "src/locale";
import { useWafPolicy } from "../hooks";

const WafPolicyModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const { data, isLoading, error } = useWafPolicy();
	return (
		<Modal show={visible} onHide={remove} size="xl">
			<Modal.Header closeButton>
				<Modal.Title>local_policy.yaml</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{isLoading && <Loading noLogo />}
				{error && <Alert variant="danger">{error.message}</Alert>}
				{data && (
					<>
						<p className="text-secondary">
							<T id="npmos.waf.policy-readonly" /> <code>{data.file}</code>
						</p>
						<pre className="mb-0" style={{ maxHeight: "65vh", overflow: "auto" }}>
							{data.content ?? "—"}
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

export const showWafPolicyModal = () => EasyModal.show(WafPolicyModal, {});
