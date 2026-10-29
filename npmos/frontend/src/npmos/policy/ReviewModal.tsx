// A change of WAF → Policy that is not an object form (default policy, delete, objects of a host):
// what local_policy.yaml becomes, then apply.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { T } from "src/locale";
import { type Change, type Preview, previewChange } from "./api";
import { Review } from "./Review";

interface Props extends InnerModalProps {
	change: Change;
	/** locale key of the title */
	title: string;
	onApply: () => Promise<void>;
}

const ReviewModal = EasyModal.create(({ visible, remove, change, title, onApply }: Props) => {
	const [preview, setPreview] = useState<Preview | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	useEffect(() => {
		previewChange(change)
			.then(setPreview)
			.catch((err) => setError(err.message));
	}, [change]);

	const apply = async () => {
		setBusy(true);
		setError(null);
		try {
			await onApply();
			remove();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={title} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				{preview ? (
					<Review preview={preview} />
				) : (
					!error && (
						<div className="text-secondary">
							<T id="npmos.policy.previewing" />
						</div>
					)
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" isLoading={busy} disabled={!preview?.valid} onClick={apply}>
					<T id="npmos.policy.apply" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showReviewModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(ReviewModal, props);
