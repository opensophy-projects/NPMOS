import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { T } from "src/locale";

interface ShowProps {
	tTitle: string;
	children: ReactNode;
	tConfirm: string;
	danger?: boolean;
	onConfirm: () => Promise<unknown> | unknown;
}

interface Props extends InnerModalProps, ShowProps {}

const ConfirmModal = EasyModal.create(({ tTitle, children, tConfirm, danger, onConfirm, visible, remove }: Props) => {
	const [error, setError] = useState<string | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);

	const onSubmit = async () => {
		if (isSubmitting) return;
		setIsSubmitting(true);
		setError(null);
		try {
			await onConfirm();
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setIsSubmitting(false);
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={tTitle} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
					{error}
				</Alert>
				{children}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={isSubmitting}>
					<T id="cancel" />
				</Button>
				<Button
					actionType="primary"
					className={danger ? "ms-auto btn-red" : "ms-auto"}
					isLoading={isSubmitting}
					disabled={isSubmitting}
					onClick={onSubmit}
				>
					<T id={tConfirm} />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showConfirmModal = (props: ShowProps) => {
	EasyModal.show(ConfirmModal, props);
};
