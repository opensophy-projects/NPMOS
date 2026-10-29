// Import of a local_policy.yaml (v1beta1 or v1beta2): its objects and default policy. A dry run shows
// what will be created and updated; rules of hosts are not imported (hosts choose their objects).
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { type ImportResult, importPolicy } from "./api";

interface Props extends InnerModalProps {
	onImported: () => void;
}

function List({ label, items }: { label: string; items: string[] }) {
	if (!items.length) return null;
	return (
		<div className="mb-2">
			<strong>
				<T id={label} data={{ count: items.length }} />
			</strong>
			<div className="small font-monospace text-secondary">{items.join(", ")}</div>
		</div>
	);
}

const ImportModal = EasyModal.create(({ visible, remove, onImported }: Props) => {
	const [content, setContent] = useState("");
	const [plan, setPlan] = useState<ImportResult | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const run = async (dryRun: boolean) => {
		setBusy(true);
		setError(null);
		try {
			const result = await importPolicy(content, dryRun);
			if (dryRun || !result.applied) {
				setPlan(result);
			} else {
				showSuccess(intl.formatMessage({ id: "npmos.policy.imported" }));
				onImported();
				remove();
			}
		} catch (err: any) {
			setError(err.message);
		} finally {
			setBusy(false);
		}
	};

	const readFile = async (file?: File) => {
		if (!file) return;
		setContent(await file.text());
		setPlan(null);
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.policy.import" />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<p className="text-secondary small">
					<T id="npmos.policy.import.hint" />
				</p>
				{error && <Alert variant="danger">{error}</Alert>}
				<input
					type="file"
					accept=".yaml,.yml,text/yaml"
					className="form-control mb-2"
					aria-label={intl.formatMessage({ id: "npmos.policy.import.file" })}
					onChange={(e) => readFile(e.target.files?.[0])}
				/>
				<textarea
					className="form-control font-monospace"
					rows={10}
					aria-label={intl.formatMessage({ id: "npmos.policy.import.content" })}
					value={content}
					onChange={(e) => {
						setContent(e.target.value);
						setPlan(null);
					}}
				/>
				{plan && (
					<div className="mt-3">
						<List label="npmos.policy.import.create" items={plan.create} />
						<List label="npmos.policy.import.update" items={plan.update} />
						<List label="npmos.policy.import.skipped" items={plan.skipped} />
						{plan.policy && (
							<p className="mb-2">
								<T id="npmos.policy.import.policy" />
							</p>
						)}
						{plan.rules > 0 && (
							<p className="text-secondary small mb-2">
								<T id="npmos.policy.import.rules" data={{ count: plan.rules }} />
							</p>
						)}
						{plan.errors.length > 0 && (
							<Alert variant="danger" className="mb-0">
								<ul className="mb-0 ps-3">
									{plan.errors.map((e) => (
										<li key={e}>{e}</li>
									))}
								</ul>
							</Alert>
						)}
					</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				{plan && !plan.errors.length ? (
					<Button actionType="primary" isLoading={busy} onClick={() => run(false)}>
						<T id="npmos.policy.import.apply" />
					</Button>
				) : (
					<Button actionType="primary" isLoading={busy} disabled={!content.trim()} onClick={() => run(true)}>
						<T id="npmos.policy.import.check" />
					</Button>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showImportModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(ImportModal, props);
