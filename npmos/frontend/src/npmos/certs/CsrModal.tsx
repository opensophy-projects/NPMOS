// Certificates → Add → ACME with your own CSR: the request and its key come from elsewhere (a key type, subject or
// extensions NPMOS does not choose); the ACME server of Settings → ACME signs it, NPMOS renews it with the same CSR.
import { useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Field, Form, Formik, useFormikContext } from "formik";
import { type ChangeEvent, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import * as api from "src/api/backend/base";
import { Button, DNSProviderFields } from "src/components";
import { T } from "src/locale";
import { showObjectSuccess } from "src/notifications";
import { AcmeLogButton } from "./AcmeLog";

interface CsrInfo {
	names: string[];
	keyType: string;
	subject: string;
}

interface Values {
	csr: string;
	key: string;
	meta: {
		dnsChallenge: boolean;
		dnsProvider?: string;
		dnsProviderCredentials?: string;
		propagationSeconds?: string | number;
	};
}

const body = (v: Values) => ({
	csr: v.csr,
	key: v.key,
	meta: v.meta.dnsChallenge
		? {
				dnsChallenge: true,
				dnsProvider: v.meta.dnsProvider,
				dnsProviderCredentials: v.meta.dnsProviderCredentials,
				propagationSeconds:
					v.meta.propagationSeconds === "" || v.meta.propagationSeconds === undefined
						? null
						: Number(v.meta.propagationSeconds),
			}
		: {},
});

/** a PEM field with "From file" */
function PemField({ name, label, hint, rows }: { name: "csr" | "key"; label: string; hint: string; rows: number }) {
	const { setFieldValue } = useFormikContext<Values>();
	const load = async (e: ChangeEvent<HTMLInputElement>) => {
		const file = e.target.files?.[0];
		if (file) setFieldValue(name, await file.text());
		e.target.value = "";
	};
	return (
		<div className="mb-3">
			<div className="d-flex align-items-end mb-1">
				<label className="form-label mb-0" htmlFor={`csr-${name}`}>
					<T id={label} />
				</label>
				<label className="btn btn-sm ms-auto mb-0">
					<T id="npmos.acme.csr.from-file" />
					<input type="file" accept=".pem,.csr,.key,.txt" className="d-none" onChange={load} />
				</label>
			</div>
			<Field
				as="textarea"
				id={`csr-${name}`}
				name={name}
				rows={rows}
				spellCheck={false}
				autoComplete="off"
				className="form-control font-monospace small"
				placeholder={name === "csr" ? "-----BEGIN CERTIFICATE REQUEST-----" : "-----BEGIN PRIVATE KEY-----"}
			/>
			<div className="form-hint">
				<T id={hint} />
			</div>
		</div>
	);
}

const CsrModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const queryClient = useQueryClient();
	const [error, setError] = useState<string | null>(null);
	const [info, setInfo] = useState<CsrInfo | null>(null);
	const [checking, setChecking] = useState(false);

	const check = async (v: Values) => {
		setChecking(true);
		setError(null);
		try {
			setInfo((await api.post({ url: "/npmos/acme/csr/check", data: { csr: v.csr, key: v.key } })) as CsrInfo);
		} catch (err: any) {
			setInfo(null);
			setError(err.message);
		}
		setChecking(false);
	};

	const submit = async (v: Values, { setSubmitting }: any) => {
		setError(null);
		try {
			await api.post({ url: "/npmos/acme/csr", data: body(v) });
			showObjectSuccess("certificate", "saved");
			queryClient.invalidateQueries({ queryKey: ["certificates"] });
			queryClient.invalidateQueries({ queryKey: ["npmos-certificates"] });
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setSubmitting(false);
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Formik<Values> initialValues={{ csr: "", key: "", meta: { dnsChallenge: false } }} onSubmit={submit}>
				{({ values, isSubmitting, setFieldValue }) => (
					<Form autoComplete="off">
						<Modal.Header closeButton>
							<Modal.Title>
								<T id="npmos.acme.csr.title" />
							</Modal.Title>
						</Modal.Header>
						<Modal.Body>
							<p className="text-secondary small">
								<T id="npmos.acme.csr.intro" />
							</p>
							<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
								<div className="text-break">{error}</div>
								{error && <AcmeLogButton />}
							</Alert>
							<PemField name="csr" label="npmos.acme.csr.csr" hint="npmos.acme.csr.csr.hint" rows={6} />
							<PemField name="key" label="npmos.acme.csr.key" hint="npmos.acme.csr.key.hint" rows={4} />
							<div className="d-flex align-items-center gap-2 mb-3">
								<Button
									type="button"
									onClick={() => check(values)}
									isLoading={checking}
									disabled={!values.csr || !values.key || checking}
								>
									<T id="npmos.acme.csr.check" />
								</Button>
								{info && (
									<span className="small">
										<T id="npmos.acme.csr.names" data={{ names: info.names.join(", ") }} />
										{" · "}
										{info.keyType}
										{info.subject && <span className="text-secondary"> · {info.subject}</span>}
									</span>
								)}
							</div>
							<label className="form-check form-switch">
								<input
									className="form-check-input"
									type="checkbox"
									checked={values.meta.dnsChallenge}
									onChange={(e) => setFieldValue("meta.dnsChallenge", e.target.checked)}
								/>
								<span className="form-check-label">
									<T id="npmos.acme.csr.dns" />
								</span>
							</label>
							<div className="form-hint mb-2">
								<T
									id={
										values.meta.dnsChallenge
											? "npmos.acme.csr.dns.hint"
											: "npmos.acme.csr.http.hint"
									}
								/>
							</div>
							{values.meta.dnsChallenge && <DNSProviderFields />}
						</Modal.Body>
						<Modal.Footer>
							<Button onClick={remove} disabled={isSubmitting}>
								<T id="cancel" />
							</Button>
							<Button
								type="submit"
								actionType="primary"
								className="ms-auto"
								isLoading={isSubmitting}
								disabled={isSubmitting || !values.csr || !values.key}
							>
								<T id="npmos.acme.csr.submit" />
							</Button>
						</Modal.Footer>
					</Form>
				)}
			</Formik>
		</Modal>
	);
});

export const showCsrModal = () => EasyModal.show(CsrModal);
