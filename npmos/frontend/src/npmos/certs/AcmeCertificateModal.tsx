// Certificates → Add → ACME: one form for every ACME server of Settings → ACME (Let's Encrypt, ZeroSSL, Google, the
// TLS CA of the Russian Federation, a server of your own): the server, how the domain is checked (HTTP-01 or DNS-01)
// and the names. Your own CSR has its form (CsrModal), reached from here.
import { useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Field, Form, Formik } from "formik";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import { createCertificate, testHttpCertificate } from "src/api/backend";
import { Button, DomainNamesField } from "src/components";
import { T } from "src/locale";
import { showObjectSuccess } from "src/notifications";
import { AcmeDnsFields, AcmeServerField, useChosenAcmeServer } from "../acme/AcmeFields";
import { AcmeLogButton } from "./AcmeLog";
import { showCsrModal } from "./CsrModal";

export const showAcmeCertificateModal = () => {
	EasyModal.show(AcmeCertificateModal);
};

const TEST_MESSAGES: Record<string, string> = {
	ok: "certificates.http.reachability-ok",
	"no-host": "certificates.http.reachability-not-resolved",
	failed: "certificates.http.reachability-failed-to-check",
	"404": "certificates.http.reachability-404",
	"wrong-data": "certificates.http.reachability-wrong-data",
};

function ReuseKey() {
	const server = useChosenAcmeServer();
	// lego makes a new key for every certificate
	if (server?.client === "lego") return null;
	return (
		<Field name="meta.reuseKey">
			{({ field }: any) => (
				<label className="form-check form-switch mt-2">
					<input
						{...field}
						className={cn("form-check-input", { "bg-cyan": field.value })}
						type="checkbox"
						checked={!!field.value}
					/>
					<span className="form-check-label">
						<T id="domains.reuse-key" />
					</span>
				</label>
			)}
		</Field>
	);
}

const AcmeCertificateModal = EasyModal.create(({ visible, remove }: InnerModalProps) => {
	const queryClient = useQueryClient();
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);
	const [domains, setDomains] = useState<string[]>([]);
	const [isTesting, setIsTesting] = useState(false);
	const [testResults, setTestResults] = useState<{ domain: string; status: string }[] | null>(null);

	const onSubmit = async (values: any) => {
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);
		const meta = { ...values.meta };
		if (!meta.dnsChallenge) {
			delete meta.dnsProvider;
			delete meta.dnsProviderCredentials;
			delete meta.propagationSeconds;
		} else if (meta.propagationSeconds === "" || meta.propagationSeconds === undefined) {
			delete meta.propagationSeconds;
		} else {
			meta.propagationSeconds = Number(meta.propagationSeconds);
		}
		try {
			await createCertificate({ ...values, meta });
			showObjectSuccess("certificate", "saved");
			remove();
		} catch (err: any) {
			setErrorMsg(<T id={err.message} />);
		}
		queryClient.invalidateQueries({ queryKey: ["certificates"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-acme-servers"] });
		setIsSubmitting(false);
	};

	const handleTest = async () => {
		setIsTesting(true);
		setErrorMsg(null);
		setTestResults(null);
		try {
			setTestResults(await testHttpCertificate(domains));
		} catch (err: any) {
			setErrorMsg(<T id={err.message} />);
		}
		setIsTesting(false);
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Formik
				initialValues={
					{ domainNames: [], provider: "letsencrypt", meta: { dnsChallenge: false, reuseKey: false } } as any
				}
				onSubmit={onSubmit}
			>
				{({ values, setFieldValue }) => (
					<Form>
						<Modal.Header closeButton>
							<Modal.Title>
								<T id="npmos.acme.new" />
							</Modal.Title>
						</Modal.Header>
						<Modal.Body>
							<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
								{errorMsg}
								{errorMsg && <AcmeLogButton />}
							</Alert>
							<AcmeServerField />
							<div className="mb-3">
								<div className="form-label">
									<T id="npmos.acme.challenge" />
								</div>
								<div className="btn-group w-100" role="group">
									{[false, true].map((dns) => (
										<button
											key={String(dns)}
											type="button"
											className={cn(
												"btn",
												values.meta.dnsChallenge === dns
													? "btn-primary"
													: "btn-outline-secondary",
											)}
											onClick={() => {
												setFieldValue("meta.dnsChallenge", dns);
												setTestResults(null);
											}}
										>
											<T id={dns ? "npmos.acme.challenge.dns" : "npmos.acme.challenge.http"} />
										</button>
									))}
								</div>
								<div className="form-hint">
									<T
										id={
											values.meta.dnsChallenge
												? "npmos.acme.challenge.dns-hint"
												: "npmos.acme.challenge.http-hint"
										}
									/>
								</div>
							</div>
							<DomainNamesField
								isWildcardPermitted={values.meta.dnsChallenge}
								dnsProviderWildcardSupported={values.meta.dnsChallenge}
								onChange={(doms: string[]) => {
									setDomains(doms);
									setTestResults(null);
								}}
							/>
							{values.meta.dnsChallenge && <AcmeDnsFields showBoundaryBox />}
							<ReuseKey />
							{testResults && (
								<div className="mt-3">
									<h5>
										<T id="certificates.http.test-results" />
									</h5>
									{testResults.map(({ domain, status }) => (
										<p key={domain} className="mb-1">
											<strong>{domain}:</strong>{" "}
											{TEST_MESSAGES[status] ? (
												<T id={TEST_MESSAGES[status]} />
											) : (
												<T
													id="certificates.http.reachability-other"
													data={{ code: status.substring(6) }}
												/>
											)}
										</p>
									))}
								</div>
							)}
							<div className="mt-3 small">
								<button
									type="button"
									className="btn btn-link btn-sm p-0"
									onClick={() => {
										remove();
										showCsrModal();
									}}
								>
									<T id="npmos.acme.csr.menu" />
								</button>
							</div>
						</Modal.Body>
						<Modal.Footer>
							<Button onClick={remove} disabled={isSubmitting || isTesting}>
								<T id="cancel" />
							</Button>
							<div className="ms-auto">
								{!values.meta.dnsChallenge && (
									<Button
										type="button"
										actionType="secondary"
										className="me-3"
										isLoading={isTesting}
										disabled={isSubmitting || domains.length === 0}
										onClick={handleTest}
									>
										<T id="test" />
									</Button>
								)}
								<Button
									type="submit"
									actionType="primary"
									className="bg-pink"
									isLoading={isSubmitting}
									disabled={isSubmitting || isTesting}
								>
									<T id="save" />
								</Button>
							</div>
						</Modal.Footer>
					</Form>
				)}
			</Formik>
		</Modal>
	);
});
