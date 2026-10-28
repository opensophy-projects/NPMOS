// NPMOS: section buttons and switches use the accent colour (phase 2)
// NPMOS: hardcoded strings moved to the locale (en, ru)
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { Form, Formik } from "formik";
import { type ReactNode, useState } from "react";
import { Alert } from "react-bootstrap";
import Modal from "react-bootstrap/Modal";
import {
	Button,
	DirectoryField,
	DomainNamesField,
	Loading,
	NginxConfigField,
	SSLCertificateField,
	SSLOptionsFields,
} from "src/components";
import { useDeadHost, useDeadHosts, useDirectorySuggestions, useSetDeadHost } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";

// NPMOS: "Duplicate" in the hosts table opens the form filled from another host
const showDeadHostModal = (id: number | "new", isClone = false) => {
	EasyModal.show(DeadHostModal, { id, isClone } as Omit<Props, "visible" | "remove">);
};

interface Props extends InnerModalProps {
	id: number | "new";
	isClone?: boolean;
}
const DeadHostModal = EasyModal.create(({ id, isClone = false, visible, remove }: Props) => {
	const { data, isLoading, error } = useDeadHost(id);
	const { mutate: setDeadHost } = useSetDeadHost();
	const { data: allDeadHosts } = useDeadHosts();
	const suggestions = useDirectorySuggestions(allDeadHosts);
	const [errorMsg, setErrorMsg] = useState<ReactNode | null>(null);
	const [isSubmitting, setIsSubmitting] = useState(false);

	const onSubmit = async (values: any, { setSubmitting }: any) => {
		if (isSubmitting) return;
		setIsSubmitting(true);
		setErrorMsg(null);

		const meta = { ...(values.meta || {}) };
		if (typeof meta.directory === "string") {
			const trimmed = meta.directory.trim();
			if (trimmed) {
				meta.directory = trimmed;
			} else {
				delete meta.directory;
			}
		} else {
			delete meta.directory;
		}

		const { ...payload } = {
			id: id === "new" || isClone ? undefined : id,
			...values,
			meta,
		};

		setDeadHost(payload, {
			onError: (err: any) => {
				if (err.payload?.debug?.stack) {
					setErrorMsg(
						<div className="w-100">
							<T id={err.message} />
							<pre>
								<code>{err.payload.debug.stack.join("\n")}</code>
							</pre>
						</div>,
					);
				} else {
					setErrorMsg(<T id={err.message} />);
				}
			},
			onSuccess: () => {
				showObjectSuccess("dead-host", "saved");
				remove();
			},
			onSettled: () => {
				setIsSubmitting(false);
				setSubmitting(false);
			},
		});
	};

	return (
		<Modal show={visible} onHide={remove}>
			{!isLoading && error && (
				<Alert variant="danger" className="m-3">
					{error?.message || <T id="npmos.common.unknown-error" />}
				</Alert>
			)}
			{isLoading && <Loading noLogo />}
			{!isLoading && data && (
				<Formik
					initialValues={
						{
							domainNames: data?.domainNames,
							certificateId: data?.certificateId,
							sslForced: data?.sslForced,
							advancedConfig: data?.advancedConfig,
							http2Support: data?.http2Support,
							npmplusHttp3Support: data?.npmplusHttp3Support,
							hstsEnabled: data?.hstsEnabled,
							hstsSubdomains: data?.hstsSubdomains,
							meta: data?.meta || {},
						} as any
					}
					onSubmit={onSubmit}
				>
					{({ values }: any) => (
						<Form>
							<Modal.Header closeButton>
								<Modal.Title>
									<T
										id={!isClone && data?.id ? "object.edit" : "object.add"}
										tData={{ object: "dead-host" }}
									/>
								</Modal.Title>
							</Modal.Header>
							<Modal.Body className="p-0">
								<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
									{errorMsg}
								</Alert>
								<div className="card m-0 border-0">
									<div className="card-header">
										<ul className="nav nav-tabs card-header-tabs" data-bs-toggle="tabs">
											<li className="nav-item" role="presentation">
												<a
													href="#tab-details"
													className="nav-link active"
													data-bs-toggle="tab"
													aria-selected="true"
													role="tab"
												>
													<T id="column.details" />
												</a>
											</li>
											<li className="nav-item" role="presentation">
												<a
													href="#tab-ssl"
													className="nav-link"
													data-bs-toggle="tab"
													aria-selected="false"
													tabIndex={-1}
													role="tab"
												>
													<T id="column.ssl" />
												</a>
											</li>
											<li className="nav-item ms-auto" role="presentation">
												<a
													href="#tab-advanced"
													className="nav-link"
													title={intl.formatMessage({ id: "settings" })}
													data-bs-toggle="tab"
													aria-selected="false"
													tabIndex={-1}
													role="tab"
												>
													<T id="domains.advanced" />
													{values?.advancedConfig?.trim() ? "" : ""}
												</a>
											</li>
										</ul>
									</div>
									<div className="card-body">
										<div className="tab-content">
											<div className="tab-pane active show" id="tab-details" role="tabpanel">
												<DomainNamesField isWildcardPermitted dnsProviderWildcardSupported />
											</div>
											<div className="tab-pane" id="tab-ssl" role="tabpanel">
												<SSLCertificateField
													name="certificateId"
													label="ssl-certificate"
													allowNew
												/>
												<SSLOptionsFields color="bg-primary" />
											</div>
											<div className="tab-pane" id="tab-advanced" role="tabpanel">
												<NginxConfigField />
												<div className="row">
													<div className="col-md-12 mb-3">
														<DirectoryField
															labelId="dead-host.directory"
															datalistId="directory-suggestions-dead"
															suggestions={suggestions}
														/>
													</div>
												</div>
											</div>
										</div>
									</div>
								</div>
							</Modal.Body>
							<Modal.Footer>
								<Button data-bs-dismiss="modal" onClick={remove} disabled={isSubmitting}>
									<T id="cancel" />
								</Button>
								<Button
									type="submit"
									actionType="primary"
									className="ms-auto btn-primary"
									data-bs-dismiss="modal"
									isLoading={isSubmitting}
									disabled={isSubmitting}
								>
									<T id="save" />
								</Button>
							</Modal.Footer>
						</Form>
					)}
				</Formik>
			)}
		</Modal>
	);
});

export { showDeadHostModal };
