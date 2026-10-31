// Certificate authorities: a new root CA, a new trust domain (intermediate CA under a root), import
// of a root with its key, an external CA for verification only; editing the name (and the CRL of
// an external CA).
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { createCa, importCa, KEY_TYPES, type PkiCa, type PkiOverview, type Subject, updateCa } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export type CaMode = "root" | "intermediate" | "import" | "external";

interface Props extends InnerModalProps {
	data: PkiOverview;
	mode?: CaMode;
	/** edit this CA (name; CRL of an external one) */
	edit?: PkiCa;
	parentId?: number;
	/** name of the new CA (e.g. from a host) */
	name?: string;
	onDone: (ca: PkiCa) => void | Promise<void>;
}

function PemField({
	id,
	label,
	value,
	onChange,
	hint,
}: {
	id: string;
	label: string;
	value: string;
	onChange: (v: string) => void;
	hint?: string;
}) {
	return (
		<div className="mb-3">
			<label className="form-label" htmlFor={id}>
				<T id={label} />
			</label>
			<input
				type="file"
				className="form-control form-control-sm mb-1"
				accept=".pem,.crt,.cer,.key,.crl,text/plain"
				aria-label={t(label)}
				onChange={async (e) => {
					const file = e.target.files?.[0];
					if (file) onChange(await file.text());
				}}
			/>
			<textarea
				id={id}
				className="form-control font-monospace"
				rows={4}
				value={value}
				onChange={(e) => onChange(e.target.value)}
			/>
			{hint && (
				<div className="form-hint">
					<T id={hint} />
				</div>
			)}
		</div>
	);
}

const CaModal = EasyModal.create(({ visible, remove, data, mode = "root", edit, parentId, name, onDone }: Props) => {
	const roots = data.cas.filter((ca) => ca.kind === "root" && ca.hasKey);
	const [kind, setKind] = useState<CaMode>(edit ? (edit.kind === "external" ? "external" : "root") : mode);
	const [caName, setCaName] = useState(edit?.name ?? name ?? "");
	const [subject, setSubject] = useState<Subject>({ organization: "" });
	const [parent, setParent] = useState<number>(parentId ?? roots[0]?.id ?? 0);
	const [keyType, setKeyType] = useState(data.settings.keyType);
	const [days, setDays] = useState<number | "">("");
	const [certPem, setCertPem] = useState("");
	const [keyPem, setKeyPem] = useState("");
	const [keyPassword, setKeyPassword] = useState("");
	const [crlPem, setCrlPem] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			let ca: PkiCa;
			if (edit) {
				ca = await updateCa(edit.id, {
					name: caName,
					...(edit.kind === "external" && crlPem.trim() ? { crlPem } : {}),
				});
			} else if (kind === "root" || kind === "intermediate") {
				ca = await createCa({
					kind,
					name: caName,
					parentId: kind === "intermediate" ? parent : undefined,
					subject: { ...subject, commonName: subject.commonName || caName },
					keyType,
					days: days === "" ? undefined : days,
				});
			} else {
				ca = await importCa({
					kind: kind === "import" ? "root" : "external",
					name: caName,
					certPem,
					keyPem: kind === "import" ? keyPem : undefined,
					keyPassword: kind === "import" && keyPassword ? keyPassword : undefined,
					crlPem: kind === "external" && crlPem.trim() ? crlPem : undefined,
				});
			}
			await onDone(ca);
			remove();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	const creates = !edit && (kind === "root" || kind === "intermediate");
	const valid =
		caName.trim() &&
		(edit ||
			(creates && (kind === "root" || parent)) ||
			(kind === "import" && certPem.trim() && keyPem.trim()) ||
			(kind === "external" && certPem.trim()));

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={edit ? "npmos.pki.ca.edit" : "npmos.pki.ca.add"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				{!edit && (
					<div className="mb-3">
						<div className="btn-group flex-wrap">
							{(["root", "intermediate", "import", "external"] as CaMode[]).map((k) => (
								<button
									key={k}
									type="button"
									className={`btn ${kind === k ? "btn-primary" : ""}`}
									onClick={() => setKind(k)}
								>
									<T id={`npmos.pki.ca.mode.${k}`} />
								</button>
							))}
						</div>
						<div className="form-hint">
							<T id={`npmos.pki.ca.mode.${kind}.hint`} />
						</div>
					</div>
				)}
				<div className="mb-3">
					<label className="form-label" htmlFor="pki-ca-name">
						<T id="npmos.pki.ca.name" />
					</label>
					<input
						id="pki-ca-name"
						className="form-control"
						maxLength={100}
						value={caName}
						onChange={(e) => setCaName(e.target.value)}
					/>
				</div>
				{creates && (
					<>
						{kind === "intermediate" &&
							(roots.length ? (
								<div className="mb-3">
									<label className="form-label" htmlFor="pki-ca-parent">
										<T id="npmos.pki.ca.parent" />
									</label>
									<select
										id="pki-ca-parent"
										className="form-select"
										value={parent}
										onChange={(e) => setParent(Number(e.target.value))}
									>
										{roots.map((ca) => (
											<option key={ca.id} value={ca.id}>
												{ca.name}
											</option>
										))}
									</select>
								</div>
							) : (
								<Alert variant="warning">
									<T id="npmos.pki.ca.no-root" />
								</Alert>
							))}
						<div className="row">
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="pki-ca-cn">
									<T id="npmos.pki.subject.commonName" />
								</label>
								<input
									id="pki-ca-cn"
									className="form-control"
									placeholder={caName}
									value={subject.commonName ?? ""}
									onChange={(e) => setSubject({ ...subject, commonName: e.target.value })}
								/>
							</div>
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="pki-ca-o">
									<T id="npmos.pki.subject.organization" />
								</label>
								<input
									id="pki-ca-o"
									className="form-control"
									value={subject.organization ?? ""}
									onChange={(e) => setSubject({ ...subject, organization: e.target.value })}
								/>
							</div>
						</div>
						<div className="form-hint mb-3">
							<T id="npmos.pki.ca.ascii" />
						</div>
						<div className="row">
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="pki-ca-key">
									<T id="npmos.pki.key-type" />
								</label>
								<select
									id="pki-ca-key"
									className="form-select"
									value={keyType}
									onChange={(e) => setKeyType(e.target.value)}
								>
									{KEY_TYPES.map((k) => (
										<option key={k} value={k}>
											{t(`npmos.pki.key-type.${k}`)}
										</option>
									))}
								</select>
							</div>
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="pki-ca-days">
									<T id="npmos.pki.days" />
								</label>
								<input
									id="pki-ca-days"
									type="number"
									min={1}
									className="form-control"
									placeholder={kind === "root" ? "3650" : "1825"}
									value={days}
									onChange={(e) => setDays(e.target.value ? Number(e.target.value) : "")}
								/>
							</div>
						</div>
					</>
				)}
				{!edit && kind === "import" && (
					<>
						<PemField
							id="pki-ca-cert"
							label="npmos.pki.ca.cert-pem"
							value={certPem}
							onChange={setCertPem}
						/>
						<PemField id="pki-ca-keypem" label="npmos.pki.ca.key-pem" value={keyPem} onChange={setKeyPem} />
						<div className="mb-3">
							<label className="form-label" htmlFor="pki-ca-keypass">
								<T id="npmos.pki.ca.key-password" />
							</label>
							{/* NPMOS: form wrapper so the lone password field is inside a form */}
							<form
								style={{ display: "contents" }}
								autoComplete="off"
								onSubmit={(e) => e.preventDefault()}
							>
								<input
									id="pki-ca-keypass"
									type="password"
									className="form-control"
									autoComplete="off"
									value={keyPassword}
									onChange={(e) => setKeyPassword(e.target.value)}
								/>
							</form>
						</div>
					</>
				)}
				{!edit && kind === "external" && (
					<PemField
						id="pki-ca-bundle"
						label="npmos.pki.ca.bundle"
						value={certPem}
						onChange={setCertPem}
						hint="npmos.pki.ca.bundle.hint"
					/>
				)}
				{(kind === "external" || edit?.kind === "external") && !edit?.upstreamCertificateId && (
					<PemField
						id="pki-ca-crl"
						label="npmos.pki.ca.crl"
						value={crlPem}
						onChange={setCrlPem}
						hint="npmos.pki.ca.crl.hint"
					/>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" isLoading={busy} disabled={!valid} onClick={submit}>
					<T id={edit ? "save" : "npmos.pki.ca.create"} />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showCaModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(CaModal, props);
