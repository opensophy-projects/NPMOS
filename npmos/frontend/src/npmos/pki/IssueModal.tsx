// Issue a certificate (from a template, by hand or from a request) or renew one, then hand it out:
// .p12 with a password, PEM files, a one-time link with a QR code.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { useCan } from "../rbac/hooks";
import {
	type IssueData,
	type IssueResult,
	issueCert,
	KEY_TYPES,
	type PkiCert,
	type PkiOverview,
	PROFILES,
	type Profile,
	renewCert,
	type Subject,
	type SubjectField,
} from "./api";
import { Delivery } from "./Delivery";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

export interface IssuePreset {
	caId?: number;
	profile?: Profile;
	templateId?: string;
	commonName?: string;
	dns?: string;
}

interface Props extends InnerModalProps {
	data: PkiOverview;
	preset?: IssuePreset;
	/** renewal of this certificate */
	renew?: PkiCert;
	onDone: () => void;
}

const LINK_HOURS = [1, 24, 72, 168];
const MAIN_FIELDS: SubjectField[] = ["commonName", "organization", "organizationalUnit", "email"];
const MORE_FIELDS: SubjectField[] = ["country", "state", "locality"];

const lines = (text: string) =>
	text
		.split(/[\n,]+/)
		.map((s) => s.trim())
		.filter(Boolean);

const IssueModal = EasyModal.create(({ visible, remove, data, preset, renew, onDone }: Props) => {
	const can = useCan();
	const canKeepKey = can("pki", "export_key");
	const issuers = data.cas.filter(
		(ca) => ca.kind === "intermediate" && ca.hasKey && new Date(ca.notAfter) > new Date(),
	);
	const template = data.settings.templates.find((x) => x.id === preset?.templateId);
	const [templateId, setTemplateId] = useState(template?.id ?? "");
	const [caId, setCaId] = useState<number>(renew?.caId ?? preset?.caId ?? template?.caId ?? issuers[0]?.id ?? 0);
	const [profile, setProfile] = useState<Profile>(renew?.profile ?? preset?.profile ?? template?.profile ?? "client");
	const [subject, setSubject] = useState<Subject>({
		...(template?.subject ?? {}),
		commonName: preset?.commonName ?? "",
	});
	const [more, setMore] = useState(false);
	const [dns, setDns] = useState(preset?.dns ?? "");
	const [ips, setIps] = useState("");
	const [emails, setEmails] = useState("");
	const defaultDays = (p: Profile) => (p === "server" ? data.settings.serverDays : data.settings.clientDays);
	const [days, setDays] = useState<number>(
		template?.days ?? defaultDays(renew?.profile ?? preset?.profile ?? "client"),
	);
	const [keyType, setKeyType] = useState(renew?.keyType ?? template?.keyType ?? data.settings.keyType);
	const [source, setSource] = useState<"generate" | "csr">("generate");
	const [csr, setCsr] = useState("");
	const [password, setPassword] = useState("");
	const [compatible, setCompatible] = useState(data.settings.p12Compatible);
	const [link, setLink] = useState(0);
	const [storeKey, setStoreKey] = useState(renew?.hasKey ?? false);
	const [includeKey, setIncludeKey] = useState(false);
	const [install, setInstall] = useState(renew ? !!renew.certificateId : true);
	const [revokeOld, setRevokeOld] = useState(false);
	const [notes, setNotes] = useState("");
	// short-lived client certificates renewed by NPMOS (not for renewals of a certificate by hand)
	const [autoRenew, setAutoRenew] = useState<"" | "link" | "token">("");
	const [hours, setHours] = useState(24);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [result, setResult] = useState<IssueResult | null>(null);

	const applyTemplate = (id: string) => {
		setTemplateId(id);
		const x = data.settings.templates.find((tpl) => tpl.id === id);
		if (!x) return;
		if (x.caId) setCaId(x.caId);
		setProfile(x.profile);
		setDays(x.days);
		setKeyType(x.keyType);
		setSubject((s) => ({ ...x.subject, commonName: s.commonName }));
	};

	const caName = useMemo(() => data.cas.find((ca) => ca.id === caId)?.name ?? "", [data.cas, caId]);

	const submit = async () => {
		setBusy(true);
		setError(null);
		const delivery =
			source === "generate"
				? {
						password: password || undefined,
						compatible,
						linkHours: link || undefined,
						storeKey: canKeepKey && storeKey,
						includeKeyPem: includeKey,
					}
				: {};
		try {
			if (renew) {
				setResult(
					await renewCert(renew.id, {
						days,
						keyType,
						csrPem: source === "csr" ? csr : undefined,
						revokeOld,
						...delivery,
					}),
				);
			} else {
				const payload: IssueData = {
					caId,
					profile,
					days,
					sans: { dns: lines(dns), ip: lines(ips), email: lines(emails) },
					template: data.settings.templates.find((x) => x.id === templateId)?.name,
					notes: notes || undefined,
					...(source === "csr"
						? { csrPem: csr }
						: { subject, keyType, install: profile === "server" && install }),
					...delivery,
					...(profile === "client" && autoRenew ? { autoRenew, hours } : {}),
				};
				setResult(await issueCert(payload));
			}
			onDone();
		} catch (err: any) {
			setError(err.message);
		} finally {
			setBusy(false);
		}
	};

	const field = (name: SubjectField) => (
		<div className="col-md-6 mb-2" key={name}>
			<label className="form-label" htmlFor={`pki-subject-${name}`}>
				<T id={`npmos.pki.subject.${name}`} />
			</label>
			<input
				id={`pki-subject-${name}`}
				className="form-control"
				value={subject[name] ?? ""}
				required={name === "commonName"}
				onChange={(e) => setSubject((s) => ({ ...s, [name]: e.target.value }))}
			/>
		</div>
	);

	const title = renew ? "npmos.pki.renew" : "npmos.pki.issue";

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={title} />
					{renew && <span className="text-secondary ms-2">{renew.commonName}</span>}
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				{result ? (
					<Delivery result={result} publicUrl={data.settings.publicUrl} />
				) : !issuers.length ? (
					<Alert variant="warning" className="mb-0">
						<T id="npmos.pki.no-issuer" />
					</Alert>
				) : (
					<>
						{!renew && (
							<>
								{data.settings.templates.length > 0 && (
									<div className="mb-3">
										<label className="form-label" htmlFor="pki-template">
											<T id="npmos.pki.template" />
										</label>
										<select
											id="pki-template"
											className="form-select"
											value={templateId}
											onChange={(e) => applyTemplate(e.target.value)}
										>
											<option value="">{t("npmos.pki.template.none")}</option>
											{data.settings.templates.map((x) => (
												<option key={x.id} value={x.id}>
													{x.name}
												</option>
											))}
										</select>
									</div>
								)}
								<div className="row">
									<div className="col-md-6 mb-3">
										<label className="form-label" htmlFor="pki-ca">
											<T id="npmos.pki.issuer" />
										</label>
										<select
											id="pki-ca"
											className="form-select"
											value={caId}
											onChange={(e) => setCaId(Number(e.target.value))}
										>
											{issuers.map((ca) => (
												<option key={ca.id} value={ca.id}>
													{ca.name}
												</option>
											))}
										</select>
									</div>
									<div className="col-md-6 mb-3">
										<span className="form-label d-block">
											<T id="npmos.pki.profile" />
										</span>
										<div className="btn-group w-100">
											{PROFILES.map((p) => (
												<button
													key={p}
													type="button"
													className={`btn ${profile === p ? "btn-primary" : ""}`}
													onClick={() => {
														setProfile(p);
														setDays(defaultDays(p));
													}}
												>
													<T id={`npmos.pki.profile.${p}`} />
												</button>
											))}
										</div>
									</div>
								</div>
							</>
						)}
						<div className="mb-3">
							<span className="form-label d-block">
								<T id="npmos.pki.key-source" />
							</span>
							<div className="btn-group">
								{(["generate", "csr"] as const).map((s) => (
									<button
										key={s}
										type="button"
										className={`btn ${source === s ? "btn-primary" : ""}`}
										onClick={() => setSource(s)}
									>
										<T id={`npmos.pki.key-source.${s}`} />
									</button>
								))}
							</div>
							<div className="form-hint">
								<T id={`npmos.pki.key-source.${source}.hint`} />
							</div>
						</div>
						{source === "csr" ? (
							<div className="mb-3">
								<label className="form-label" htmlFor="pki-csr">
									<T id="npmos.pki.csr" />
								</label>
								<textarea
									id="pki-csr"
									className="form-control font-monospace"
									rows={6}
									value={csr}
									onChange={(e) => setCsr(e.target.value)}
								/>
							</div>
						) : (
							!renew && (
								<>
									<div className="row">{MAIN_FIELDS.map(field)}</div>
									<button
										type="button"
										className="btn btn-link px-0 mb-2"
										onClick={() => setMore(!more)}
									>
										<T id={more ? "npmos.pki.subject.less" : "npmos.pki.subject.more"} />
									</button>
									{more && <div className="row">{MORE_FIELDS.map(field)}</div>}
								</>
							)
						)}
						{!renew && (
							<div className="row">
								{profile === "server" ? (
									<>
										<div className="col-md-6 mb-3">
											<label className="form-label" htmlFor="pki-dns">
												<T id="npmos.pki.sans.dns" />
											</label>
											<textarea
												id="pki-dns"
												className="form-control font-monospace"
												rows={3}
												value={dns}
												onChange={(e) => setDns(e.target.value)}
											/>
										</div>
										<div className="col-md-6 mb-3">
											<label className="form-label" htmlFor="pki-ip">
												<T id="npmos.pki.sans.ip" />
											</label>
											<textarea
												id="pki-ip"
												className="form-control font-monospace"
												rows={3}
												value={ips}
												onChange={(e) => setIps(e.target.value)}
											/>
										</div>
									</>
								) : (
									<div className="col-md-12 mb-3">
										<label className="form-label" htmlFor="pki-emails">
											<T id="npmos.pki.sans.email" />
										</label>
										<input
											id="pki-emails"
											className="form-control"
											value={emails}
											onChange={(e) => setEmails(e.target.value)}
										/>
										<div className="form-hint">
											<T id="npmos.pki.sans.email.hint" />
										</div>
									</div>
								)}
							</div>
						)}
						{!renew && profile === "client" && (
							<div className="mb-3">
								<span className="form-label d-block">
									<T id="npmos.pki.auto-renew" />
								</span>
								<div className="btn-group">
									{(["", "link", "token"] as const).map((m) => (
										<button
											key={m || "none"}
											type="button"
											className={`btn ${autoRenew === m ? "btn-primary" : ""}`}
											disabled={m === "link" && source === "csr"}
											onClick={() => setAutoRenew(m)}
										>
											<T id={`npmos.pki.auto-renew.${m || "none"}`} />
										</button>
									))}
								</div>
								<div className="form-hint">
									<T id={`npmos.pki.auto-renew.${autoRenew || "none"}.hint`} />
								</div>
								{autoRenew && (
									<div className="d-flex align-items-center gap-2 mt-2">
										<label className="form-label mb-0" htmlFor="pki-hours">
											<T id="npmos.pki.hours" />
										</label>
										<input
											id="pki-hours"
											type="number"
											min={1}
											max={8760}
											className="form-control w-auto"
											value={hours}
											onChange={(e) => setHours(Number(e.target.value))}
										/>
									</div>
								)}
							</div>
						)}
						<div className="row">
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="pki-days">
									<T id="npmos.pki.days" />
								</label>
								<input
									id="pki-days"
									type="number"
									min={1}
									max={3650}
									className="form-control"
									disabled={!!autoRenew && profile === "client" && !renew}
									value={days}
									onChange={(e) => setDays(Number(e.target.value))}
								/>
							</div>
							{source === "generate" && (
								<div className="col-md-6 mb-3">
									<label className="form-label" htmlFor="pki-key-type">
										<T id="npmos.pki.key-type" />
									</label>
									<select
										id="pki-key-type"
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
							)}
						</div>
						{source === "generate" && (
							<fieldset className="border rounded p-3 mb-3">
								<legend className="fs-5 float-none w-auto px-1 mb-0">
									<T id="npmos.pki.delivery" />
								</legend>
								<div className="mb-2">
									<label className="form-label" htmlFor="pki-password">
										<T id="npmos.pki.p12.password" />
									</label>
									<input
										id="pki-password"
										className="form-control"
										autoComplete="new-password"
										placeholder={t("npmos.pki.p12.password.generate")}
										value={password}
										onChange={(e) => setPassword(e.target.value)}
									/>
								</div>
								<label className="form-check">
									<input
										type="checkbox"
										className="form-check-input"
										checked={compatible}
										onChange={(e) => setCompatible(e.target.checked)}
									/>
									<span className="form-check-label">
										<T id="npmos.pki.p12.compatible" />
									</span>
								</label>
								<div className="d-flex align-items-center gap-2 mb-2">
									<label className="form-label mb-0" htmlFor="pki-link">
										<T id="npmos.pki.link.create" />
									</label>
									<select
										id="pki-link"
										className="form-select form-select-sm w-auto"
										value={link}
										onChange={(e) => setLink(Number(e.target.value))}
									>
										<option value={0}>{t("npmos.pki.link.none")}</option>
										{LINK_HOURS.map((h) => (
											<option key={h} value={h}>
												{t("npmos.pki.link.hours", { hours: h })}
											</option>
										))}
									</select>
								</div>
								{canKeepKey && (
									<label className="form-check">
										<input
											type="checkbox"
											className="form-check-input"
											checked={storeKey}
											onChange={(e) => setStoreKey(e.target.checked)}
										/>
										<span className="form-check-label">
											<T id="npmos.pki.store-key" />
										</span>
										<span className="form-check-description">
											<T id="npmos.pki.store-key.hint" />
										</span>
									</label>
								)}
								<label className="form-check">
									<input
										type="checkbox"
										className="form-check-input"
										checked={includeKey}
										onChange={(e) => setIncludeKey(e.target.checked)}
									/>
									<span className="form-check-label">
										<T id="npmos.pki.include-key" />
									</span>
								</label>
								{(renew ? !!renew.certificateId : profile === "server") && (
									<label className="form-check mb-0">
										<input
											type="checkbox"
											className="form-check-input"
											checked={install}
											disabled={!!renew}
											onChange={(e) => setInstall(e.target.checked)}
										/>
										<span className="form-check-label">
											<T id="npmos.pki.install" />
										</span>
									</label>
								)}
							</fieldset>
						)}
						{renew ? (
							<label className="form-check">
								<input
									type="checkbox"
									className="form-check-input"
									checked={revokeOld}
									onChange={(e) => setRevokeOld(e.target.checked)}
								/>
								<span className="form-check-label">
									<T id="npmos.pki.revoke-old" />
								</span>
							</label>
						) : (
							<div className="mb-0">
								<label className="form-label" htmlFor="pki-notes">
									<T id="npmos.pki.notes" />
								</label>
								<input
									id="pki-notes"
									className="form-control"
									maxLength={500}
									value={notes}
									onChange={(e) => setNotes(e.target.value)}
								/>
							</div>
						)}
						{!renew && caName && (
							<p className="text-secondary small mt-2 mb-0">
								<T id="npmos.pki.issue.summary" data={{ ca: caName }} />
							</p>
						)}
					</>
				)}
			</Modal.Body>
			<Modal.Footer>
				{result ? (
					<Button actionType="primary" onClick={remove}>
						<T id="npmos.pki.done" />
					</Button>
				) : (
					<>
						<Button onClick={remove} disabled={busy}>
							<T id="cancel" />
						</Button>
						<Button
							actionType="primary"
							isLoading={busy}
							disabled={
								!issuers.length ||
								(source === "csr" ? !csr.trim() : !renew && !subject.commonName?.trim())
							}
							onClick={submit}
						>
							<T id={renew ? "npmos.pki.renew.do" : "npmos.pki.issue.do"} />
						</Button>
					</>
				)}
			</Modal.Footer>
		</Modal>
	);
});

export const showIssueModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(IssueModal, props);
