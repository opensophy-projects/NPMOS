// A template of certificates: trust domain, profile, lifetime, key type and the fixed part of the
// subject (organization, unit…); the common name is entered when a certificate is issued.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { KEY_TYPES, type PkiOverview, type PkiTemplate, PROFILES, type SubjectField, setPkiSettings } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const FIELDS: SubjectField[] = ["organization", "organizationalUnit", "country", "state", "locality"];

interface Props extends InnerModalProps {
	data: PkiOverview;
	template?: PkiTemplate;
	onDone: () => void;
}

const slug = (name: string) =>
	name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-|-$/g, "")
		.slice(0, 30) || "template";

const TemplateModal = EasyModal.create(({ visible, remove, data, template, onDone }: Props) => {
	const issuers = data.cas.filter((ca) => ca.kind === "intermediate");
	const [value, setValue] = useState<PkiTemplate>(
		template ?? {
			id: "",
			name: "",
			profile: "client",
			caId: issuers[0]?.id ?? null,
			days: data.settings.clientDays,
			keyType: data.settings.keyType,
			subject: {},
		},
	);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			const others = data.settings.templates.filter((x) => x.id !== template?.id);
			let id = template?.id ?? slug(value.name);
			while (!template && others.some((x) => x.id === id))
				id = `${slug(value.name).slice(0, 26)}-${Math.floor(Math.random() * 999)}`;
			const subject = Object.fromEntries(Object.entries(value.subject).filter(([, v]) => v?.trim()));
			await setPkiSettings({ ...data.settings, templates: [...others, { ...value, id, subject }] });
			onDone();
			remove();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	return (
		<Modal show={visible} onHide={remove}>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={template ? "npmos.pki.template.edit" : "npmos.pki.template.add"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				<div className="mb-3">
					<label className="form-label" htmlFor="pki-tpl-name">
						<T id="npmos.pki.template.name" />
					</label>
					<input
						id="pki-tpl-name"
						className="form-control"
						maxLength={100}
						value={value.name}
						onChange={(e) => setValue({ ...value, name: e.target.value })}
					/>
				</div>
				<div className="row">
					<div className="col-6 mb-3">
						<label className="form-label" htmlFor="pki-tpl-ca">
							<T id="npmos.pki.issuer" />
						</label>
						<select
							id="pki-tpl-ca"
							className="form-select"
							value={value.caId ?? ""}
							onChange={(e) =>
								setValue({ ...value, caId: e.target.value ? Number(e.target.value) : null })
							}
						>
							<option value="">{t("npmos.pki.template.any-ca")}</option>
							{issuers.map((ca) => (
								<option key={ca.id} value={ca.id}>
									{ca.name}
								</option>
							))}
						</select>
					</div>
					<div className="col-6 mb-3">
						<label className="form-label" htmlFor="pki-tpl-profile">
							<T id="npmos.pki.profile" />
						</label>
						<select
							id="pki-tpl-profile"
							className="form-select"
							value={value.profile}
							onChange={(e) => setValue({ ...value, profile: e.target.value as PkiTemplate["profile"] })}
						>
							{PROFILES.map((p) => (
								<option key={p} value={p}>
									{t(`npmos.pki.profile.${p}`)}
								</option>
							))}
						</select>
					</div>
					<div className="col-6 mb-3">
						<label className="form-label" htmlFor="pki-tpl-days">
							<T id="npmos.pki.days" />
						</label>
						<input
							id="pki-tpl-days"
							type="number"
							min={1}
							max={3650}
							className="form-control"
							value={value.days}
							onChange={(e) => setValue({ ...value, days: Number(e.target.value) })}
						/>
					</div>
					<div className="col-6 mb-3">
						<label className="form-label" htmlFor="pki-tpl-key">
							<T id="npmos.pki.key-type" />
						</label>
						<select
							id="pki-tpl-key"
							className="form-select"
							value={value.keyType}
							onChange={(e) => setValue({ ...value, keyType: e.target.value })}
						>
							{KEY_TYPES.map((k) => (
								<option key={k} value={k}>
									{t(`npmos.pki.key-type.${k}`)}
								</option>
							))}
						</select>
					</div>
					{FIELDS.map((f) => (
						<div className="col-6 mb-3" key={f}>
							<label className="form-label" htmlFor={`pki-tpl-${f}`}>
								<T id={`npmos.pki.subject.${f}`} />
							</label>
							<input
								id={`pki-tpl-${f}`}
								className="form-control"
								value={value.subject[f] ?? ""}
								onChange={(e) =>
									setValue({ ...value, subject: { ...value.subject, [f]: e.target.value } })
								}
							/>
						</div>
					))}
				</div>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" isLoading={busy} disabled={!value.name.trim()} onClick={submit}>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showTemplateModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(TemplateModal, props);
