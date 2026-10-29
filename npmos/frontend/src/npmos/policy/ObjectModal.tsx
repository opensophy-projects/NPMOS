// An object of the policy (WAF → Policy): a form by kind (fields.ts), then what local_policy.yaml
// becomes (Review), then save: applied at once and kept as a version.
import { IconPlus, IconTrash } from "@tabler/icons-react";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import {
	createObject,
	type DefaultPolicy,
	type Kind,
	type PolicyObject,
	type Preview,
	previewChange,
	setDefaultPolicy,
	updateObject,
} from "./api";
import { EXCEPTION_KEYS, FIELDS, type Field, getPath, NEW_SPEC, setPath } from "./fields";
import { Review } from "./Review";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const NAME = /^[a-z0-9]([a-z0-9._-]{0,98}[a-z0-9])?$/;

/** placeholders of technical values (not translated) */
const EXAMPLE = { uri: "/login", ip: "203.0.113.10", header: "x-user-id" };

interface Props extends InnerModalProps {
	kind: Kind;
	/** edited object; without it a new one */
	object?: PolicyObject;
	/** a new object from this one (duplicate) or from an event (exception) */
	initial?: { name?: string; description?: string; spec?: Record<string, any> };
	/** all objects: names of other objects (trusted sources) */
	objects: PolicyObject[];
	/** a new exception is also added to the exceptions of the default policy */
	addToDefault?: DefaultPolicy;
	onSaved?: () => void;
}

function Rows<T>({
	rows,
	onChange,
	empty,
	add,
	render,
}: {
	rows: T[];
	onChange: (rows: T[]) => void;
	empty: () => T;
	add: string;
	render: (row: T, set: (row: T) => void) => React.ReactNode;
}) {
	return (
		<div>
			{rows.map((row, i) => (
				<div className="row g-2 align-items-center mb-2" key={i}>
					{render(row, (next) => onChange(rows.map((r, j) => (j === i ? next : r))))}
					<div className="col-auto">
						<button
							type="button"
							className="btn btn-icon btn-sm btn-ghost-danger"
							aria-label={t("npmos.policy.remove")}
							onClick={() => onChange(rows.filter((_, j) => j !== i))}
						>
							<IconTrash size={16} />
						</button>
					</div>
				</div>
			))}
			<Button size="sm" onClick={() => onChange([...rows, empty()])}>
				<IconPlus size={14} className="me-1" />
				<T id={add} />
			</Button>
		</div>
	);
}

function FieldInput({
	field,
	spec,
	set,
	objects,
}: {
	field: Field;
	spec: Record<string, any>;
	set: (path: string, value: unknown) => void;
	objects: PolicyObject[];
}) {
	const value = getPath(spec, field.path);
	const id = `policy-${field.path}`;
	switch (field.type) {
		case "select":
			return (
				<select
					id={id}
					className="form-select"
					value={value ?? ""}
					onChange={(e) => set(field.path, e.target.value)}
				>
					{field.options.map((o) => (
						<option key={o} value={o}>
							{field.modes ? t(`npmos.policy.mode.${o}`) : field.labels ? t(`${field.labels}${o}`) : o}
						</option>
					))}
				</select>
			);
		case "bool":
			return (
				<label className="form-check form-switch mb-0">
					<input
						id={id}
						className="form-check-input"
						type="checkbox"
						checked={!!value}
						onChange={(e) => set(field.path, e.target.checked)}
					/>
				</label>
			);
		case "number":
			return (
				<input
					id={id}
					type="number"
					className="form-control"
					min={field.min}
					max={field.max}
					value={value ?? ""}
					onChange={(e) => set(field.path, e.target.value === "" ? undefined : Number(e.target.value))}
				/>
			);
		case "text":
			return (
				<input
					id={id}
					className="form-control"
					value={value ?? ""}
					onChange={(e) => set(field.path, e.target.value)}
				/>
			);
		case "textarea":
			return (
				<textarea
					id={id}
					className="form-control"
					rows={3}
					value={value ?? ""}
					onChange={(e) => set(field.path, e.target.value)}
				/>
			);
		case "strings":
			return (
				<textarea
					id={id}
					className="form-control font-monospace"
					rows={3}
					value={(value || []).join("\n")}
					onChange={(e) =>
						set(
							field.path,
							e.target.value
								.split("\n")
								.map((s) => s.trim())
								.filter(Boolean),
						)
					}
				/>
			);
		case "names": {
			const names: string[] = value || [];
			const options = objects.filter((o) => o.kind === field.kind);
			if (!options.length) {
				return (
					<div className="text-secondary small">
						<T id="npmos.policy.no-objects" />
					</div>
				);
			}
			return (
				<div>
					{options.map((o) => (
						<label className="form-check" key={o.id}>
							<input
								className="form-check-input"
								type="checkbox"
								checked={names.includes(o.name)}
								onChange={(e) =>
									set(
										field.path,
										e.target.checked ? [...names, o.name] : names.filter((n) => n !== o.name),
									)
								}
							/>
							<span className="form-check-label">{o.name}</span>
						</label>
					))}
				</div>
			);
		}
		case "conditions":
			return (
				<>
					<Rows
						rows={value || []}
						onChange={(rows) => set(field.path, rows)}
						empty={() => ({ key: "sourceIp", value: "" })}
						add="npmos.policy.condition.add"
						render={(row: any, setRow) => (
							<>
								<div className="col-5">
									<select
										className="form-select"
										aria-label={t("npmos.policy.condition.key")}
										value={row.key}
										onChange={(e) => setRow({ ...row, key: e.target.value })}
									>
										{EXCEPTION_KEYS.map((k) => (
											<option key={k} value={k}>
												{t(`npmos.policy.key.${k}`)}
											</option>
										))}
									</select>
								</div>
								<div className="col">
									<input
										className="form-control"
										aria-label={t("npmos.policy.condition.value")}
										placeholder={row.key === "sourceIp" ? EXAMPLE.ip : ""}
										value={row.value}
										onChange={(e) => setRow({ ...row, value: e.target.value })}
									/>
								</div>
							</>
						)}
					/>
					<div className="form-hint">
						<T id="npmos.policy.condition.hint" />
					</div>
				</>
			);
		case "rateRules":
			return (
				<Rows
					rows={value || []}
					onChange={(rows) => set(field.path, rows)}
					empty={() => ({ uri: "", limit: 100, unit: "minute", action: "inherited" })}
					add="npmos.policy.rate.add"
					render={(row: any, setRow) => (
						<>
							<div className="col-4">
								<input
									className="form-control"
									aria-label={t("npmos.policy.rate.uri")}
									placeholder={EXAMPLE.uri}
									value={row.uri}
									onChange={(e) => setRow({ ...row, uri: e.target.value })}
								/>
							</div>
							<div className="col-2">
								<input
									type="number"
									min={1}
									className="form-control"
									aria-label={t("npmos.policy.rate.limit")}
									value={row.limit}
									onChange={(e) => setRow({ ...row, limit: Number(e.target.value) })}
								/>
							</div>
							<div className="col-3">
								<select
									className="form-select"
									aria-label={t("npmos.policy.rate.unit")}
									value={row.unit}
									onChange={(e) => setRow({ ...row, unit: e.target.value })}
								>
									<option value="minute">{t("npmos.policy.rate.minute")}</option>
									<option value="second">{t("npmos.policy.rate.second")}</option>
								</select>
							</div>
							<div className="col">
								<select
									className="form-select"
									aria-label={t("npmos.policy.rate.action")}
									value={row.action}
									onChange={(e) => setRow({ ...row, action: e.target.value })}
								>
									{["inherited", "prevent", "detect"].map((a) => (
										<option key={a} value={a}>
											{t(`npmos.policy.mode.${a}`)}
										</option>
									))}
								</select>
							</div>
						</>
					)}
				/>
			);
		case "identifiers":
			return (
				<Rows
					rows={value || []}
					onChange={(rows) => set(field.path, rows)}
					empty={() => ({ identifier: "sourceip", value: [] })}
					add="npmos.policy.identifier.add"
					render={(row: any, setRow) => (
						<>
							<div className="col-5">
								<select
									className="form-select"
									aria-label={t("npmos.policy.identifier.type")}
									value={row.identifier}
									onChange={(e) => setRow({ ...row, identifier: e.target.value })}
								>
									{["sourceip", "x-forwarded-for", "headerkey", "cookie", "JWTKey"].map((k) => (
										<option key={k} value={k}>
											{k}
										</option>
									))}
								</select>
							</div>
							<div className="col">
								<input
									className="form-control"
									aria-label={t("npmos.policy.identifier.values")}
									placeholder={
										["headerkey", "cookie", "JWTKey"].includes(row.identifier) ? EXAMPLE.header : ""
									}
									value={(row.value || []).join(", ")}
									onChange={(e) =>
										setRow({
											...row,
											value: e.target.value
												.split(",")
												.map((s) => s.trim())
												.filter(Boolean),
										})
									}
								/>
							</div>
						</>
					)}
				/>
			);
		default:
			return null;
	}
}

export function ObjectForm({
	kind,
	spec,
	onChange,
	objects,
}: {
	kind: Kind;
	spec: Record<string, any>;
	onChange: (spec: Record<string, any>) => void;
	objects: PolicyObject[];
}) {
	const set = (path: string, value: unknown) => onChange(setPath(spec, path, value));
	return (
		<>
			{FIELDS[kind]
				.filter((f) => !f.showIf || f.showIf(spec))
				.map((field) =>
					field.type === "heading" ? (
						<h4 key={field.path} className="mt-3 mb-2">
							<T id={`npmos.policy.h.${field.path}`} />
						</h4>
					) : (
						<div key={field.path} className="mb-3">
							<label className="form-label" htmlFor={`policy-${field.path}`}>
								<T id={`npmos.policy.f.${field.path}`} />
								{field.premium && (
									<span className="badge bg-yellow-lt ms-2">
										<T id="npmos.policy.premium" />
									</span>
								)}
								{field.v2 && (
									<span className="badge bg-purple-lt ms-2" title={t("npmos.policy.v2-hint")}>
										v1beta2
									</span>
								)}
							</label>
							<FieldInput field={field} spec={spec} set={set} objects={objects} />
						</div>
					),
				)}
		</>
	);
}

const ObjectModal = EasyModal.create(
	({ visible, remove, kind, object, initial, objects, addToDefault, onSaved }: Props) => {
		const [name, setName] = useState(object?.name ?? initial?.name ?? "");
		const [description, setDescription] = useState(object?.description ?? initial?.description ?? "");
		const [spec, setSpec] = useState<Record<string, any>>(
			structuredClone(object?.spec ?? initial?.spec ?? NEW_SPEC[kind]()),
		);
		const [preview, setPreview] = useState<Preview | null>(null);
		const [busy, setBusy] = useState(false);
		const [error, setError] = useState<string | null>(null);
		const readOnly = !!object?.builtin;
		const input = { kind, name, description, spec };

		const review = async () => {
			if (!NAME.test(name)) {
				setError(t("npmos.policy.name.invalid"));
				return;
			}
			setBusy(true);
			setError(null);
			try {
				setPreview(await previewChange(object ? { object: input, id: object.id } : { object: input }));
			} catch (err: any) {
				setError(err.message);
			} finally {
				setBusy(false);
			}
		};

		const save = async () => {
			setBusy(true);
			setError(null);
			try {
				const saved = object ? await updateObject(object.id, input) : await createObject(input);
				if (!object && addToDefault) {
					await setDefaultPolicy({
						...addToDefault,
						exceptions: [...(addToDefault.exceptions || []), saved.id],
					});
				}
				showSuccess(t("npmos.policy.saved"));
				onSaved?.();
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
						<T id={`npmos.policy.kind.${kind}`} />
						{object ? `: ${object.name}` : ""}
					</Modal.Title>
				</Modal.Header>
				<Modal.Body>
					{error && <Alert variant="danger">{error}</Alert>}
					{readOnly && (
						<Alert variant="info">
							<T id="npmos.policy.builtin-readonly" />
						</Alert>
					)}
					{preview ? (
						<>
							{addToDefault && preview.valid && (
								<p className="text-secondary small">
									<T id="npmos.policy.add-to-default" />
								</p>
							)}
							<Review preview={preview} />
						</>
					) : (
						<fieldset disabled={readOnly}>
							<div className="row">
								<div className="col-md-5 mb-3">
									<label className="form-label" htmlFor="policy-name">
										<T id="npmos.policy.name" />
									</label>
									<input
										id="policy-name"
										className="form-control font-monospace"
										value={name}
										maxLength={100}
										onChange={(e) => setName(e.target.value.toLowerCase())}
									/>
									<div className="form-hint">
										<T id="npmos.policy.name.hint" />
									</div>
								</div>
								<div className="col-md-7 mb-3">
									<label className="form-label" htmlFor="policy-description">
										<T id="npmos.policy.description" />
									</label>
									<input
										id="policy-description"
										className="form-control"
										value={description}
										maxLength={500}
										onChange={(e) => setDescription(e.target.value)}
									/>
								</div>
							</div>
							<ObjectForm kind={kind} spec={spec} onChange={setSpec} objects={objects} />
						</fieldset>
					)}
				</Modal.Body>
				<Modal.Footer>
					{preview ? (
						<>
							<Button onClick={() => setPreview(null)} disabled={busy}>
								<T id="npmos.policy.back" />
							</Button>
							<Button actionType="primary" isLoading={busy} disabled={!preview.valid} onClick={save}>
								<T id="npmos.policy.apply" />
							</Button>
						</>
					) : (
						<>
							<Button onClick={remove} disabled={busy}>
								<T id="cancel" />
							</Button>
							{!readOnly && (
								<Button actionType="primary" isLoading={busy} onClick={review}>
									<T id="npmos.policy.review" />
								</Button>
							)}
						</>
					)}
				</Modal.Footer>
			</Modal>
		);
	},
);

export const showObjectModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(ObjectModal, props);
