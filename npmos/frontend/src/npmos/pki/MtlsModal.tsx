// mTLS of a proxy host or stream: trusted CAs (trust domains), required everywhere or on chosen
// locations, rules on fields of the client certificate, X-Client-* headers to the upstream.
import { IconPlus, IconTrash } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { useCan } from "../rbac/hooks";
import {
	fromApiRule,
	getMtlsHost,
	getPki,
	type MtlsBinding,
	type MtlsHost,
	type MtlsHostType,
	type MtlsRule,
	type PkiCa,
	type PkiOverview,
	RULE_FIELDS,
	type RuleField,
	setMtlsHost,
} from "./api";
import { showCaModal } from "./CaModal";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props extends InnerModalProps {
	type: MtlsHostType;
	hostId: number;
	onDone: () => void;
}

/** CAs as a tree: roots with their trust domains, then external CAs */
const ordered = (cas: PkiCa[]) => {
	const roots = cas.filter((ca) => ca.kind === "root");
	return [
		...roots.flatMap((root) => [
			{ ca: root, depth: 0 },
			...cas.filter((ca) => ca.parentId === root.id).map((ca) => ({ ca, depth: 1 })),
		]),
		...cas.filter((ca) => ca.kind === "external").map((ca) => ({ ca, depth: 0 })),
	];
};

function MtlsForm({
	host,
	pki,
	type,
	id,
	onSaved,
	onCaCreated,
}: {
	host: MtlsHost;
	pki: PkiOverview;
	type: MtlsHostType;
	id: number;
	onSaved: () => void;
	onCaCreated: () => Promise<unknown>;
}) {
	const can = useCan();
	const cas = pki.cas;
	const [value, setValue] = useState<MtlsBinding>({
		enabled: host.enabled || !host.caIds.length,
		caIds: host.caIds,
		mode: host.mode,
		depth: host.depth,
		sendCaNames: host.sendCaNames,
		rules: host.rules.map((r) => fromApiRule(r as any)),
		requiredPaths: host.requiredPaths,
		headers: host.headers,
		revocation: host.revocation ?? "crl",
	});
	const [advanced, setAdvanced] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const proxy = type === "proxy_host";

	const toggleCa = (caId: number) =>
		setValue((v) => ({
			...v,
			caIds: v.caIds.includes(caId) ? v.caIds.filter((x) => x !== caId) : [...v.caIds, caId],
		}));
	const setRule = (i: number, rule: Partial<MtlsRule>) =>
		setValue((v) => ({ ...v, rules: v.rules.map((r, j) => (j === i ? { ...r, ...rule } : r)) }));

	const save = async () => {
		setBusy(true);
		setError(null);
		try {
			// a rule without values is not finished: left out
			const saved = await setMtlsHost(type, id, { ...value, rules: value.rules.filter((r) => r.values.length) });
			if (saved.nginx && !saved.nginx.nginxOnline) {
				setError(t("npmos.mtls.nginx-error", { error: saved.nginx.nginxErr ?? "" }));
				setBusy(false);
				return;
			}
			showSuccess(t("npmos.mtls.saved"));
			onSaved();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	const newDomain = () =>
		showCaModal({
			data: pki,
			mode: "intermediate",
			name: host.name.split(",")[0].trim().slice(0, 100),
			onDone: async (ca) => {
				await onCaCreated();
				setValue((v) => ({ ...v, enabled: true, caIds: [...v.caIds, ca.id] }));
			},
		});

	return (
		<>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				{!host.hasCertificate && (
					<Alert variant="warning">
						<T id="npmos.hosts.mtls.needs-tls" />
					</Alert>
				)}
				{host.upstreamCaCertificateId && (
					<Alert variant="info">
						<T id="npmos.mtls.replaces-upstream" />
					</Alert>
				)}
				<label className="form-check form-switch mb-3">
					<input
						type="checkbox"
						className="form-check-input"
						checked={value.enabled}
						onChange={(e) => setValue({ ...value, enabled: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="npmos.mtls.enabled" />
					</span>
				</label>

				<div className="mb-3">
					<div className="d-flex align-items-center justify-content-between mb-1">
						<span className="form-label mb-0">
							<T id="npmos.mtls.cas" />
						</span>
						{can("pki", "manage") && cas.some((ca) => ca.kind === "root" && ca.hasKey) && (
							<button type="button" className="btn btn-sm" onClick={newDomain}>
								<IconPlus size={14} className="me-1" />
								<T id="npmos.mtls.new-domain" />
							</button>
						)}
					</div>
					{cas.length === 0 ? (
						<Alert variant="warning" className="mb-0">
							<T id="npmos.mtls.no-cas" />
						</Alert>
					) : (
						<div className="border rounded p-2">
							{ordered(cas).map(({ ca, depth }) => (
								<label className="form-check mb-1" key={ca.id} style={{ marginLeft: depth * 24 }}>
									<input
										type="checkbox"
										className="form-check-input"
										checked={value.caIds.includes(ca.id)}
										onChange={() => toggleCa(ca.id)}
									/>
									<span className="form-check-label">
										{ca.name}
										<span className="text-secondary small ms-2">
											<T id={`npmos.pki.ca.kind.${ca.kind}`} />
										</span>
									</span>
								</label>
							))}
						</div>
					)}
					<div className="form-hint">
						<T id={host.issuerCheck ? "npmos.mtls.cas.hint" : "npmos.mtls.cas.stream-hint"} />
					</div>
				</div>

				{proxy && (
					<div className="mb-3">
						<span className="form-label d-block">
							<T id="npmos.mtls.mode" />
						</span>
						<div className="btn-group">
							{(["on", "optional"] as const).map((m) => (
								<button
									key={m}
									type="button"
									className={`btn ${value.mode === m ? "btn-primary" : ""}`}
									onClick={() => setValue({ ...value, mode: m })}
								>
									<T id={`npmos.mtls.mode.${m}`} />
								</button>
							))}
						</div>
						<div className="form-hint">
							<T id={`npmos.mtls.mode.${value.mode}.hint`} />
						</div>
						{value.mode === "optional" && (
							<div className="border rounded p-2 mt-2">
								<div className="small text-secondary mb-1">
									<T id="npmos.mtls.required-paths" />
								</div>
								{host.paths.map((p) => (
									<label className="form-check mb-1" key={p}>
										<input
											type="checkbox"
											className="form-check-input"
											checked={value.requiredPaths.includes(p)}
											onChange={(e) =>
												setValue({
													...value,
													requiredPaths: e.target.checked
														? [...value.requiredPaths, p]
														: value.requiredPaths.filter((x) => x !== p),
												})
											}
										/>
										<span className="form-check-label font-monospace">{p}</span>
									</label>
								))}
							</div>
						)}
					</div>
				)}

				{proxy && (
					<div className="mb-3">
						<div className="d-flex align-items-center justify-content-between mb-1">
							<span className="form-label mb-0">
								<T id="npmos.mtls.rules" />
							</span>
							<button
								type="button"
								className="btn btn-sm"
								onClick={() =>
									setValue({
										...value,
										rules: [
											...value.rules,
											{ field: "organizationalUnit", op: "one_of", values: [] },
										],
									})
								}
							>
								<IconPlus size={14} className="me-1" />
								<T id="npmos.mtls.rule.add" />
							</button>
						</div>
						{value.rules.length === 0 ? (
							<div className="text-secondary small">
								<T id="npmos.mtls.rules.none" />
							</div>
						) : (
							value.rules.map((rule, i) => (
								<div className="d-flex gap-2 mb-2" key={`${i}-${rule.field}`}>
									<select
										className="form-select form-select-sm w-auto"
										aria-label={t("npmos.mtls.rule.field")}
										value={rule.field}
										onChange={(e) => setRule(i, { field: e.target.value as RuleField })}
									>
										{RULE_FIELDS.map((f) => (
											<option key={f} value={f}>
												{t(`npmos.mtls.field.${f}`)}
											</option>
										))}
									</select>
									<select
										className="form-select form-select-sm w-auto"
										aria-label={t("npmos.mtls.rule.op")}
										value={rule.op}
										onChange={(e) => setRule(i, { op: e.target.value as MtlsRule["op"] })}
									>
										<option value="one_of">{t("npmos.mtls.op.one_of")}</option>
										<option value="regex">{t("npmos.mtls.op.regex")}</option>
									</select>
									<input
										className="form-control form-control-sm font-monospace"
										aria-label={t("npmos.mtls.rule.values")}
										placeholder={t(
											rule.op === "regex" ? "npmos.mtls.rule.regex" : "npmos.mtls.rule.list",
										)}
										defaultValue={rule.op === "regex" ? rule.values[0] : rule.values.join(", ")}
										onBlur={(e) =>
											setRule(i, {
												values:
													rule.op === "regex"
														? [e.target.value.trim()].filter(Boolean)
														: e.target.value
																.split(",")
																.map((s) => s.trim())
																.filter(Boolean),
											})
										}
									/>
									<button
										type="button"
										className="btn btn-sm btn-ghost-danger"
										aria-label={t("npmos.mtls.rule.remove")}
										onClick={() =>
											setValue({ ...value, rules: value.rules.filter((_, j) => j !== i) })
										}
									>
										<IconTrash size={14} />
									</button>
								</div>
							))
						)}
						<div className="form-hint">
							<T id="npmos.mtls.rules.hint" />
						</div>
					</div>
				)}

				{proxy && (
					<div className="mb-3">
						<span className="form-label d-block">
							<T id="npmos.mtls.revocation" />
						</span>
						<div className="btn-group">
							{(["crl", "ocsp"] as const).map((r) => (
								<button
									key={r}
									type="button"
									className={`btn ${value.revocation === r ? "btn-primary" : ""}`}
									onClick={() => setValue({ ...value, revocation: r })}
								>
									<T id={`npmos.mtls.revocation.${r}`} />
								</button>
							))}
						</div>
						<div className="form-hint">
							<T id={`npmos.mtls.revocation.${value.revocation}.hint`} />
						</div>
					</div>
				)}

				<button type="button" className="btn btn-link px-0" onClick={() => setAdvanced(!advanced)}>
					<T id={advanced ? "npmos.mtls.advanced.hide" : "npmos.mtls.advanced"} />
				</button>
				{advanced && (
					<div className="mt-2">
						<div className="mb-2 d-flex align-items-center gap-2">
							<label className="form-label mb-0" htmlFor="mtls-depth">
								<T id="npmos.mtls.depth" />
							</label>
							<input
								id="mtls-depth"
								type="number"
								min={1}
								max={5}
								className="form-control form-control-sm w-auto"
								value={value.depth}
								onChange={(e) => setValue({ ...value, depth: Number(e.target.value) })}
							/>
						</div>
						<label className="form-check">
							<input
								type="checkbox"
								className="form-check-input"
								checked={value.sendCaNames}
								onChange={(e) => setValue({ ...value, sendCaNames: e.target.checked })}
							/>
							<span className="form-check-label">
								<T id="npmos.mtls.send-ca-names" />
							</span>
							<span className="form-check-description">
								<T id="npmos.mtls.send-ca-names.hint" />
							</span>
						</label>
						{proxy && (
							<label className="form-check">
								<input
									type="checkbox"
									className="form-check-input"
									checked={value.headers}
									onChange={(e) => setValue({ ...value, headers: e.target.checked })}
								/>
								<span className="form-check-label">
									<T id="npmos.mtls.headers" />
								</span>
								<span className="form-check-description">
									<T id="npmos.mtls.headers.hint" />
								</span>
							</label>
						)}
					</div>
				)}
			</Modal.Body>
			<Modal.Footer>
				<Button
					actionType="primary"
					isLoading={busy}
					disabled={!host.hasCertificate && value.enabled}
					onClick={save}
				>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</>
	);
}

const MtlsModal = EasyModal.create(({ visible, remove, type, hostId: id, onDone }: Props) => {
	const host = useQuery({ queryKey: ["npmos-mtls-host", type, id], queryFn: () => getMtlsHost(type, id) });
	const pki = useQuery({ queryKey: ["npmos-pki"], queryFn: getPki });
	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="npmos.mtls.title" />
					{host.data && <span className="text-secondary ms-2">{host.data.name}</span>}
				</Modal.Title>
			</Modal.Header>
			{host.error || pki.error ? (
				<Modal.Body>
					<Alert variant="danger">{(host.error || pki.error)?.message}</Alert>
				</Modal.Body>
			) : host.data && pki.data ? (
				<MtlsForm
					host={host.data}
					pki={pki.data}
					type={type}
					id={id}
					onCaCreated={() => pki.refetch()}
					onSaved={() => {
						onDone();
						remove();
					}}
				/>
			) : (
				<Modal.Body>
					<LoadingPage noLogo />
				</Modal.Body>
			)}
		</Modal>
	);
});

export const showMtlsModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(MtlsModal, props);
