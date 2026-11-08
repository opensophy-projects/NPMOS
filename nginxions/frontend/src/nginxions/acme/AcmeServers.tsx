// Settings → ACME → Servers: where ACME certificates come from. A preset (Let's Encrypt, ZeroSSL, Google, SSL.com,
// the TLS CA of the Russian Federation) or a server of your own; each says its client (certbot or lego) and may be
// the default one, which the certificate forms choose first.
import { useQueryClient } from "@tanstack/react-query";
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import {
	type AcmeClient,
	type AcmePreset,
	type AcmeServer,
	type AcmeServerInput,
	createAcmeServer,
	deleteAcmeServer,
	SECRET_SET,
	setDefaultAcmeServer,
	updateAcmeServer,
	useAcmeServers,
} from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

interface Props {
	server?: AcmeServer;
	presets: AcmePreset[];
	onSaved: () => void;
}

const ServerModal = EasyModal.create(({ visible, remove, server, presets, onSaved }: InnerModalProps & Props) => {
	const [v, setV] = useState<AcmeServerInput>(
		server
			? { ...server }
			: {
					preset: presets[0]?.id ?? "custom",
					name: presets[0]?.name ?? "",
					client: presets[0]?.client ?? "certbot",
					tlsVerify: true,
					email: "",
					eabKid: "",
					eabHmacKey: "",
					profile: "",
				},
	);
	const [error, setError] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const preset = presets.find((p) => p.id === v.preset);
	const set = (patch: AcmeServerInput) => setV((old) => ({ ...old, ...patch }));

	const save = async () => {
		setSaving(true);
		setError(null);
		try {
			const body: AcmeServerInput = { ...v };
			delete (body as any).id;
			delete (body as any).usedBy;
			delete (body as any).isDefault;
			if (preset) delete body.directory;
			if (server) await updateAcmeServer(server.id, body);
			else await createAcmeServer(body);
			onSaved();
			remove();
		} catch (err: any) {
			setError(err.message);
		}
		setSaving(false);
	};

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={server ? "nginxions.acme.servers.edit" : "nginxions.acme.servers.add"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible>
					{error}
				</Alert>
				<form onSubmit={(e) => e.preventDefault()} autoComplete="off">
					<div className="row g-3">
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-preset">
								<T id="nginxions.acme.servers.preset" />
							</label>
							<select
								id="acme-preset"
								className="form-select"
								value={v.preset}
								onChange={(e) => {
									const p = presets.find((x) => x.id === e.target.value);
									set({
										preset: e.target.value,
										name: p ? p.name : v.name,
										client: p ? p.client : v.client,
										directory: p ? p.directory : "",
									});
								}}
							>
								{presets.map((p) => (
									<option key={p.id} value={p.id}>
										{p.name}
									</option>
								))}
								<option value="custom">{t("nginxions.acme.servers.custom")}</option>
							</select>
						</div>
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-name">
								<T id="nginxions.acme.servers.name" />
							</label>
							<input
								id="acme-name"
								className="form-control"
								value={v.name ?? ""}
								onChange={(e) => set({ name: e.target.value })}
							/>
						</div>
						<div className="col-12">
							<label className="form-label" htmlFor="acme-directory">
								<T id="nginxions.acme.servers.directory" />
							</label>
							<input
								id="acme-directory"
								type="url"
								className="form-control font-monospace"
								placeholder={t("nginxions.acme.servers.directory-placeholder")}
								value={preset ? preset.directory : (v.directory ?? "")}
								disabled={!!preset}
								onChange={(e) => set({ directory: e.target.value.trim() })}
							/>
							{preset?.caa && (
								<div className="form-hint">
									<T id="nginxions.acme.servers.caa" data={{ caa: preset.caa }} />
								</div>
							)}
						</div>
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-client">
								<T id="nginxions.acme.servers.client" />
							</label>
							<select
								id="acme-client"
								className="form-select"
								value={v.client}
								onChange={(e) => set({ client: e.target.value as AcmeClient })}
							>
								<option value="certbot" disabled={preset?.legoOnly}>
									{t("nginxions.acme.client.certbot")}
								</option>
								<option value="lego">{t("nginxions.acme.client.lego")}</option>
							</select>
							<div className="form-hint">
								<T id={`nginxions.acme.servers.client-hint.${v.client}`} />
							</div>
						</div>
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-email">
								<T id="nginxions.acme.servers.email" />
							</label>
							<input
								id="acme-email"
								type="email"
								className="form-control"
								value={v.email ?? ""}
								onChange={(e) => set({ email: e.target.value.trim() })}
							/>
							<div className="form-hint">
								<T
									id={
										preset?.eab === "auto"
											? "nginxions.acme.servers.email-zerossl"
											: "nginxions.acme.servers.email-hint"
									}
								/>
							</div>
						</div>
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-kid">
								<T id="nginxions.acme.servers.eab-kid" />
							</label>
							<input
								id="acme-kid"
								className="form-control font-monospace"
								value={v.eabKid ?? ""}
								onChange={(e) => set({ eabKid: e.target.value.trim() })}
							/>
						</div>
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-hmac">
								<T id="nginxions.acme.servers.eab-hmac" />
							</label>
							<input
								id="acme-hmac"
								type="password"
								autoComplete="new-password"
								className="form-control font-monospace"
								value={v.eabHmacKey ?? ""}
								onFocus={() => v.eabHmacKey === SECRET_SET && set({ eabHmacKey: "" })}
								onChange={(e) => set({ eabHmacKey: e.target.value.trim() })}
							/>
						</div>
						<div className="col-12">
							<div className="form-hint mt-n2">
								<T
									id={
										preset?.eab === "required"
											? "nginxions.acme.servers.eab-required"
											: "nginxions.acme.servers.eab-hint"
									}
								/>
							</div>
						</div>
						<div className="col-md-6">
							<label className="form-label" htmlFor="acme-profile">
								<T id="nginxions.acme.servers.profile" />
							</label>
							<input
								id="acme-profile"
								className="form-control"
								list="acme-profiles"
								placeholder={t("nginxions.acme.servers.profile-default")}
								value={v.profile ?? ""}
								onChange={(e) => set({ profile: e.target.value.trim() })}
							/>
							<datalist id="acme-profiles">
								{(preset?.profiles ?? []).map((p) => (
									<option key={p} value={p} />
								))}
							</datalist>
							<div className="form-hint">
								<T id="nginxions.acme.servers.profile-hint" />
							</div>
						</div>
						<div className="col-md-6">
							<label className="form-check form-switch mt-4">
								<input
									type="checkbox"
									className="form-check-input"
									checked={v.tlsVerify !== false}
									onChange={(e) => set({ tlsVerify: e.target.checked })}
								/>
								<span className="form-check-label">
									<T id="nginxions.acme.servers.tls-verify" />
								</span>
							</label>
							<div className="form-hint">
								<T id="nginxions.acme.servers.tls-verify-hint" />
							</div>
						</div>
					</div>
				</form>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={saving}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" className="ms-auto" isLoading={saving} onClick={save}>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export function AcmeServers({ canManage }: { canManage: boolean }) {
	const queryClient = useQueryClient();
	const { data, isLoading } = useAcmeServers();
	const refresh = () => queryClient.invalidateQueries({ queryKey: ["nginxions-acme-servers"] });
	const open = (server?: AcmeServer) =>
		EasyModal.show(ServerModal, { server, presets: data?.presets ?? [], onSaved: refresh });

	const act = async (fn: () => Promise<unknown>, done: string) => {
		try {
			await fn();
			showSuccess(t(done));
			refresh();
		} catch (err: any) {
			showError(err.message);
		}
	};

	return (
		<div className="px-4 pt-4">
			<div className="d-flex align-items-start mb-2">
				<div>
					<h3 className="h4 mb-1">
						<T id="nginxions.acme.servers.title" />
					</h3>
					<p className="text-secondary small mb-0">
						<T id="nginxions.acme.servers.description" />
					</p>
				</div>
				{canManage && (
					<Button actionType="primary" className="ms-3 flex-shrink-0 text-nowrap" onClick={() => open()}>
						<T id="nginxions.acme.servers.add" />
					</Button>
				)}
			</div>
			<div className="table-responsive">
				<table className="table table-vcenter card-table">
					<thead>
						<tr>
							<th>
								<T id="nginxions.acme.servers.name" />
							</th>
							<th>
								<T id="nginxions.acme.servers.directory" />
							</th>
							<th>
								<T id="nginxions.acme.servers.client" />
							</th>
							<th>
								<T id="nginxions.acme.servers.used" />
							</th>
							<th />
						</tr>
					</thead>
					<tbody>
						{isLoading && (
							<tr>
								<td colSpan={5} className="text-secondary">
									<T id="loading" />
								</td>
							</tr>
						)}
						{(data?.items ?? []).map((s) => (
							<tr key={s.id}>
								<td>
									{s.name}
									{s.isDefault && (
										<span className="badge bg-green-lt ms-2">
											<T id="nginxions.acme.server.default" />
										</span>
									)}
								</td>
								<td className="font-monospace small text-break">{s.directory}</td>
								<td>
									<T id={`nginxions.acme.client.${s.client}`} />
								</td>
								<td>{s.usedBy}</td>
								<td className="text-end text-nowrap">
									{canManage && (
										<>
											{!s.isDefault && (
												<button
													type="button"
													className="btn btn-sm me-2"
													onClick={() =>
														act(
															() => setDefaultAcmeServer(s.id),
															"nginxions.acme.servers.default-set",
														)
													}
												>
													<T id="nginxions.acme.servers.make-default" />
												</button>
											)}
											<button type="button" className="btn btn-sm me-2" onClick={() => open(s)}>
												<T id="action.edit" />
											</button>
											{!s.isDefault && (
												<button
													type="button"
													className="btn btn-sm btn-ghost-danger"
													disabled={s.usedBy > 0}
													title={
														s.usedBy > 0 ? t("nginxions.acme.servers.in-use") : undefined
													}
													onClick={() =>
														act(
															() => deleteAcmeServer(s.id),
															"nginxions.acme.servers.deleted",
														)
													}
												>
													<T id="action.delete" />
												</button>
											)}
										</>
									)}
								</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
	);
}
