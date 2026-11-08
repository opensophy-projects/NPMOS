// A local blocklist: a file of IPs and CIDRs, or a URL downloaded on a schedule (another NginxionS node
// with its token, or any list in the same format). Saving downloads it and replaces its decisions.
import EasyModal, { type InnerModalProps } from "ez-modal-react";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import Modal from "react-bootstrap/Modal";
import { Button } from "src/components";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { type Blocklist, type BlocklistData, DECISION_TYPES, DURATIONS, saveBlocklist } from "./api";
import { HiddenUsername } from "../ui/HiddenUsername";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const MAX_FILE = 20 * 1024 * 1024;
/** example in the field (technical, not translated) */
const EXAMPLE_URL = "https://nginxions-2.example.com/api/nginxions/crowdsec/public/decisions";

interface Props extends InnerModalProps {
	list?: Blocklist;
	onDone: () => void;
}

const BlocklistModal = EasyModal.create(({ visible, remove, list, onDone }: Props) => {
	const [data, setData] = useState<BlocklistData>({
		name: list?.name ?? "",
		enabled: list?.enabled ?? true,
		source: list?.source ?? "file",
		url: list?.url ?? "",
		insecure: list?.insecure ?? false,
		decision: list?.decision ?? "ban",
		duration: list?.duration ?? "24h",
		refreshMinutes: list?.refreshMinutes ?? 60,
	});
	const [token, setToken] = useState("");
	const [content, setContent] = useState<string | undefined>(undefined);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const set = (patch: Partial<BlocklistData>) => setData({ ...data, ...patch });

	const readFile = async (file?: File) => {
		if (!file) return;
		if (file.size > MAX_FILE) {
			setError(t("nginxions.crowdsec.blocklist.too-large"));
			return;
		}
		setContent(await file.text());
		if (!data.name)
			set({
				name: file.name
					.replace(/\.[^.]+$/, "")
					.replace(/[^A-Za-z0-9 _.-]/g, "-")
					.slice(0, 64),
			});
	};

	const submit = async () => {
		setBusy(true);
		setError(null);
		try {
			const body: BlocklistData =
				data.source === "url"
					? { ...data, ...(token || !list ? { token } : {}) }
					: {
							name: data.name,
							enabled: data.enabled,
							source: "file",
							decision: data.decision,
							duration: data.duration,
						};
			const saved = await saveBlocklist(list?.id ?? null, body, data.source === "file" ? content : undefined);
			if (saved.sync?.error)
				showError(t("nginxions.crowdsec.blocklist.sync-failed", { error: saved.sync.error }));
			else showSuccess(t("nginxions.crowdsec.blocklist.saved", { count: saved.count }));
			onDone();
			remove();
		} catch (err: any) {
			setError(err.message);
			setBusy(false);
		}
	};

	const canSave = data.name && (data.source === "url" ? /^https?:\/\//.test(data.url || "") : list || content);

	return (
		<Modal show={visible} onHide={remove} size="lg">
			<Modal.Header closeButton>
				<Modal.Title>
					<T id={list ? "nginxions.crowdsec.blocklist.edit" : "nginxions.crowdsec.blocklist.add"} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{error && <Alert variant="danger">{error}</Alert>}
				<div className="row">
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-bl-name">
							<T id="nginxions.crowdsec.name" />
						</label>
						<input
							id="cs-bl-name"
							className="form-control"
							maxLength={64}
							value={data.name}
							onChange={(e) => set({ name: e.target.value })}
						/>
					</div>
					<div className="col-md-6 mb-3">
						<span className="form-label">
							<T id="nginxions.crowdsec.blocklist.source" />
						</span>
						<div className="btn-group w-100">
							{(["file", "url"] as const).map((s) => (
								<button
									key={s}
									type="button"
									disabled={!!list}
									className={`btn ${data.source === s ? "btn-primary" : "btn-outline-secondary"}`}
									onClick={() => set({ source: s })}
								>
									<T id={`nginxions.crowdsec.blocklist.source.${s}`} />
								</button>
							))}
						</div>
					</div>
				</div>
				{data.source === "file" ? (
					<div className="mb-3">
						<label className="form-label" htmlFor="cs-bl-file">
							<T
								id={
									list
										? "nginxions.crowdsec.blocklist.file.replace"
										: "nginxions.crowdsec.blocklist.file"
								}
							/>
						</label>
						<input
							id="cs-bl-file"
							type="file"
							accept=".txt,.csv,.list,text/plain"
							className="form-control"
							onChange={(e) => readFile(e.target.files?.[0])}
						/>
						<div className="form-hint">
							<T id="nginxions.crowdsec.blocklist.format" />
						</div>
					</div>
				) : (
					<>
						<div className="mb-3">
							<label className="form-label" htmlFor="cs-bl-url">
								<T id="nginxions.crowdsec.blocklist.url" />
							</label>
							<input
								id="cs-bl-url"
								className="form-control"
								placeholder={EXAMPLE_URL}
								value={data.url}
								onChange={(e) => set({ url: e.target.value.trim() })}
							/>
							<div className="form-hint">
								<T id="nginxions.crowdsec.blocklist.url.hint" />
							</div>
						</div>
						<div className="row">
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="cs-bl-token">
									<T id="nginxions.crowdsec.blocklist.token" />
								</label>
								{/* NginxionS: inside a form with a user field, so the browser does not warn about the password */}
								<form
									style={{ display: "contents" }}
									autoComplete="off"
									onSubmit={(e) => e.preventDefault()}
								>
									<HiddenUsername />
									<input
										id="cs-bl-token"
										type="password"
										autoComplete="off"
										className="form-control"
										placeholder={list?.hasToken ? t("nginxions.crowdsec.secret.kept") : ""}
										value={token}
										onChange={(e) => setToken(e.target.value)}
									/>
								</form>
							</div>
							<div className="col-md-6 mb-3">
								<label className="form-label" htmlFor="cs-bl-refresh">
									<T id="nginxions.crowdsec.blocklist.refresh" />
								</label>
								<select
									id="cs-bl-refresh"
									className="form-select"
									value={data.refreshMinutes}
									onChange={(e) => set({ refreshMinutes: Number(e.target.value) })}
								>
									{[0, 15, 60, 360, 1440].map((m) => (
										<option key={m} value={m}>
											{t(`nginxions.crowdsec.blocklist.refresh.${m}`)}
										</option>
									))}
								</select>
							</div>
						</div>
						<label className="form-check mb-3">
							<input
								type="checkbox"
								className="form-check-input"
								checked={!!data.insecure}
								onChange={(e) => set({ insecure: e.target.checked })}
							/>
							<span className="form-check-label">
								<T id="nginxions.crowdsec.blocklist.insecure" />
							</span>
							<span className="form-check-description">
								<T id="nginxions.crowdsec.blocklist.insecure.hint" />
							</span>
						</label>
					</>
				)}
				<div className="row">
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-bl-decision">
							<T id="nginxions.crowdsec.decision" />
						</label>
						<select
							id="cs-bl-decision"
							className="form-select"
							value={data.decision}
							onChange={(e) => set({ decision: e.target.value })}
						>
							{DECISION_TYPES.map((d) => (
								<option key={d} value={d}>
									{t(`nginxions.crowdsec.decision.${d}`)}
								</option>
							))}
						</select>
					</div>
					<div className="col-md-6 mb-3">
						<label className="form-label" htmlFor="cs-bl-duration">
							<T id="nginxions.crowdsec.duration" />
						</label>
						<select
							id="cs-bl-duration"
							className="form-select"
							value={data.duration}
							onChange={(e) => set({ duration: e.target.value })}
						>
							{DURATIONS.map((d) => (
								<option key={d} value={d}>
									{t(`nginxions.crowdsec.duration.${d}`)}
								</option>
							))}
						</select>
						<div className="form-hint">
							<T id="nginxions.crowdsec.blocklist.duration.hint" />
						</div>
					</div>
				</div>
				<label className="form-check">
					<input
						type="checkbox"
						className="form-check-input"
						checked={data.enabled}
						onChange={(e) => set({ enabled: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="nginxions.crowdsec.blocklist.enabled" />
					</span>
				</label>
			</Modal.Body>
			<Modal.Footer>
				<Button onClick={remove} disabled={busy}>
					<T id="cancel" />
				</Button>
				<Button actionType="primary" className="ms-auto" isLoading={busy} disabled={!canSave} onClick={submit}>
					<T id="save" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export const showBlocklistModal = (props: Omit<Props, keyof InnerModalProps>) => EasyModal.show(BlocklistModal, props);
