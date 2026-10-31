// System → Settings → Migration: an installation of NPM, NPMplus or open-appsec-npm moves into
// NPMOS (backend: npmos/migration). Source → analysis → import → result.
import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import * as api from "src/api/backend/base";
import { T } from "src/locale";
import { showError } from "src/notifications";

type Stage = "idle" | "ready" | "importing" | "done" | "failed";

interface Warning {
	code: string;
	ids?: number[];
	names?: string[];
	count?: number;
	message?: string;
	hosts?: { table: string; id: number; error: string }[];
}

interface Analysis {
	kind: "npm" | "npmplus" | "open-appsec-npm";
	schema: { applied: number; last: string | null; upgraded: number; unknown: string[] };
	live: Record<string, number>;
	blocking: { table: string; count: number }[];
	users: { email: string; name: string; admin: boolean; disabled: boolean; exists: boolean }[];
	certificates: { id: number; provider: string; name: string; files?: boolean }[];
	files: { certbot: boolean; customCerts: boolean; customNginx: string[]; html: boolean; wafRules: number };
	warnings: Warning[];
}

interface MigrationState {
	stage: Stage;
	origin: { type: "archive" | "database"; engine?: string; host?: string; database?: string; files?: boolean } | null;
	analysis: Analysis | null;
	result: {
		users?: { added: string[]; matched: string[] };
		rows?: Record<string, number>;
		roles?: number;
		hashed?: number;
		certbot?: number;
		dnsCertificates?: number;
		customNginx?: string[];
		wafRules?: number;
		committed?: boolean;
		warnings: Warning[];
	} | null;
	error: string | null;
}

const URL = "/npmos/system/migration";
const getState = () => api.get({ url: URL }) as Promise<MigrationState>;

/** raw upload: the common client sends JSON only */
const upload = async (file: File): Promise<MigrationState> => {
	const response = await fetch(`/api${URL}/upload`, {
		method: "POST",
		headers: { "Content-Type": "application/octet-stream" },
		body: file,
	});
	const payload = await response.json().catch(() => ({}));
	if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
	return payload;
};

const ARCHIVE_NPM = "tar czf npm-backup.tgz -C /path/to/npm data letsencrypt";
const ARCHIVE_NPMPLUS = "tar czf npmplus-backup.tgz -C /path/to/npmplus/data .";
// [locale key, key in the (camelized) API response]
const HOSTS = [
	["proxy_host", "proxyHost"],
	["redirection_host", "redirectionHost"],
	["dead_host", "deadHost"],
	["stream", "stream"],
	["certificate", "certificate"],
	["access_list", "accessList"],
];

function WarningText({ w }: { w: Warning }) {
	const list = (w.ids ?? w.names ?? []).join(", ");
	return (
		<T id={`npmos.migration.warning.${w.code}`} data={{ list, count: w.count ?? 0, message: w.message ?? "" }} />
	);
}

function Source({ busy, run }: { busy: boolean; run: (fn: () => Promise<unknown>) => void }) {
	const input = useRef<HTMLInputElement>(null);
	const [db, setDb] = useState({ engine: "mariadb", host: "", port: "", user: "", password: "", database: "" });
	const field = (name: keyof typeof db, label: string, type = "text") => (
		<div className="col-sm-6 mb-2">
			<label className="form-label" htmlFor={`npmos-mig-${name}`}>
				<T id={label} />
			</label>
			<input
				id={`npmos-mig-${name}`}
				className="form-control"
				type={type}
				value={db[name]}
				autoComplete="off"
				onChange={(e) => setDb({ ...db, [name]: e.target.value })}
			/>
		</div>
	);
	return (
		<>
			<div className="card mb-3">
				<div className="card-body">
					<h3 className="card-title">
						<T id="npmos.migration.archive" />
					</h3>
					<p className="text-secondary">
						<T id="npmos.migration.archive.hint" />
					</p>
					<div className="mb-1 small">
						<T id="npmos.migration.archive.npm" />
					</div>
					<pre className="small">{ARCHIVE_NPM}</pre>
					<div className="mb-1 small">
						<T id="npmos.migration.archive.npmplus" />
					</div>
					<pre className="small">{ARCHIVE_NPMPLUS}</pre>
					<input
						ref={input}
						type="file"
						accept=".tgz,.gz,.tar,.sqlite"
						className="d-none"
						onChange={(e) => {
							const f = e.target.files?.[0];
							e.target.value = "";
							if (f) run(() => upload(f));
						}}
					/>
					<button
						type="button"
						className="btn btn-primary"
						disabled={busy}
						onClick={() => input.current?.click()}
					>
						{busy && <span className="spinner-border spinner-border-sm me-2" />}
						<T id="npmos.migration.upload" />
					</button>
				</div>
			</div>
			<div className="card">
				<div className="card-body">
					<h3 className="card-title">
						<T id="npmos.migration.database" />
					</h3>
					<p className="text-secondary">
						<T id="npmos.migration.database.hint" />
					</p>
					<div className="row">
						<div className="col-sm-6 mb-2">
							<label className="form-label" htmlFor="npmos-mig-engine">
								<T id="npmos.migration.database.engine" />
							</label>
							<select
								id="npmos-mig-engine"
								className="form-select"
								value={db.engine}
								onChange={(e) => setDb({ ...db, engine: e.target.value })}
							>
								<option value="mariadb">MariaDB / MySQL</option>
								<option value="postgres">PostgreSQL</option>
							</select>
						</div>
						{field("host", "npmos.migration.database.host")}
						{field("port", "npmos.migration.database.port")}
						{field("database", "npmos.migration.database.name")}
						{field("user", "npmos.migration.database.user")}
						{/* NPMOS: form wrapper (display:contents) so the password field is inside a form */}
						<form style={{ display: "contents" }} autoComplete="off" onSubmit={(e) => e.preventDefault()}>
							{field("password", "npmos.migration.database.password", "password")}
						</form>
					</div>
					<button
						type="button"
						className="btn btn-outline-primary"
						disabled={busy || !db.host || !db.user || !db.database}
						onClick={() =>
							run(() =>
								api.post({
									url: `${URL}/connect`,
									data: {
										engine: db.engine,
										host: db.host,
										user: db.user,
										password: db.password,
										database: db.database,
										...(db.port ? { port: Number(db.port) } : {}),
									},
								}),
							)
						}
					>
						<T id="npmos.migration.connect" />
					</button>
				</div>
			</div>
		</>
	);
}

function Review({
	state,
	busy,
	run,
}: {
	state: MigrationState;
	busy: boolean;
	run: (fn: () => Promise<unknown>) => void;
}) {
	const a = state.analysis as Analysis;
	const [history, setHistory] = useState(true);
	const [customNginx, setCustomNginx] = useState(true);
	const input = useRef<HTMLInputElement>(null);
	return (
		<>
			<Alert variant="info">
				<T
					id="npmos.migration.found"
					data={{ applied: a.schema.applied, upgraded: a.schema.upgraded }}
					tData={{ kind: `npmos.migration.kind.${a.kind}` }}
				/>
			</Alert>
			{a.blocking.length > 0 && (
				<Alert variant="danger">
					<T
						id="npmos.migration.blocking"
						data={{ list: a.blocking.map((b) => `${b.table} (${b.count})`).join(", ") }}
					/>
				</Alert>
			)}
			{a.warnings.map((w) => (
				<Alert key={w.code} variant="warning">
					<WarningText w={w} />
				</Alert>
			))}
			{state.origin?.type === "database" && !state.origin.files && (
				<Alert variant="secondary">
					<T id="npmos.migration.files-hint" />
					<input
						ref={input}
						type="file"
						accept=".tgz,.gz,.tar"
						className="d-none"
						onChange={(e) => {
							const f = e.target.files?.[0];
							e.target.value = "";
							if (f) run(() => upload(f));
						}}
					/>
					<button
						type="button"
						className="btn btn-sm btn-outline-secondary ms-2"
						disabled={busy}
						onClick={() => input.current?.click()}
					>
						<T id="npmos.migration.upload-files" />
					</button>
				</Alert>
			)}
			<div className="row">
				<div className="col-md-6">
					<h3 className="h4">
						<T id="npmos.migration.what" />
					</h3>
					<table className="table table-sm">
						<tbody>
							{HOSTS.map(([id, k]) => (
								<tr key={id}>
									<td>
										<T id={`npmos.migration.table.${id}`} />
									</td>
									<td className="text-end">{a.live[k] ?? 0}</td>
								</tr>
							))}
							<tr>
								<td>
									<T id="npmos.migration.custom-nginx" />
								</td>
								<td className="text-end font-monospace small">
									{a.files.customNginx.join(", ") || "—"}
								</td>
							</tr>
							<tr>
								<td>
									<T id="npmos.migration.waf-rules" />
								</td>
								<td className="text-end">{a.files.wafRules}</td>
							</tr>
						</tbody>
					</table>
				</div>
				<div className="col-md-6">
					<h3 className="h4">
						<T id="npmos.migration.users" />
					</h3>
					<table className="table table-sm">
						<tbody>
							{a.users.map((u) => (
								<tr key={u.email}>
									<td>{u.email}</td>
									<td className="text-end">
										{u.admin && (
											<span className="badge bg-blue-lt me-1">
												<T id="npmos.migration.user.admin" />
											</span>
										)}
										<span className={`badge ${u.exists ? "bg-secondary-lt" : "bg-green-lt"}`}>
											<T
												id={
													u.exists
														? "npmos.migration.user.exists"
														: "npmos.migration.user.new"
												}
											/>
										</span>
									</td>
								</tr>
							))}
						</tbody>
					</table>
				</div>
			</div>
			<div className="form-check">
				<input
					id="npmos-mig-history"
					className="form-check-input"
					type="checkbox"
					checked={history}
					onChange={(e) => setHistory(e.target.checked)}
				/>
				<label className="form-check-label" htmlFor="npmos-mig-history">
					<T id="npmos.migration.option.history" />
				</label>
			</div>
			{a.files.customNginx.length > 0 && (
				<div className="form-check">
					<input
						id="npmos-mig-nginx"
						className="form-check-input"
						type="checkbox"
						checked={customNginx}
						onChange={(e) => setCustomNginx(e.target.checked)}
					/>
					<label className="form-check-label" htmlFor="npmos-mig-nginx">
						<T id="npmos.migration.option.custom-nginx" />
					</label>
				</div>
			)}
			<div className="d-flex flex-wrap gap-2 mt-3">
				<button
					type="button"
					className="btn btn-primary"
					disabled={busy || a.blocking.length > 0}
					onClick={() =>
						run(() => api.post({ url: `${URL}/apply`, data: { history, custom_nginx: customNginx } }))
					}
				>
					<T id="npmos.migration.apply" />
				</button>
				<button
					type="button"
					className="btn btn-outline-secondary"
					disabled={busy}
					onClick={() => run(() => api.del({ url: URL }))}
				>
					<T id="npmos.migration.discard" />
				</button>
			</div>
		</>
	);
}

function Result({
	state,
	busy,
	run,
}: {
	state: MigrationState;
	busy: boolean;
	run: (fn: () => Promise<unknown>) => void;
}) {
	const r = state.result;
	return (
		<>
			{state.stage === "failed" ? (
				<Alert variant="danger">
					<T
						id={r?.committed ? "npmos.migration.failed-after" : "npmos.migration.failed"}
						data={{ message: state.error ?? "" }}
					/>
				</Alert>
			) : (
				<Alert variant="success">
					<T
						id="npmos.migration.done"
						data={{
							hosts: HOSTS.slice(0, 4).reduce((n, [, k]) => n + (r?.rows?.[k] ?? 0), 0),
							certificates: r?.rows?.certificate ?? 0,
							users: r?.users?.added.length ?? 0,
						}}
					/>
				</Alert>
			)}
			{(r?.users?.matched.length ?? 0) > 0 && (
				<Alert variant="secondary">
					<T id="npmos.migration.matched" data={{ list: r?.users?.matched.join(", ") }} />
				</Alert>
			)}
			{(r?.hashed ?? 0) > 0 && (
				<Alert variant="secondary">
					<T id="npmos.migration.hashed" data={{ count: r?.hashed }} />
				</Alert>
			)}
			{(r?.dnsCertificates ?? 0) > 0 && (
				<Alert variant="warning">
					<T id="npmos.migration.restart" />
				</Alert>
			)}
			{r?.warnings.map((w) => (
				<Alert key={w.code} variant="warning">
					<WarningText w={w} />
					{w.hosts && (
						<ul className="mb-0 mt-1">
							{w.hosts.map((h) => (
								<li key={`${h.table}-${h.id}`} className="small">
									{h.table} #{h.id}: <span className="font-monospace">{h.error}</span>
								</li>
							))}
						</ul>
					)}
				</Alert>
			))}
			<p className="text-secondary">
				<T id="npmos.migration.after" />
			</p>
			<button
				type="button"
				className="btn btn-outline-secondary"
				disabled={busy}
				onClick={() => run(() => api.del({ url: URL }))}
			>
				<T id="npmos.migration.finish" />
			</button>
		</>
	);
}

export function MigrationForm({ canManage }: { canManage: boolean }) {
	const query = useQuery({
		queryKey: ["npmos-migration"],
		queryFn: getState,
		refetchInterval: (q) => (q.state.data?.stage === "importing" ? 2000 : false),
	});
	const [busy, setBusy] = useState(false);
	const run = async (fn: () => Promise<unknown>) => {
		setBusy(true);
		try {
			await fn();
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(false);
		query.refetch();
	};
	const state = query.data;
	return (
		<div className="p-4">
			<p className="text-secondary">
				<T id="npmos.migration.hint" />
			</p>
			{query.isError && <Alert variant="danger">{(query.error as Error).message}</Alert>}
			{!canManage && (
				<Alert variant="secondary">
					<T id="npmos.migration.forbidden" />
				</Alert>
			)}
			{canManage && state?.stage === "idle" && <Source busy={busy} run={run} />}
			{canManage && state?.stage === "ready" && state.analysis && <Review state={state} busy={busy} run={run} />}
			{state?.stage === "importing" && (
				<div className="d-flex align-items-center gap-2">
					<span className="spinner-border spinner-border-sm" />
					<T id="npmos.migration.importing" />
				</div>
			)}
			{canManage && (state?.stage === "done" || state?.stage === "failed") && (
				<Result state={state} busy={busy} run={run} />
			)}
			{busy && state?.stage === "idle" && (
				<p className="text-secondary mt-2">
					<T id="npmos.migration.reading" />
				</p>
			)}
		</div>
	);
}
