// System → Settings → GeoIP: the database that gives security events their countries. The one of
// CrowdSec (GeoLite2-City) is used until an administrator uploads another .mmdb file.
import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import * as api from "src/api/backend/base";
import { T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { t } from "../crowdsec/labels";
import { dateTime } from "../ui/time";

interface GeoipState {
	database: { source: "uploaded" | "crowdsec"; type: string; built: string | null; size: number } | null;
	uploaded: boolean;
}

const getGeoip = () => api.get({ url: "/npmos/system/geoip" }) as Promise<GeoipState>;

/** raw upload: the common client sends JSON only */
const upload = async (file: File): Promise<GeoipState> => {
	const response = await fetch("/api/npmos/system/geoip", {
		method: "POST",
		headers: { "Content-Type": "application/octet-stream" },
		body: file,
	});
	const payload = await response.json().catch(() => ({}));
	if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
	return payload;
};

export function GeoipForm({ canManage }: { canManage: boolean }) {
	const query = useQuery({ queryKey: ["npmos-geoip"], queryFn: getGeoip });
	const input = useRef<HTMLInputElement>(null);
	const [busy, setBusy] = useState(false);
	const db = query.data?.database;

	const run = async (fn: () => Promise<unknown>) => {
		setBusy(true);
		try {
			await fn();
			showSuccess(t("npmos.geoip.saved"));
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(false);
		query.refetch();
	};

	return (
		<div className="p-4">
			<p className="text-secondary">
				<T id="npmos.geoip.hint" />
			</p>
			{query.isError && <Alert variant="danger">{(query.error as Error).message}</Alert>}
			{query.data && !db && (
				<Alert variant="warning">
					<T id="npmos.geoip.none" />
				</Alert>
			)}
			{db && (
				<dl className="row mb-3">
					<dt className="col-sm-3">
						<T id="npmos.geoip.source" />
					</dt>
					<dd className="col-sm-9">
						<T id={`npmos.geoip.source.${db.source}`} />
					</dd>
					<dt className="col-sm-3">
						<T id="npmos.geoip.type" />
					</dt>
					<dd className="col-sm-9 font-monospace">{db.type || "—"}</dd>
					<dt className="col-sm-3">
						<T id="npmos.geoip.built" />
					</dt>
					<dd className="col-sm-9">{db.built ? dateTime(db.built) : "—"}</dd>
				</dl>
			)}
			{canManage && (
				<div className="d-flex flex-wrap gap-2">
					<input
						ref={input}
						type="file"
						accept=".mmdb"
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
						<T id="npmos.geoip.upload" />
					</button>
					{query.data?.uploaded && (
						<button
							type="button"
							className="btn btn-outline-danger"
							disabled={busy}
							onClick={() => run(() => api.del({ url: "/npmos/system/geoip" }))}
						>
							<T id="npmos.geoip.remove" />
						</button>
					)}
				</div>
			)}
		</div>
	);
}
