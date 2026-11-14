// WAF → Agent: File Security of the WAF policy (ClamAV in its own container, waf/files.js of the backend): whether clamd
// runs, its signatures, an upload of signature files (offline) and online updates (freshclam, needs the internet)
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { getWafFiles, setWafFiles, uploadClamavSignatures } from "../../api";
import { useCan } from "../../rbac/hooks";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const KEY = "nginxions-waf-files";

export function FileSecurityCard() {
	const can = useCan();
	const manage = can("waf_policy:manage");
	const queryClient = useQueryClient();
	const { data, isLoading, error } = useQuery({ queryKey: [KEY], queryFn: getWafFiles, refetchInterval: 30000 });
	const [failure, setFailure] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const fileRef = useRef<HTMLInputElement>(null);
	const refresh = () => queryClient.invalidateQueries({ queryKey: [KEY] });

	const run = async (action: () => Promise<unknown>, done: string) => {
		setBusy(true);
		setFailure(null);
		try {
			await action();
			showSuccess(t(done));
			await refresh();
		} catch (err: any) {
			setFailure(err.message);
		}
		setBusy(false);
	};

	return (
		<div className="card mt-4">
			<div className="card-header">
				<h3 className="card-title">
					<T id="nginxions.waf.files.title" />
				</h3>
			</div>
			<div className="card-body">
				<p className="text-secondary">
					<T id="nginxions.waf.files.text" />
				</p>
				<Alert variant="danger" show={!!(failure || error)} onClose={() => setFailure(null)} dismissible>
					{failure || (error as Error)?.message}
				</Alert>
				{isLoading || !data ? (
					<LoadingPage noLogo />
				) : (
					<>
						<dl className="row mb-3">
							<dt className="col-sm-4">
								<T id="nginxions.waf.files.state" />
							</dt>
							<dd className="col-sm-8">
								{!data.enabled ? (
									<T id="nginxions.waf.files.off" />
								) : data.clamd ? (
									<T id="nginxions.waf.files.on" data={{ hosts: data.hosts }} />
								) : (
									<span className="text-warning">
										<T id="nginxions.waf.files.starting" />
									</span>
								)}
							</dd>
							<dt className="col-sm-4">
								<T id="nginxions.waf.files.signatures" />
							</dt>
							<dd className="col-sm-8">
								{data.clamd ?? "—"}
								{data.uploaded.length > 0 && (
									<div className="text-secondary small">
										<T
											id="nginxions.waf.files.uploaded"
											data={{ files: data.uploaded.join(", ") }}
										/>
									</div>
								)}
							</dd>
						</dl>
						{manage && (
							<div className="d-flex flex-wrap gap-3 align-items-center">
								<label className="form-check form-switch mb-0">
									<input
										className="form-check-input"
										type="checkbox"
										disabled={busy}
										checked={data.settings.online_updates}
										onChange={(e) =>
											run(
												() => setWafFiles({ online_updates: e.target.checked }),
												"nginxions.waf.files.saved",
											)
										}
									/>
									<span className="form-check-label">
										<T id="nginxions.waf.files.online" />
									</span>
								</label>
								<input
									ref={fileRef}
									type="file"
									accept=".cvd,.cld,.cud"
									className="d-none"
									aria-label={t("nginxions.waf.files.upload")}
									onChange={(e) => {
										const file = e.target.files?.[0];
										if (fileRef.current) fileRef.current.value = "";
										if (file)
											run(() => uploadClamavSignatures(file), "nginxions.waf.files.uploaded-now");
									}}
								/>
								<Button isLoading={busy} disabled={busy} onClick={() => fileRef.current?.click()}>
									<T id="nginxions.waf.files.upload" />
								</Button>
							</div>
						)}
					</>
				)}
			</div>
		</div>
	);
}
