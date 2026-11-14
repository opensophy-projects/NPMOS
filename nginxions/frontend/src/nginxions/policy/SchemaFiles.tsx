// OpenAPI files of schemaValidation of a practice (WAF -> Policy): the files of NginxionS to choose from, an upload of
// a new one (chosen at once), the download and deletion of a file no practice names.
import { IconDownload, IconTrash, IconUpload } from "@tabler/icons-react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { intl, T } from "src/locale";
import { deleteSchemaFile, downloadSchemaFile, getSchemaFiles, uploadSchemaFile } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const KEY = "nginxions-waf-schemas";
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.(ya?ml|json)$/;

export function SchemaFiles({
	id,
	value,
	onChange,
}: {
	id: string;
	value: string[] | undefined;
	onChange: (files: string[]) => void;
}) {
	const queryClient = useQueryClient();
	const { data = [], error } = useQuery({ queryKey: [KEY], queryFn: getSchemaFiles });
	const [failure, setFailure] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const fileRef = useRef<HTMLInputElement>(null);
	const chosen = value ?? [];
	const refresh = () => queryClient.invalidateQueries({ queryKey: [KEY] });

	const upload = async (file: File | undefined) => {
		if (fileRef.current) fileRef.current.value = "";
		if (!file) return;
		setFailure(null);
		const name = file.name.replace(/[^A-Za-z0-9_.-]/g, "_");
		if (!NAME.test(name)) {
			setFailure(t("nginxions.policy.schemas.bad-name"));
			return;
		}
		setBusy(true);
		try {
			await uploadSchemaFile(name, file);
			if (!chosen.includes(name)) onChange([...chosen, name]);
			await refresh();
		} catch (err: any) {
			setFailure(err.message);
		}
		setBusy(false);
	};

	const remove = async (name: string) => {
		setFailure(null);
		try {
			await deleteSchemaFile(name);
			onChange(chosen.filter((n) => n !== name));
			await refresh();
		} catch (err: any) {
			setFailure(err.message);
		}
	};

	// a file named by the practice that the store does not have (deleted, or an imported policy)
	const missing = chosen.filter((n) => !data.some((f) => f.name === n));
	return (
		<div id={id}>
			{(failure || error) && <div className="text-danger small mb-2">{failure || (error as Error).message}</div>}
			{!data.length && !missing.length && (
				<div className="text-secondary small mb-2">
					<T id="nginxions.policy.schemas.empty" />
				</div>
			)}
			{data.map((f) => (
				<div className="d-flex align-items-center gap-2" key={f.name}>
					<label className="form-check mb-1 flex-grow-1">
						<input
							className="form-check-input"
							type="checkbox"
							checked={chosen.includes(f.name)}
							onChange={(e) =>
								onChange(e.target.checked ? [...chosen, f.name] : chosen.filter((n) => n !== f.name))
							}
						/>
						<span className="form-check-label">
							{f.name}
							<span className="text-secondary small ms-2">
								<T
									id="nginxions.policy.schemas.info"
									data={{ title: f.title || "—", version: f.version, paths: f.paths }}
								/>
							</span>
						</span>
					</label>
					<button
						type="button"
						className="btn btn-sm btn-ghost-secondary"
						aria-label={t("nginxions.policy.schemas.download")}
						title={t("nginxions.policy.schemas.download")}
						onClick={() => downloadSchemaFile(f.name)}
					>
						<IconDownload size={16} />
					</button>
					<button
						type="button"
						className="btn btn-sm btn-ghost-danger"
						disabled={f.usedBy.length > 0}
						aria-label={t("nginxions.policy.schemas.delete")}
						title={
							f.usedBy.length
								? t("nginxions.policy.schemas.used", { practices: f.usedBy.join(", ") })
								: t("nginxions.policy.schemas.delete")
						}
						onClick={() => remove(f.name)}
					>
						<IconTrash size={16} />
					</button>
				</div>
			))}
			{missing.map((n) => (
				<div className="text-warning small" key={n}>
					<T id="nginxions.policy.schemas.missing" data={{ name: n }} />
				</div>
			))}
			<input
				ref={fileRef}
				type="file"
				accept=".yaml,.yml,.json"
				className="d-none"
				aria-label={t("nginxions.policy.schemas.upload")}
				onChange={(e) => upload(e.target.files?.[0])}
			/>
			<button type="button" className="btn btn-sm mt-1" disabled={busy} onClick={() => fileRef.current?.click()}>
				<IconUpload size={16} className="me-1" />
				<T id="nginxions.policy.schemas.upload" />
			</button>
		</div>
	);
}
