// A section of System → Settings for env settings of NPMplus (docs/ENV-INVENTORY.md): a row per
// setting with its explanation; saving writes them for the next start of NPMOS, "Save and restart"
// applies them now (the panel reconnects after ~30 s).
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { useEffect, useMemo, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button } from "src/components";
import { useCertificates } from "src/hooks";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { useCan } from "../rbac/hooks";
import {
	applySystemSettings,
	type EnvGroup,
	type EnvSetting,
	type EnvValue,
	getSystemSettings,
	setSystemSettings,
} from "./api";
import styles from "./EnvSection.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const TIME_ZONES: string[] = (() => {
	try {
		return (Intl as any).supportedValuesOf("timeZone");
	} catch {
		return [];
	}
})();

/** ACME servers to choose from; any other URL is entered by hand */
const ACME_SERVERS = [
	{ name: "Let's Encrypt", url: "https://acme-v02.api.letsencrypt.org/directory" },
	{ name: "Let's Encrypt (staging)", url: "https://acme-staging-v02.api.letsencrypt.org/directory" },
	{ name: "ZeroSSL", url: "https://acme.zerossl.com/v2/DV90" },
	{ name: "Google Trust Services", url: "https://dv.acme-v02.api.pki.goog/directory" },
	{ name: "SSL.com", url: "https://acme.ssl.com/sslcom-dv-ecc" },
];
// shown by the backend instead of a secret that is set
const SECRET_SET = "********";
const URL_FORM = /^https?:\/\/[A-Za-z0-9._~:/?&%+@-]+$/;
const EMAIL_FORM = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}$/;
const TOKEN_FORM = /^[A-Za-z0-9_-]{0,512}$/;

function AcmeServer({
	value,
	disabled,
	label,
	onChange,
}: {
	value: string;
	disabled: boolean;
	label: string;
	onChange: (value: string) => void;
}) {
	const known = ACME_SERVERS.some((s) => s.url === value);
	const [custom, setCustom] = useState(!known);
	return (
		<div className={styles.acme}>
			<select
				className="form-select form-select-sm"
				value={custom ? "" : value}
				disabled={disabled}
				aria-label={label}
				onChange={(e) => {
					setCustom(!e.target.value);
					if (e.target.value) onChange(e.target.value);
				}}
			>
				{ACME_SERVERS.map((s) => (
					<option key={s.url} value={s.url}>
						{s.name}
					</option>
				))}
				<option value="">{t("npmos.system.acme.custom")}</option>
			</select>
			{custom && (
				<input
					type="url"
					className="form-control form-control-sm"
					placeholder="https://"
					value={value}
					disabled={disabled}
					aria-label={label}
					onChange={(e) => onChange(e.target.value.trim())}
				/>
			)}
		</div>
	);
}

export const useSystemSettings = () =>
	useQuery({ queryKey: ["npmos-system-settings"], queryFn: getSystemSettings, refetchInterval: 15000 });

function Control({
	item,
	value,
	disabled,
	onChange,
}: {
	item: EnvSetting;
	value: EnvValue;
	disabled: boolean;
	onChange: (value: EnvValue) => void;
}) {
	const certificates = useCertificates([], { enabled: item.env === "DEFAULT_CERT_ID" });
	const label = t(`npmos.system.env.${item.env}`);
	if (item.type === "bool") {
		return (
			<label className="form-check form-switch m-0">
				<input
					type="checkbox"
					className="form-check-input"
					checked={value === true}
					disabled={disabled}
					aria-label={label}
					onChange={(e) => onChange(e.target.checked)}
				/>
			</label>
		);
	}
	if (item.env === "DEFAULT_CERT_ID") {
		return (
			<select
				className="form-select form-select-sm"
				value={String(value)}
				disabled={disabled}
				aria-label={label}
				onChange={(e) => onChange(Number(e.target.value))}
			>
				<option value="0">{t("npmos.system.env.DEFAULT_CERT_ID.none")}</option>
				{(certificates.data ?? []).map((c) => (
					<option key={c.id} value={c.id}>
						{c.niceName || c.domainNames.join(", ")}
					</option>
				))}
			</select>
		);
	}
	if (item.type === "url") {
		return <AcmeServer value={String(value)} disabled={disabled} label={label} onChange={onChange} />;
	}
	if (item.type === "email" || item.type === "token") {
		return (
			<input
				type={item.type === "email" ? "email" : "text"}
				className="form-control form-control-sm"
				autoComplete="off"
				value={String(value)}
				disabled={disabled}
				aria-label={label}
				onChange={(e) => onChange(e.target.value.trim())}
			/>
		);
	}
	if (item.type === "secret") {
		return (
			<input
				type="password"
				className="form-control form-control-sm"
				autoComplete="new-password"
				placeholder={value === SECRET_SET ? t("npmos.system.secret.set") : ""}
				value={value === SECRET_SET ? "" : String(value)}
				disabled={disabled}
				aria-label={label}
				onChange={(e) => onChange(e.target.value.trim() || (item.value === SECRET_SET ? SECRET_SET : ""))}
			/>
		);
	}
	if (item.type === "tz") {
		return (
			<>
				<input
					className="form-control form-control-sm"
					list="npmos-timezones"
					value={String(value)}
					disabled={disabled}
					aria-label={label}
					onChange={(e) => onChange(e.target.value)}
				/>
				<datalist id="npmos-timezones">
					{TIME_ZONES.map((z) => (
						<option key={z} value={z} />
					))}
				</datalist>
			</>
		);
	}
	if (item.type === "workers") {
		return (
			<div className={styles.workers}>
				<label className="form-check m-0">
					<input
						type="checkbox"
						className="form-check-input"
						checked={value === "auto"}
						disabled={disabled}
						onChange={(e) => onChange(e.target.checked ? "auto" : 1)}
					/>
					<span className="form-check-label">
						<T id="npmos.system.env.auto" />
					</span>
				</label>
				{value !== "auto" && (
					<input
						type="number"
						className="form-control form-control-sm"
						min={item.min}
						max={item.max}
						value={Number(value)}
						disabled={disabled}
						aria-label={label}
						onChange={(e) => onChange(Number.parseInt(e.target.value, 10) || 0)}
					/>
				)}
			</div>
		);
	}
	return (
		<input
			type="number"
			className="form-control form-control-sm"
			min={item.min}
			max={item.max}
			value={Number(value)}
			disabled={disabled}
			aria-label={label}
			onChange={(e) => onChange(Number.parseInt(e.target.value, 10) || 0)}
		/>
	);
}

/** a valid value in the limits of the setting (the backend checks the same) */
const valid = (item: EnvSetting, value: EnvValue) => {
	if (item.type === "bool") return typeof value === "boolean";
	if (item.type === "tz")
		return typeof value === "string" && (!TIME_ZONES.length || TIME_ZONES.includes(value) || value === "UTC");
	if (item.type === "workers" && value === "auto") return true;
	if (item.type === "url") return typeof value === "string" && value.length <= 512 && URL_FORM.test(value);
	if (item.type === "email") return value === "" || (typeof value === "string" && EMAIL_FORM.test(value));
	if (item.type === "token") return typeof value === "string" && TOKEN_FORM.test(value);
	if (item.type === "secret") return value === SECRET_SET || (typeof value === "string" && TOKEN_FORM.test(value));
	return (
		Number.isInteger(value) &&
		Number(value) >= (item.min ?? 0) &&
		Number(value) <= (item.max ?? Number.POSITIVE_INFINITY)
	);
};

export function RestartBanner() {
	const can = useCan();
	const queryClient = useQueryClient();
	const { data } = useSystemSettings();
	const [busy, setBusy] = useState(false);
	if (!data?.restartRequired) return null;
	const restart = async () => {
		setBusy(true);
		try {
			await applySystemSettings();
			showSuccess(t("npmos.system.restarting"));
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(false);
		queryClient.invalidateQueries({ queryKey: ["npmos-system-settings"] });
	};
	return (
		<Alert variant="warning" className={styles.banner}>
			<span>
				<T id="npmos.system.pending" />
			</span>
			{can("settings", "manage") && (
				<Button size="sm" actionType="primary" isLoading={busy} onClick={restart}>
					<T id="npmos.system.restart" />
				</Button>
			)}
		</Alert>
	);
}

export function EnvSection({ group }: { group: EnvGroup }) {
	const can = useCan();
	const manage = can("settings", "manage");
	const queryClient = useQueryClient();
	const { data, isError, error } = useSystemSettings();
	const items = useMemo(() => (data?.items ?? []).filter((i) => i.group === group), [data, group]);
	const [form, setForm] = useState<Record<string, EnvValue>>({});
	const [busy, setBusy] = useState<"save" | "apply" | null>(null);

	// the form follows the server until the user changes something
	const key = items.map((i) => `${i.env}=${i.value}`).join("&");
	// biome-ignore lint/correctness/useExhaustiveDependencies: reset when the saved values change
	useEffect(() => setForm(Object.fromEntries(items.map((i) => [i.env, i.value]))), [key]);

	if (isError) return <Alert variant="danger">{error.message}</Alert>;
	if (!data) return <div className="spinner-border spinner-border-sm text-secondary" />;

	const changed = items.filter((i) => form[i.env] !== undefined && form[i.env] !== i.value);
	const invalid = items.filter((i) => form[i.env] !== undefined && !valid(i, form[i.env]));

	const save = async (apply: boolean) => {
		setBusy(apply ? "apply" : "save");
		try {
			const result = await setSystemSettings(
				changed.map((i) => ({ env: i.env, value: form[i.env] })),
				apply,
			);
			queryClient.setQueryData(["npmos-system-settings"], result);
			showSuccess(t(result.restarting ? "npmos.system.restarting" : "npmos.system.saved"));
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(null);
	};

	return (
		<div className={styles.section}>
			<p className={styles.intro}>
				<T id={`npmos.system.group.${group}.hint`} />
			</p>
			<ul className={styles.rows}>
				{items.map((item) => (
					<li key={item.env} className={styles.row}>
						<div className={styles.text}>
							<div className={styles.label}>
								<T id={`npmos.system.env.${item.env}`} />
								{item.internet && (
									<span className="badge bg-yellow-lt ms-2">
										<T id="npmos.system.internet" />
									</span>
								)}
								{item.pending && (
									<span className="badge bg-azure-lt ms-2">
										<T id="npmos.system.after-restart" />
									</span>
								)}
							</div>
							<div className={styles.hint}>
								<T id={`npmos.system.env.${item.env}.hint`} />
							</div>
							<code className={styles.env}>{item.env}</code>
						</div>
						<div
							className={cn(styles.control, !valid(item, form[item.env] ?? item.value) && styles.invalid)}
						>
							<Control
								item={item}
								value={form[item.env] ?? item.value}
								disabled={!manage}
								onChange={(value) => setForm({ ...form, [item.env]: value })}
							/>
						</div>
					</li>
				))}
			</ul>
			{manage && (
				<div className={styles.actions}>
					<Button
						size="sm"
						disabled={!changed.length || invalid.length > 0}
						isLoading={busy === "save"}
						onClick={() => save(false)}
					>
						<T id="npmos.system.save" />
					</Button>
					<Button
						size="sm"
						actionType="primary"
						disabled={!changed.length || invalid.length > 0}
						isLoading={busy === "apply"}
						onClick={() => save(true)}
					>
						<T id="npmos.system.save-restart" />
					</Button>
				</div>
			)}
		</div>
	);
}
