// What an issued certificate is handed out as: .p12 with its password, PEM files, a one-time link
// with a QR code. Shown once: the key of the client is not kept unless asked.
import { IconCopy, IconDownload } from "@tabler/icons-react";
import { QRCodeSVG } from "qrcode.react";
import Alert from "react-bootstrap/Alert";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { showSuccess } from "src/notifications";
import { type IssueResult, linkUrl, type OneTimeLink, saveBase64, saveText } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

const copy = (text: string) => navigator.clipboard?.writeText(text).then(() => showSuccess(t("npmos.pki.copied")));

export function LinkBox({ link, publicUrl }: { link: OneTimeLink; publicUrl: string }) {
	const { locale } = useLocaleState();
	const url = linkUrl(link.path, publicUrl);
	return (
		<div className="d-flex gap-3 align-items-start flex-wrap mt-3">
			<div className="bg-white p-2 rounded">
				<QRCodeSVG value={url} size={148} marginSize={1} />
			</div>
			<div className="flex-fill" style={{ minWidth: 220 }}>
				<div className="fw-medium mb-1">
					<T id="npmos.pki.link" />
				</div>
				<div className="input-group input-group-sm mb-1">
					<input
						className="form-control font-monospace"
						readOnly
						value={url}
						aria-label={t("npmos.pki.link")}
					/>
					<button type="button" className="btn" onClick={() => copy(url)} aria-label={t("npmos.pki.copy")}>
						<IconCopy size={16} />
					</button>
				</div>
				<div className="text-secondary small">
					<T id="npmos.pki.link.expires" data={{ time: formatDateTime(link.expiresOn, locale) }} />
				</div>
				{!publicUrl && (
					<div className="text-secondary small">
						<T id="npmos.pki.link.local" />
					</div>
				)}
			</div>
		</div>
	);
}

export function PasswordBox({ password }: { password: string }) {
	return (
		<div className="mb-3">
			<div className="fw-medium mb-1">
				<T id="npmos.pki.p12.password" />
			</div>
			<div className="input-group">
				<input
					className="form-control font-monospace"
					readOnly
					value={password}
					aria-label={t("npmos.pki.p12.password")}
				/>
				<button type="button" className="btn" onClick={() => copy(password)} aria-label={t("npmos.pki.copy")}>
					<IconCopy size={16} />
				</button>
			</div>
			<div className="form-hint">
				<T id="npmos.pki.p12.password.hint" />
			</div>
		</div>
	);
}

/** the renewal token of a service (shown once) and how the service renews itself */
function RenewBox({ token, publicUrl }: { token: string; publicUrl: string }) {
	const url = `${publicUrl || window.location.origin}/api/npmos/pki/public/renew`;
	const command = `curl -sS -X POST ${url} -H 'Authorization: Bearer ${token}' -H 'Content-Type: application/json' -d '{}'`;
	return (
		<div className="mt-3">
			<div className="form-label">
				<T id="npmos.pki.renew-token" />
			</div>
			<div className="input-group mb-2">
				<input className="form-control font-monospace" readOnly value={token} />
				<button type="button" className="btn" onClick={() => copy(token)} aria-label={t("npmos.pki.copy")}>
					<IconCopy size={16} />
				</button>
			</div>
			<div className="form-hint mb-1">
				<T id="npmos.pki.renew-token.hint" />
			</div>
			<pre className="small mb-0" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
				{command}
			</pre>
		</div>
	);
}

export function Delivery({ result, publicUrl }: { result: IssueResult; publicUrl: string }) {
	const { locale } = useLocaleState();
	const { certificate: c, files, link } = result;
	const base = files.filename || c.commonName.replace(/[^\p{L}\p{N}._-]+/gu, "_");
	return (
		<div>
			<Alert variant="success">
				<T
					id="npmos.pki.issued"
					data={{ name: c.commonName, serial: c.serial, until: formatDateTime(c.notAfter, locale) }}
				/>
			</Alert>
			{files.p12Base64 && (
				<>
					{!c.hasKey && (
						<Alert variant="warning">
							<T id="npmos.pki.key-not-kept" />
						</Alert>
					)}
					{files.password && <PasswordBox password={files.password} />}
				</>
			)}
			<div className="d-flex flex-wrap gap-2">
				{files.p12Base64 && (
					<button
						type="button"
						className="btn btn-primary"
						onClick={() => saveBase64(files.p12Base64 as string, `${base}.p12`, "application/x-pkcs12")}
					>
						<IconDownload size={16} className="me-1" />
						<T id="npmos.pki.download.p12" />
					</button>
				)}
				<button type="button" className="btn" onClick={() => saveText(files.certPem, `${base}.crt`)}>
					<IconDownload size={16} className="me-1" />
					<T id="npmos.pki.download.cert" />
				</button>
				<button type="button" className="btn" onClick={() => saveText(files.chainPem, `${base}-chain.pem`)}>
					<IconDownload size={16} className="me-1" />
					<T id="npmos.pki.download.chain" />
				</button>
				{files.keyPem && (
					<button
						type="button"
						className="btn"
						onClick={() => saveText(files.keyPem as string, `${base}.key`)}
					>
						<IconDownload size={16} className="me-1" />
						<T id="npmos.pki.download.key" />
					</button>
				)}
			</div>
			{link && <LinkBox link={link} publicUrl={publicUrl} />}
			{result.renewToken && <RenewBox token={result.renewToken} publicUrl={publicUrl} />}
			{c.certificateId && (
				<p className="text-secondary small mt-3 mb-0">
					<T id="npmos.pki.installed" />
				</p>
			)}
		</div>
	);
}
