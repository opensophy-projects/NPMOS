// PKI and mTLS API (/api/npmos/pki, /api/npmos/mtls), see npmos/backend/npmos/pki. The common client
// converts keys (snake_case ↔ camelCase); PEM texts are values and pass as they are.
import { useQuery } from "@tanstack/react-query";
import * as api from "src/api/backend/base";

export const KEY_TYPES = ["ec-p256", "ec-p384", "rsa-2048", "rsa-3072", "rsa-4096"] as const;
export const PROFILES = ["client", "server"] as const;
export type Profile = (typeof PROFILES)[number];
export const REVOKE_REASONS = [
	"unspecified",
	"keyCompromise",
	"CACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
] as const;
export const SUBJECT_FIELDS = [
	"commonName",
	"organization",
	"organizationalUnit",
	"email",
	"country",
	"state",
	"locality",
] as const;
export type SubjectField = (typeof SUBJECT_FIELDS)[number];
export type Subject = Partial<Record<SubjectField, string>>;

export interface Sans {
	dns: string[];
	ip: string[];
	email: string[];
}

export type CaKind = "root" | "intermediate" | "external";

export interface PkiCa {
	id: number;
	createdOn: string;
	name: string;
	kind: CaKind;
	parentId: number | null;
	/** external CAs uploaded in Certificates of NPMplus */
	upstreamCertificateId: number | null;
	subject: Subject;
	subjectDn: string;
	serial: string;
	notBefore: string;
	notAfter: string;
	fingerprint: string;
	keyType: string;
	hasKey: boolean;
	/** certificates in the bundle (external) */
	certificates: number;
	hasCrl: boolean;
	crlNumber: number;
	crlUpdatedOn: string | null;
	crlNextUpdate: string | null;
	issued: number;
	active: number;
	revoked: number;
	/** hosts with mTLS that trust it */
	hosts: string[];
}

export type CertStatus = "active" | "expired" | "revoked" | "replaced";

export interface PkiCert {
	id: number;
	createdOn: string;
	caId: number;
	profile: Profile;
	serial: string;
	commonName: string;
	subject: Subject;
	sans: Sans;
	notBefore: string;
	notAfter: string;
	daysLeft: number;
	fingerprint: string;
	keyType: string;
	status: CertStatus;
	revokedOn: string | null;
	revokeReason: string | null;
	replacedBy: number | null;
	template: string;
	notes: string;
	hasKey: boolean;
	ownerUserId: number;
	/** custom certificate of NPMplus (server certificates) */
	certificateId: number | null;
	/** hosts that serve it (server certificates installed in NPMplus) */
	hosts: string[];
	/** hosts with mTLS it opens (client certificates) */
	access: HostRef[];
}

export interface HostRef {
	hostType: MtlsHostType;
	hostId: number;
	name: string;
}

/** a host with mTLS on */
export interface ProtectedHost extends HostRef {
	mode: "on" | "optional";
	caIds: number[];
	/** rules on fields of certificates narrow who passes */
	rules: number;
	/** the host is on and has its TLS certificate */
	active: boolean;
}

export interface PkiTemplate {
	id: string;
	name: string;
	profile: Profile;
	caId: number | null;
	days: number;
	keyType: string;
	subject: Subject;
}

export interface PkiSettings {
	publicUrl: string;
	crlDays: number;
	clientDays: number;
	serverDays: number;
	keyType: string;
	p12Compatible: boolean;
	templates: PkiTemplate[];
}

export interface PkiOverview {
	cas: PkiCa[];
	certificates: PkiCert[];
	settings: PkiSettings;
	protected: ProtectedHost[];
}

export interface IssueData {
	caId: number;
	profile: Profile;
	subject?: Subject;
	sans?: Sans;
	days?: number;
	keyType?: string;
	csrPem?: string;
	template?: string;
	notes?: string;
	storeKey?: boolean;
	password?: string;
	compatible?: boolean;
	includeKeyPem?: boolean;
	linkHours?: number;
	install?: boolean;
	/** short-lived: validity in hours instead of days */
	hours?: number;
	/** renewed by NPMOS: "link" (people, a one-time link of the next .p12) or "token" (services) */
	autoRenew?: "" | "link" | "token";
	/** caId is a root: a CA of its own is made under it for this certificate */
	ownCa?: boolean;
}

export interface OneTimeLink {
	token: string;
	path: string;
	expiresOn: string;
}

export interface IssueResult {
	certificate: PkiCert;
	files: {
		certPem: string;
		chainPem: string;
		p12Base64?: string;
		password?: string;
		keyPem?: string;
		filename?: string;
	};
	link: OneTimeLink | null;
	/** auto renewal by token: shown once, the service renews with it */
	renewToken?: string | null;
}

export interface FileResult {
	filename: string;
	contentType: string;
	dataBase64: string;
}

export const getPki = (): Promise<PkiOverview> => api.get({ url: "/npmos/pki" });

export const usePki = (options = {}) =>
	useQuery<PkiOverview, Error>({ queryKey: ["npmos-pki"], queryFn: getPki, staleTime: 5000, ...options });

export const setPkiSettings = (data: PkiSettings): Promise<PkiSettings> =>
	api.put({ url: "/npmos/pki/settings", data });

export const createCa = (data: {
	kind: "root" | "intermediate";
	name: string;
	parentId?: number;
	subject: Subject;
	keyType?: string;
	days?: number;
}): Promise<PkiCa> => api.post({ url: "/npmos/pki/cas", data });

export const importCa = (data: {
	kind: "root" | "external";
	name: string;
	certPem: string;
	keyPem?: string;
	keyPassword?: string;
	crlPem?: string;
}): Promise<PkiCa> => api.post({ url: "/npmos/pki/cas/import", data });

export const updateCa = (id: number, data: { name?: string; crlPem?: string }): Promise<PkiCa> =>
	api.put({ url: `/npmos/pki/cas/${id}`, data });

export const deleteCa = (id: number, cascade = false, disableHosts = false) =>
	api.del({
		url: `/npmos/pki/cas/${id}${cascade ? `?cascade=true${disableHosts ? "&disable_hosts=true" : ""}` : ""}`,
	});

export const exportCa = (
	id: number,
	format: "cert" | "chain" | "crl" | "key",
	password?: string,
): Promise<FileResult> => api.post({ url: `/npmos/pki/cas/${id}/export`, data: { format, password } });

export const issueCert = (data: IssueData): Promise<IssueResult> => api.post({ url: "/npmos/pki/certs", data });

export const renewCert = (
	id: number,
	data: Pick<IssueData, "days" | "keyType" | "csrPem" | "storeKey" | "password" | "compatible" | "linkHours"> & {
		revokeOld?: boolean;
	},
): Promise<IssueResult> => api.post({ url: `/npmos/pki/certs/${id}/renew`, data });

export const revokeCerts = (ids: number[], reason: string): Promise<{ revoked: number }> =>
	api.post({ url: "/npmos/pki/certs/revoke", data: { ids, reason } });

/** still valid certificates are revoked first */
export const deleteCerts = (ids: number[]): Promise<{ deleted: number; revoked: number }> =>
	api.post({ url: "/npmos/pki/certs/delete", data: { ids } });

export const updateCert = (id: number, data: { notes: string }): Promise<PkiCert> =>
	api.put({ url: `/npmos/pki/certs/${id}`, data });

export const downloadCert = (
	id: number,
	format: "cert" | "chain" | "key" | "p12",
	options: { password?: string; compatible?: boolean } = {},
): Promise<FileResult> => api.post({ url: `/npmos/pki/certs/${id}/download`, data: { format, ...options } });

export const createLink = (
	id: number,
	data: { hours: number; password?: string; compatible?: boolean },
): Promise<{ link: OneTimeLink; password: string }> => api.post({ url: `/npmos/pki/certs/${id}/links`, data });

export interface CertLink {
	id: number;
	createdOn: string;
	expiresOn: string;
	usedOn: string | null;
	active: boolean;
}

export const getCertLinks = (id: number): Promise<CertLink[]> => api.get({ url: `/npmos/pki/certs/${id}/links` });

export const deleteCertLink = (id: number) => api.del({ url: `/npmos/pki/links/${id}` });

// ---- mTLS of hosts ----

export type MtlsHostType = "proxy_host" | "stream";
export const RULE_FIELDS = ["commonName", "organization", "organizationalUnit", "email", "serial"] as const;
export type RuleField = (typeof RULE_FIELDS)[number];

export interface MtlsRule {
	field: RuleField;
	op: "one_of" | "regex";
	values: string[];
}

export interface MtlsBinding {
	enabled: boolean;
	caIds: number[];
	mode: "on" | "optional";
	depth: number;
	sendCaNames: boolean;
	rules: MtlsRule[];
	requiredPaths: string[];
	headers: boolean;
	/** crl: nginx reads the CRL (reloads on a revocation); ocsp: nginx asks NPMOS, no reload */
	revocation: "crl" | "ocsp";
}

export interface MtlsHost extends MtlsBinding {
	name: string;
	hasCertificate: boolean;
	/** "/" and the paths of the locations (proxy hosts) */
	paths: string[];
	/** streams: a trust domain accepts every intermediate CA of its root */
	issuerCheck: boolean;
	/** the mTLS CA chosen in NPMplus (replaced by this one when enabled) */
	upstreamCaCertificateId: number | null;
	nginx?: { nginxOnline: boolean; nginxErr: string | null } | null;
}

export type MtlsList = Record<"proxyHost" | "stream", Record<string, MtlsBinding>>;

export const getMtlsHosts = (): Promise<MtlsList> => api.get({ url: "/npmos/mtls" });

export const useMtlsHosts = (options = {}) =>
	useQuery<MtlsList, Error>({ queryKey: ["npmos-mtls-hosts"], queryFn: getMtlsHosts, staleTime: 15000, ...options });

export const getMtlsHost = (type: MtlsHostType, id: number): Promise<MtlsHost> =>
	api.get({ url: `/npmos/mtls/${type}/${id}` });

/** mTLS on in one step: the CAs of before, or a trust domain of the host (created when missing) */
export const enableMtlsHost = (type: MtlsHostType, id: number): Promise<MtlsHost> =>
	api.post({ url: `/npmos/mtls/${type}/${id}/enable` });

/** "proxy_host-5" (filters and links of the mTLS page) */
export const hostKey = (ref: { hostType: MtlsHostType; hostId: number }) => `${ref.hostType}-${ref.hostId}`;

/** CAs of NPMOS that can issue client certificates for a host: its trust domains, or those of its roots */
export const issuersFor = (host: { caIds: number[] }, cas: PkiCa[]) => {
	const now = Date.now();
	const usable = (ca: PkiCa) => ca.kind === "intermediate" && ca.hasKey && new Date(ca.notAfter).getTime() > now;
	const direct = cas.filter((ca) => host.caIds.includes(ca.id) && usable(ca));
	if (direct.length) return direct;
	return cas.filter((ca) => ca.parentId !== null && host.caIds.includes(ca.parentId) && usable(ca));
};

/** rules keep the field names of the API (common_name…): values of "field" are not converted */
export const setMtlsHost = (type: MtlsHostType, id: number, data: MtlsBinding): Promise<MtlsHost> =>
	api.put({ url: `/npmos/mtls/${type}/${id}`, data: { ...data, rules: data.rules.map(toApiRule) } });

const SNAKE: Record<RuleField, string> = {
	commonName: "common_name",
	organization: "organization",
	organizationalUnit: "organizational_unit",
	email: "email",
	serial: "serial",
};

const toApiRule = (rule: MtlsRule) => ({ ...rule, field: SNAKE[rule.field] });

/** rules as the API returns them (field in snake_case) → fields of the GUI */
export const fromApiRule = (rule: { field: string; op: MtlsRule["op"]; values: string[] }): MtlsRule => ({
	...rule,
	field: (Object.entries(SNAKE).find(([, v]) => v === rule.field)?.[0] ?? "commonName") as RuleField,
});

// ---- files ----

/** saves a file returned by the API */
export const saveFile = (file: { filename: string; contentType: string; dataBase64: string }) => {
	const bytes = Uint8Array.from(atob(file.dataBase64), (c) => c.charCodeAt(0));
	saveBlob(new Blob([bytes], { type: file.contentType }), file.filename);
};

export const saveText = (text: string, filename: string, type = "application/x-pem-file") =>
	saveBlob(new Blob([text], { type }), filename);

export const saveBase64 = (base64: string, filename: string, type: string) =>
	saveFile({ filename, contentType: type, dataBase64: base64 });

const saveBlob = (blob: Blob, filename: string) => {
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
};

/** full address of a one-time link: the public address of the PKI, or this GUI */
export const linkUrl = (path: string, publicUrl: string) => `${publicUrl || window.location.origin}${path}`;
