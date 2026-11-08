// The ACME server of a new certificate (Certificates → ACME, the host form, your own CSR) and the DNS fields of its
// client: certbot plugins, or the providers of lego (credentials as KEY=VALUE, the variables from `lego dnshelp`).
import { useQuery } from "@tanstack/react-query";
import { Field, useFormikContext } from "formik";
import { useEffect, useMemo, useState } from "react";
import Select from "react-select";
import { DNSProviderFields } from "src/components";
import { intl, T } from "src/locale";
import { chosenServer, getLegoDnsProviderHelp, getLegoDnsProviders, useAcmeServers } from "./api";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

/** the server the form chose (meta.acmeServerId), the default one before a choice */
export const useChosenAcmeServer = () => {
	const { values } = useFormikContext<any>();
	const { data } = useAcmeServers();
	return chosenServer(data, values?.meta?.acmeServerId);
};

/** a select of the ACME servers of Settings → ACME, with the default one chosen */
export function AcmeServerField() {
	const { values, setFieldValue } = useFormikContext<any>();
	const { data, isLoading } = useAcmeServers();
	const server = chosenServer(data, values?.meta?.acmeServerId);
	// the default server is written into the form, so that what is shown is what is sent
	useEffect(() => {
		if (server && !values?.meta?.acmeServerId) setFieldValue("meta.acmeServerId", server.id);
	}, [server, values?.meta?.acmeServerId, setFieldValue]);
	return (
		<div className="mb-3">
			<label className="form-label" htmlFor="acmeServerId">
				<T id="nginxions.acme.server" />
			</label>
			<select
				id="acmeServerId"
				className="form-select"
				disabled={isLoading}
				value={server?.id ?? ""}
				onChange={(e) => setFieldValue("meta.acmeServerId", Number(e.target.value))}
			>
				{(data?.items ?? []).map((s) => (
					<option key={s.id} value={s.id}>
						{s.name}
						{s.isDefault ? ` — ${t("nginxions.acme.server.default")}` : ""}
					</option>
				))}
			</select>
			{server && (
				<div className="form-hint">
					<span className="font-monospace small">{server.directory}</span>
					{" · "}
					<T id={`nginxions.acme.client.${server.client}`} />
					{" · "}
					{/* a plain link: the modals of EasyModal are rendered outside the router */}
					<a href="/settings?section=nginxions-acme" target="_blank" rel="noreferrer">
						<T id="nginxions.acme.server.manage" />
					</a>
				</div>
			)}
		</div>
	);
}

/** the DNS provider of lego and its variables */
function LegoDnsFields() {
	const { values, setFieldValue } = useFormikContext<any>();
	const meta = values?.meta ?? {};
	const providers = useQuery({ queryKey: ["nginxions-lego-dns"], queryFn: getLegoDnsProviders, staleTime: 3600000 });
	const code: string = meta.dnsProvider || "";
	const help = useQuery({
		queryKey: ["nginxions-lego-dns-help", code],
		queryFn: () => getLegoDnsProviderHelp(code),
		enabled: !!code,
		staleTime: 3600000,
	});
	const [showHelp, setShowHelp] = useState(true);
	const options = useMemo(() => (providers.data?.items ?? []).map((c) => ({ value: c, label: c })), [providers.data]);
	// the variables of the provider as an empty template, when nothing is written yet
	const template = useMemo(() => {
		const text = help.data?.help ?? "";
		const credentials = text.split(/\n\s*Additional Configuration:/)[0];
		return [...credentials.matchAll(/- "([A-Z0-9_]+)":/g)].map((m) => `${m[1]}=`).join("\n");
	}, [help.data]);
	useEffect(() => {
		if (template && !meta.dnsProviderCredentials) setFieldValue("meta.dnsProviderCredentials", template);
	}, [template, meta.dnsProviderCredentials, setFieldValue]);
	return (
		<div>
			<p className="text-warning small mb-2">
				<T id="nginxions.acme.lego.warning" />
			</p>
			<label className="form-label" htmlFor="legoDnsProvider">
				<T id="certificates.dns.provider" />
			</label>
			<Select
				inputId="legoDnsProvider"
				className="react-select-container"
				classNamePrefix="react-select"
				isLoading={providers.isLoading}
				isSearchable
				placeholder={t("certificates.dns.provider.placeholder")}
				value={code ? { value: code, label: code } : null}
				options={options}
				onChange={(o: any) => {
					setFieldValue("meta.dnsProvider", o?.value);
					setFieldValue("meta.dnsProviderCredentials", "");
				}}
			/>
			{code && (
				<>
					<label className="form-label mt-3" htmlFor="legoDnsCredentials">
						<T id="certificates.dns.credentials" />
					</label>
					<Field
						as="textarea"
						id="legoDnsCredentials"
						name="meta.dnsProviderCredentials"
						rows={5}
						spellCheck={false}
						autoComplete="off"
						className="form-control font-monospace small"
						placeholder={t("nginxions.acme.lego.credentials-placeholder")}
					/>
					<div className="form-hint">
						<T id="nginxions.acme.lego.credentials-hint" />{" "}
						<button
							type="button"
							className="btn btn-link btn-sm p-0"
							onClick={() => setShowHelp(!showHelp)}
						>
							<T id={showHelp ? "nginxions.acme.lego.help-hide" : "nginxions.acme.lego.help-show"} />
						</button>
					</div>
					{showHelp && help.data?.help && (
						<pre
							className="small mt-2 mb-0 p-2 border rounded"
							style={{ maxHeight: 220, overflow: "auto" }}
						>
							{help.data.help}
						</pre>
					)}
					<label className="form-label mt-3" htmlFor="legoPropagation">
						<T id="certificates.dns.propagation-seconds" />
					</label>
					<Field
						id="legoPropagation"
						name="meta.propagationSeconds"
						type="number"
						min={0}
						max={7200}
						className="form-control"
					/>
					<div className="form-hint">
						<T id="nginxions.acme.lego.propagation-hint" />
					</div>
				</>
			)}
		</div>
	);
}

/** the DNS fields of the client of the chosen server */
export function AcmeDnsFields({ showBoundaryBox = false }: { showBoundaryBox?: boolean }) {
	const server = useChosenAcmeServer();
	const { setFieldValue, values } = useFormikContext<any>();
	const client = server?.client;
	// another client knows other providers: the choice of the other one is cleared
	const [lastClient, setLastClient] = useState(client);
	useEffect(() => {
		if (client && lastClient && client !== lastClient && values?.meta?.dnsProvider) {
			setFieldValue("meta.dnsProvider", undefined);
			setFieldValue("meta.dnsProviderCredentials", undefined);
		}
		setLastClient(client);
	}, [client, lastClient, values?.meta?.dnsProvider, setFieldValue]);
	if (!server) return null;
	return client === "lego" ? (
		<LegoDnsFields key="lego" />
	) : (
		<DNSProviderFields key="certbot" showBoundaryBox={showBoundaryBox} />
	);
}
