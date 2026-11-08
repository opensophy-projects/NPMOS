// Countries of a host (the Details tab of a proxy, redirection or 404 host): only some countries let in, or some
// kept out. Kept in the meta of the host (meta.nginxionsGeo, saved with it); nginx applies it with the GeoIP database
// of System → Settings → GeoIP (backend nginxions/geo). The ACME challenge and private addresses always pass.
import { useQuery } from "@tanstack/react-query";
import { countries } from "country-flag-icons";
import { useFormikContext } from "formik";
import { useMemo } from "react";
import Select from "react-select";
import * as api from "src/api/backend/base";
import { intl, T } from "src/locale";
import { Country } from "../pages/WafAnalytics/common";
import { Admonition } from "../ui/Admonition";
import { countryName } from "../ui/charts/format";

interface GeoValue {
	mode?: "off" | "allow" | "deny";
	countries?: string[];
	action?: "403" | "444";
}

const t = (id: string) => intl.formatMessage({ id });

const useGeoAvailable = () =>
	useQuery({
		queryKey: ["nginxions-geo"],
		queryFn: () => api.get({ url: "/nginxions/geo" }) as Promise<{ available: boolean }>,
		staleTime: 60000,
	});

export function GeoFields() {
	const { values, setFieldValue } = useFormikContext<any>();
	const geo: GeoValue = values?.meta?.nginxionsGeo ?? {};
	const mode = geo.mode === "allow" || geo.mode === "deny" ? geo.mode : "off";
	const chosen = geo.countries ?? [];
	const available = useGeoAvailable();
	const set = (patch: GeoValue) =>
		setFieldValue("meta.nginxionsGeo", { mode, countries: chosen, action: "403", ...geo, ...patch });
	const options = useMemo(
		() =>
			countries
				.filter((c) => /^[A-Z]{2}$/.test(c))
				.map((code) => ({ value: code, label: countryName(code) || code }))
				.sort((a, b) => a.label.localeCompare(b.label)),
		[],
	);
	return (
		<div className="my-3">
			<h4 className="py-2">
				<T id="nginxions.geo.title" />
			</h4>
			<div className="mb-2">
				<select
					className="form-select"
					aria-label={t("nginxions.geo.title")}
					value={mode}
					onChange={(e) => set({ mode: e.target.value as GeoValue["mode"] })}
				>
					<option value="off">{t("nginxions.geo.mode.off")}</option>
					<option value="allow">{t("nginxions.geo.mode.allow")}</option>
					<option value="deny">{t("nginxions.geo.mode.deny")}</option>
				</select>
			</div>
			{mode !== "off" && (
				<>
					<div className="mb-2">
						<Select
							isMulti
							inputId="nginxionsGeoCountries"
							aria-label={t("nginxions.geo.countries")}
							className="react-select-container"
							classNamePrefix="react-select"
							placeholder={t("nginxions.geo.countries.placeholder")}
							options={options}
							value={chosen.map((code) => ({ value: code, label: countryName(code) || code }))}
							formatOptionLabel={(o) => <Country code={o.value} />}
							onChange={(list) => set({ countries: list.map((o) => o.value) })}
						/>
					</div>
					<div className="mb-2">
						<select
							className="form-select"
							aria-label={t("nginxions.geo.action")}
							value={geo.action === "444" ? "444" : "403"}
							onChange={(e) => set({ action: e.target.value as GeoValue["action"] })}
						>
							<option value="403">{t("nginxions.geo.action.403")}</option>
							<option value="444">{t("nginxions.geo.action.444")}</option>
						</select>
					</div>
					<small className="text-secondary d-block">
						<T id={mode === "allow" ? "nginxions.geo.hint.allow" : "nginxions.geo.hint.deny"} />
					</small>
					{mode === "allow" && chosen.length === 0 && (
						<Admonition variant="warning" compact className="mt-2" title={<T id="nginxions.geo.empty" />} />
					)}
					{available.data && !available.data.available && (
						<Admonition
							variant="caution"
							compact
							className="mt-2"
							title={<T id="nginxions.geo.no-database" />}
						/>
					)}
				</>
			)}
		</div>
	);
}
