// WAF tab of the proxy host modal: open-appsec mode of the host and its custom locations.
// Lives in the Formik form of the modal under `npmosWaf`; saved separately (/api/npmos/waf/hosts/:id)
// after the host itself, see ProxyHostModal.
import cn from "classnames";
import { useFormikContext } from "formik";
import { intl, T } from "src/locale";
import { WAF_DEFAULTS, type WafConfidence, type WafHost, type WafLocationSettings, type WafMode } from "../api";

export const MODES: WafMode[] = ["detect-learn", "prevent-learn"];
export const CONFIDENCES: WafConfidence[] = ["medium", "high", "critical"];

/** location choice in the form: inherit the host, off, or an own mode */
type LocationChoice = "inherit" | "off" | WafMode;

export interface WafFormLocation {
	choice: LocationChoice;
	minimumConfidence: WafConfidence;
}

export interface WafFormValues {
	enabled: boolean;
	mode: WafMode;
	minimumConfidence: WafConfidence;
	/** by location path */
	locations: Record<string, WafFormLocation>;
}

export const toWafForm = (data?: WafHost): WafFormValues => {
	const locations: Record<string, WafFormLocation> = {};
	for (const l of data?.locations || []) {
		locations[l.path] = {
			choice: l.inherit ? "inherit" : l.enabled ? l.mode : "off",
			minimumConfidence: l.minimumConfidence,
		};
	}
	return {
		enabled: data?.enabled ?? WAF_DEFAULTS.enabled,
		mode: data?.mode ?? WAF_DEFAULTS.mode,
		minimumConfidence: data?.minimumConfidence ?? WAF_DEFAULTS.minimumConfidence,
		locations,
	};
};

/** request body for the paths the host has now (locations removed in the form are dropped) */
export const fromWafForm = (values: WafFormValues, paths: string[]) => ({
	enabled: values.enabled,
	mode: values.mode,
	minimumConfidence: values.minimumConfidence,
	locations: paths.map((path): WafLocationSettings => {
		const l = values.locations[path];
		if (!l || l.choice === "inherit") {
			return { path, inherit: true, ...WAF_DEFAULTS };
		}
		return {
			path,
			inherit: false,
			enabled: l.choice !== "off",
			mode: l.choice === "off" ? WAF_DEFAULTS.mode : l.choice,
			minimumConfidence: l.minimumConfidence,
		};
	}),
});

/** form values are equal to what is stored: no request needed */
export const wafUnchanged = (a: WafFormValues, b: WafFormValues, paths: string[]) =>
	JSON.stringify(fromWafForm(a, paths)) === JSON.stringify(fromWafForm(b, paths));

function ConfidenceSelect({
	id,
	value,
	disabled,
	onChange,
}: {
	id: string;
	value: WafConfidence;
	disabled?: boolean;
	onChange: (v: WafConfidence) => void;
}) {
	return (
		<select
			id={id}
			className="form-select"
			value={value}
			disabled={disabled}
			onChange={(e) => onChange(e.target.value as WafConfidence)}
		>
			{CONFIDENCES.map((c) => (
				<option key={c} value={c}>
					{/* the agent's own terms, as in open-appsec-npm */}
					{c[0].toUpperCase() + c.slice(1)}
				</option>
			))}
		</select>
	);
}

export function WafFields() {
	const { values, setFieldValue } = useFormikContext<any>();
	const waf: WafFormValues = values.npmosWaf;
	const paths: string[] = (values.locations || []).map((l: any) => l.path).filter((p: string) => !!p);
	const set = (field: string, value: any) => setFieldValue(`npmosWaf.${field}`, value);

	return (
		<div>
			<label className="form-check form-switch mt-1">
				<input
					className={cn("form-check-input", { "bg-red": waf.enabled })}
					type="checkbox"
					checked={waf.enabled}
					onChange={(e) => set("enabled", e.target.checked)}
				/>
				<span className="form-check-label">
					<T id="npmos.waf.host-enabled" />
				</span>
			</label>
			<p className="text-secondary small">
				<T id="npmos.waf.host-description" />
			</p>

			<div className="row">
				<div className="col-md-7 mb-3">
					<label className="form-label" htmlFor="npmosWafMode">
						<T id="npmos.waf.mode" />
					</label>
					<select
						id="npmosWafMode"
						className="form-select"
						value={waf.mode}
						disabled={!waf.enabled}
						onChange={(e) => set("mode", e.target.value)}
					>
						{MODES.map((m) => (
							<option key={m} value={m}>
								{intlMode(m)}
							</option>
						))}
					</select>
					<div className="form-hint">
						<T id={`npmos.waf.mode.${waf.mode}.hint`} />
					</div>
				</div>
				<div className="col-md-5 mb-3">
					<label className="form-label" htmlFor="npmosWafConfidence">
						<T id="npmos.waf.minimum-confidence" />
					</label>
					<ConfidenceSelect
						id="npmosWafConfidence"
						value={waf.minimumConfidence}
						disabled={!waf.enabled}
						onChange={(v) => set("minimumConfidence", v)}
					/>
					<div className="form-hint">
						<T id="npmos.waf.minimum-confidence.hint" />
					</div>
				</div>
			</div>

			{paths.length > 0 && (
				<>
					<h4 className="pt-2">
						<T id="column.custom-locations" />
					</h4>
					{paths.map((path) => {
						const l = waf.locations[path] || { choice: "inherit", minimumConfidence: "high" };
						const setLocation = (patch: Partial<WafFormLocation>) =>
							set("locations", { ...waf.locations, [path]: { ...l, ...patch } });
						const own = l.choice !== "inherit" && l.choice !== "off";
						return (
							<div className="row align-items-center mb-2" key={path}>
								<div className="col-md-4">
									<code>{path}</code>
								</div>
								<div className="col-md-5">
									<select
										className="form-select"
										aria-label={path}
										value={l.choice}
										onChange={(e) => setLocation({ choice: e.target.value as LocationChoice })}
									>
										<option value="inherit">{intlChoice("inherit")}</option>
										<option value="off">{intlChoice("off")}</option>
										{MODES.map((m) => (
											<option key={m} value={m}>
												{intlMode(m)}
											</option>
										))}
									</select>
								</div>
								<div className="col-md-3">
									<ConfidenceSelect
										id={`npmosWafConfidence-${path}`}
										value={l.minimumConfidence}
										disabled={!own}
										onChange={(v) => setLocation({ minimumConfidence: v })}
									/>
								</div>
							</div>
						);
					})}
				</>
			)}
		</div>
	);
}

// option elements take strings only

const intlMode = (m: WafMode) => intl.formatMessage({ id: `npmos.waf.mode.${m}` });
const intlChoice = (c: "inherit" | "off") => intl.formatMessage({ id: `npmos.waf.location.${c}` });
