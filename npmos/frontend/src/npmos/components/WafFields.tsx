// WAF tab of the proxy host modal: open-appsec mode of the host and its custom locations.
// Lives in the Formik form of the modal under `npmosWaf`; saved separately (/api/npmos/waf/hosts/:id)
// after the host itself, see ProxyHostModal.
import { useQuery } from "@tanstack/react-query";
import cn from "classnames";
import { useFormikContext } from "formik";
import { intl, T } from "src/locale";
import { WAF_DEFAULTS, type WafConfidence, type WafHost, type WafLocationSettings, type WafMode } from "../api";
import { getPolicyObjects, type HostObjects, type PolicyObjects } from "../policy/api";
import { RefsEditor } from "../policy/RefsEditor";
import { useCan } from "../rbac/hooks";

export const MODES: WafMode[] = ["detect-learn", "prevent-learn"];
export const CONFIDENCES: WafConfidence[] = ["medium", "high", "critical"];

/** location choice in the form: inherit the host, off, or an own mode */
type LocationChoice = "inherit" | "off" | WafMode;

export interface WafFormLocation {
	choice: LocationChoice;
	minimumConfidence: WafConfidence;
	/** own objects of the policy; null: those of the host */
	objects: HostObjects;
}

export interface WafFormValues {
	enabled: boolean;
	mode: WafMode;
	minimumConfidence: WafConfidence;
	/** by location path */
	locations: Record<string, WafFormLocation>;
	/** objects of the policy the host uses (WAF → Policy); null: those of the default policy */
	objects: HostObjects;
}

export const toWafForm = (data?: WafHost): WafFormValues => {
	const locations: Record<string, WafFormLocation> = {};
	for (const l of data?.locations || []) {
		locations[l.path] = {
			choice: l.inherit ? "inherit" : l.enabled ? l.mode : "off",
			minimumConfidence: l.minimumConfidence,
			objects: l.objects ?? null,
		};
	}
	return {
		enabled: data?.enabled ?? WAF_DEFAULTS.enabled,
		mode: data?.mode ?? WAF_DEFAULTS.mode,
		minimumConfidence: data?.minimumConfidence ?? WAF_DEFAULTS.minimumConfidence,
		locations,
		objects: data?.objects ?? null,
	};
};

/** request body for the paths the host has now (locations removed in the form are dropped) */
export const fromWafForm = (values: WafFormValues, paths: string[]) => ({
	enabled: values.enabled,
	mode: values.mode,
	minimumConfidence: values.minimumConfidence,
	objects: values.objects,
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
			objects: l.choice === "off" ? null : l.objects,
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

			<PolicyChoice
				value={waf.objects}
				disabled={!waf.enabled}
				onChange={(objects) => set("objects", objects)}
				onMode={(mode) => set("mode", mode)}
			/>

			{paths.length > 0 && (
				<>
					<h4 className="pt-2">
						<T id="column.custom-locations" />
					</h4>
					{paths.map((path) => {
						const l = waf.locations[path] || {
							choice: "inherit",
							minimumConfidence: "high",
							objects: null,
						};
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
								{own && (
									<LocationObjects
										value={l.objects}
										host={waf.objects}
										onChange={(objects) => setLocation({ objects })}
									/>
								)}
							</div>
						);
					})}
				</>
			)}
		</div>
	);
}

/** objects of the policy the host uses: the default policy, a template or its own */
function PolicyChoice({
	value,
	disabled,
	onChange,
	onMode,
}: {
	value: HostObjects;
	disabled: boolean;
	onChange: (value: HostObjects) => void;
	onMode: (mode: WafMode) => void;
}) {
	const can = useCan();
	const { data } = useQuery<PolicyObjects, Error>({
		queryKey: ["npmos-waf-policy-objects"],
		queryFn: getPolicyObjects,
		enabled: can("waf_policy", "view"),
	});
	if (!data) return null;
	const choice = value === null ? "default" : value.template ? `template:${value.template}` : "custom";
	const select = (next: string) => {
		if (next === "default") onChange(null);
		else if (next === "custom") {
			// own objects start from what the host uses now
			const { template: _template, mode: _mode, ...refs } = (value ?? data.policy) as Record<string, any>;
			onChange(refs);
		} else {
			const template = next.slice("template:".length);
			onChange({ template });
			// a template has a mode too (monitor: detect-learn)
			const mode = data.templates[template]?.mode;
			if (mode === "detect-learn" || mode === "prevent-learn") onMode(mode);
		}
	};
	return (
		<div className="mb-3">
			<label className="form-label" htmlFor="npmosWafPolicy">
				<T id="npmos.waf.host-policy" />
			</label>
			<select
				id="npmosWafPolicy"
				className="form-select"
				value={choice}
				disabled={disabled}
				onChange={(e) => select(e.target.value)}
			>
				<option value="default">{intl.formatMessage({ id: "npmos.waf.host-policy.default" })}</option>
				{Object.keys(data.templates).map((name) => (
					<option key={name} value={`template:${name}`}>
						{intl.formatMessage(
							{ id: "npmos.waf.host-policy.template" },
							{
								name: intl.formatMessage({ id: `npmos.policy.template.${name}` }),
							},
						)}
					</option>
				))}
				<option value="custom">{intl.formatMessage({ id: "npmos.waf.host-policy.custom" })}</option>
			</select>
			<div className="form-hint">
				<T id="npmos.waf.host-policy.hint" />
			</div>
			{choice === "custom" && value && (
				<div className="mt-3">
					<RefsEditor value={value} onChange={onChange} objects={data.objects} disabled={disabled} />
				</div>
			)}
		</div>
	);
}

/** own objects of a location (on top of those of its host: exceptions add up, the rest replaces) */
function LocationObjects({
	value,
	host,
	onChange,
}: {
	value: HostObjects;
	host: HostObjects;
	onChange: (value: HostObjects) => void;
}) {
	const can = useCan();
	const { data } = useQuery<PolicyObjects, Error>({
		queryKey: ["npmos-waf-policy-objects"],
		queryFn: getPolicyObjects,
		enabled: can("waf_policy", "view"),
	});
	if (!data) return null;
	const toggle = (on: boolean) => {
		if (!on) return onChange(null);
		// they start from what the host uses (a template has no references here)
		const source = host && !host.template ? host : data.policy;
		const { template: _template, mode: _mode, ...refs } = source as Record<string, any>;
		onChange(refs);
	};
	return (
		<div className="col-12 mt-2">
			<label className="form-check form-switch">
				<input
					type="checkbox"
					className="form-check-input"
					checked={value !== null}
					onChange={(e) => toggle(e.target.checked)}
				/>
				<span className="form-check-label">
					<T id="npmos.waf.location.objects" />
				</span>
				<span className="form-check-description">
					<T id="npmos.waf.location.objects.hint" />
				</span>
			</label>
			{value !== null && <RefsEditor value={value} onChange={onChange} objects={data.objects} />}
		</div>
	);
}

// option elements take strings only

const intlMode = (m: WafMode) => intl.formatMessage({ id: `npmos.waf.mode.${m}` });
const intlChoice = (c: "inherit" | "off") => intl.formatMessage({ id: `npmos.waf.location.${c}` });
