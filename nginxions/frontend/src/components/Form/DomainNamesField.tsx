import { Field, useFormikContext } from "formik";
import { type ReactNode, useState } from "react";
import type { ActionMeta, MultiValue } from "react-select";
import CreatableSelect from "react-select/creatable";
import { intl, T } from "src/locale";
import { validateDomain, validateDomains } from "src/modules/Validations";

type SelectOption = {
	label: string;
	value: string;
	color?: string;
};

interface Props {
	id?: string;
	maxDomains?: number;
	isWildcardPermitted?: boolean;
	dnsProviderWildcardSupported?: boolean;
	name?: string;
	label?: string;
	onChange?: (domains: string[]) => void;
}
export function DomainNamesField({
	name = "domainNames",
	label = "domain-names",
	id = "domainNames",
	maxDomains,
	isWildcardPermitted = false,
	dnsProviderWildcardSupported = false,
	onChange,
}: Props) {
	const { setFieldValue, getFieldProps } = useFormikContext();
	// NginxionS: what is being typed. A typed domain was lost unless Enter was pressed (the field looked broken); it is
	// added on Enter, Tab, a comma, a space, when a list is pasted and when the field loses focus
	const [input, setInput] = useState("");
	const valid = validateDomain(isWildcardPermitted && dnsProviderWildcardSupported);
	const add = (raw: string[]) => {
		const current: string[] = getFieldProps(name).value ?? [];
		const next = [...current];
		const rest: string[] = [];
		for (const part of raw.map((d) => d.trim().toLowerCase()).filter(Boolean)) {
			if (!valid(part)) rest.push(part);
			else if (!next.includes(part)) next.push(part);
		}
		if (next.length !== current.length) {
			setFieldValue(name, next);
			onChange?.(next);
		}
		return rest;
	};
	const onInputChange = (value: string, meta: { action: string }) => {
		// a chosen option clears the text; on blur and on closing the menu it stays (onBlur adds it)
		if (meta.action === "set-value") setInput("");
		if (meta.action !== "input-change") return;
		// a separator ends a domain: "a.com, b.com c.com" (pasted or typed)
		if (/[\s,;]/.test(value)) {
			const parts = value.split(/[\s,;]+/);
			const last = /[\s,;]$/.test(value) ? "" : (parts.pop() ?? "");
			const rest = add(parts);
			setInput([...rest, last].filter(Boolean).join(" "));
			return;
		}
		setInput(value);
	};
	const onBlur = () => {
		if (!input.trim()) return;
		const rest = add([input]);
		setInput(rest.join(" "));
	};

	const handleChange = (v: MultiValue<SelectOption>, _actionMeta: ActionMeta<SelectOption>) => {
		const doms = v?.map((i: SelectOption) => {
			return i.value;
		});
		setFieldValue(name, doms);
		onChange?.(doms);
	};

	// NginxionS: how a domain is added, always in sight
	const helperTexts: ReactNode[] = [<T key="how" id="nginxions.domain-names.how" />];
	if (maxDomains) {
		helperTexts.push(<T id="domain-names.max" data={{ count: maxDomains }} />);
	}
	if (!isWildcardPermitted) {
		helperTexts.push(<T id="domain-names.wildcards-not-permitted" />);
	} else if (!dnsProviderWildcardSupported) {
		helperTexts.push(<T id="domain-names.wildcards-not-supported" />);
	}

	return (
		<Field name={name} validate={validateDomains(isWildcardPermitted && dnsProviderWildcardSupported, maxDomains)}>
			{({ field, form }: any) => (
				<div className="mb-3">
					<label className="form-label" htmlFor={id}>
						<T id={label} />
					</label>
					<CreatableSelect
						className="react-select-container"
						classNamePrefix="react-select"
						name={field.name}
						id={id}
						closeMenuOnSelect={true}
						isClearable={false}
						isValidNewOption={validateDomain(isWildcardPermitted && dnsProviderWildcardSupported)}
						isMulti
						placeholder={intl.formatMessage({ id: "nginxions.domain-names.placeholder" })}
						onChange={handleChange}
						inputValue={input}
						onInputChange={onInputChange}
						onBlur={onBlur}
						formatCreateLabel={(value) =>
							intl.formatMessage(
								{ id: "nginxions.domain-names.create" },
								{ domain: value.trim().toLowerCase() },
							)
						}
						noOptionsMessage={({ inputValue }) =>
							intl.formatMessage(
								{
									id: inputValue.trim()
										? "nginxions.domain-names.invalid"
										: "nginxions.domain-names.hint",
								},
								{ domain: inputValue.trim() },
							)
						}
						value={field.value?.map((d: string) => ({ label: d, value: d }))}
					/>
					{form.errors[field.name] && form.touched[field.name] ? (
						<small className="text-danger">{form.errors[field.name]}</small>
					) : helperTexts.length ? (
						helperTexts.map((i, idx) => (
							<small key={idx} className="text-info">
								{i}
							</small>
						))
					) : null}
				</div>
			)}
		</Field>
	);
}
