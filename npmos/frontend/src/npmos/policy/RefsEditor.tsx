// References of a rule to objects of the policy: the default policy (WAF → Policy) and the own
// objects of a host (WAF settings of the host). Lists are checkboxes, single objects a select.
import { intl, T } from "src/locale";
import { type PolicyObject, RULE_FIELDS, type RuleRefs } from "./api";
import { objectTitle } from "./names";

const t = (id: string) => intl.formatMessage({ id });

export function RefsEditor({
	value,
	onChange,
	objects,
	disabled,
}: {
	value: RuleRefs;
	onChange: (value: RuleRefs) => void;
	objects: PolicyObject[];
	disabled?: boolean;
}) {
	return (
		<div className="row">
			{(Object.keys(RULE_FIELDS) as (keyof RuleRefs)[]).map((field) => {
				const { kind, many } = RULE_FIELDS[field];
				const options = objects.filter((o) => o.kind === kind);
				return (
					<div className="col-md-6 mb-3" key={field}>
						<span className="form-label">
							<T id={`npmos.policy.rule.${field}`} />
						</span>
						{many ? (
							options.length ? (
								options.map((o) => {
									const ids = (value[field] as number[] | undefined) || [];
									return (
										<label className="form-check mb-1" key={o.id}>
											<input
												className="form-check-input"
												type="checkbox"
												disabled={disabled}
												checked={ids.includes(o.id)}
												onChange={(e) =>
													onChange({
														...value,
														[field]: e.target.checked
															? [...ids, o.id]
															: ids.filter((id) => id !== o.id),
													})
												}
											/>
											<span className="form-check-label">
												{objectTitle(o)}
												{o.builtin && (
													<span className="text-secondary font-monospace small ms-2">
														{o.name}
													</span>
												)}
											</span>
										</label>
									);
								})
							) : (
								<div className="text-secondary small">
									<T id="npmos.policy.no-objects" />
								</div>
							)
						) : (
							<select
								className="form-select"
								aria-label={t(`npmos.policy.rule.${field}`)}
								disabled={disabled}
								value={(value[field] as number | null | undefined) ?? ""}
								onChange={(e) =>
									onChange({ ...value, [field]: e.target.value ? Number(e.target.value) : null })
								}
							>
								<option value="">{t("npmos.policy.none")}</option>
								{options.map((o) => (
									<option key={o.id} value={o.id}>
										{o.builtin ? `${objectTitle(o)} (${o.name})` : o.name}
									</option>
								))}
							</select>
						)}
					</div>
				);
			})}
		</div>
	);
}
