// What local_policy.yaml becomes with a change: the diff, the format (v1beta1 or v1beta2 and why),
// the warnings. Shown before every change of WAF → Policy is applied.
import cn from "classnames";
import Alert from "react-bootstrap/Alert";
import { intl, T } from "src/locale";
import type { DiffLine, Preview } from "./api";

/** lines around a change shown in the diff */
const CONTEXT = 3;

export function Diff({ diff }: { diff: DiffLine[] }) {
	const shown = diff.map((_, i) => diff.slice(Math.max(0, i - CONTEXT), i + CONTEXT + 1).some((x) => x.op !== " "));
	return (
		<pre className="mb-0 p-0" style={{ maxHeight: "50vh", overflow: "auto" }}>
			{diff.map((d, i) =>
				shown[i] ? (
					<div key={i} className={cn("px-3", { "bg-green-lt": d.op === "+", "bg-red-lt": d.op === "-" })}>
						{d.op} {d.line}
					</div>
				) : i > 0 && shown[i - 1] ? (
					<div key={i} className="px-3 text-secondary">
						⋯
					</div>
				) : null,
			)}
		</pre>
	);
}

/** "rate-limit:login" → a sentence */
export const reasonText = (reason: string) => {
	const [kind, ...name] = reason.split(":");
	return intl.formatMessage({ id: `npmos.policy.reason.${kind}` }, { name: name.join(":") });
};

/** "exceptions:<rule>", "missing:<rule>:<name>" → a sentence */
export const warningText = (warning: string) => {
	const [kind, rule, ...name] = warning.split(":");
	return intl.formatMessage({ id: `npmos.policy.warning.${kind}` }, { rule, name: name.join(":") });
};

export function FormatNote({
	format,
	reasons = [],
	warnings = [],
}: {
	format?: string | null;
	reasons?: string[];
	warnings?: string[];
}) {
	if (!format) return null;
	return (
		<>
			<p className="small mb-2">
				<span className={cn("badge me-2", format === "v1beta2" ? "bg-purple-lt" : "bg-blue-lt")}>{format}</span>
				<T id={format === "v1beta2" ? "npmos.policy.format.v2" : "npmos.policy.format.v1"} />
			</p>
			{reasons.length > 0 && (
				<ul className="small text-secondary mb-2">
					{reasons.map((r) => (
						<li key={r}>{reasonText(r)}</li>
					))}
				</ul>
			)}
			{warnings.length > 0 && (
				<Alert variant="warning" className="small py-2">
					<ul className="mb-0 ps-3">
						{warnings.map((w) => (
							<li key={w}>{warningText(w)}</li>
						))}
					</ul>
				</Alert>
			)}
		</>
	);
}

export function Review({ preview }: { preview: Preview }) {
	if (!preview.valid) {
		return (
			<Alert variant="danger" className="mb-0">
				<pre className="mb-0 bg-transparent p-0 text-reset" style={{ whiteSpace: "pre-wrap" }}>
					{preview.error}
				</pre>
			</Alert>
		);
	}
	return (
		<>
			<FormatNote format={preview.format} reasons={preview.reasons} warnings={preview.warnings} />
			<h4>
				<T id={preview.changed ? "npmos.policy.diff" : "npmos.policy.no-diff"} />
			</h4>
			{preview.changed && preview.diff && <Diff diff={preview.diff} />}
		</>
	);
}
