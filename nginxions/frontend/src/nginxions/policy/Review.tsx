// What local_policy.yaml becomes with a change: the diff, the format (v1beta1 or v1beta2 and why),
// the warnings. Shown before every change of WAF → Policy is applied.
import cn from "classnames";
import Alert from "react-bootstrap/Alert";
import { intl, T } from "src/locale";
import type { AppliedCheck, DiffLine, Preview, Simulation } from "./api";

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

/** "missing:<rule>:<name>" → a sentence */
const warningText = (warning: string) => {
	const [kind, rule, ...name] = warning.split(":");
	return intl.formatMessage({ id: `nginxions.policy.warning.${kind}` }, { rule, name: name.join(":") });
};

export function FormatNote({ format, warnings = [] }: { format?: string | null; warnings?: string[] }) {
	if (!format) return null;
	return (
		<>
			<p className="small mb-2">
				<span className="badge me-2 bg-purple-lt">{format}</span>
				<T id="nginxions.policy.format.v2" />
			</p>
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

/** does the agent apply the policy as NginxionS wrote it (backend waf/applied.js) */
export function AppliedCheckNote({ check }: { check?: AppliedCheck }) {
	if (!check) return null;
	if (check.status !== "drift") {
		const tone = { ok: "text-success", pending: "text-secondary", unknown: "text-secondary" }[check.status];
		return (
			<span className={cn("small", tone)} title={check.error || ""}>
				<T id={`nginxions.policy.check.${check.status}`} />
			</span>
		);
	}
	return (
		<Alert variant="warning" className="small py-2 mb-2">
			<T id="nginxions.policy.check.drift" />
			<ul className="mb-0 ps-3">
				{(check.drift || []).map((d) => {
					const [kind, ...name] = d.split(":");
					return (
						<li key={d}>
							{intl.formatMessage({ id: `nginxions.policy.check.${kind}` }, { name: name.join(":") })}
						</li>
					);
				})}
			</ul>
		</Alert>
	);
}

const VERDICT_TONE = { pass: "bg-green-lt", detect: "bg-yellow-lt", block: "bg-red-lt" } as const;

/** how the change would have treated the WAF events of the recent period */
export function SimulationNote({ simulation }: { simulation?: Simulation | null }) {
	if (!simulation) return null;
	if (simulation.error) {
		return (
			<p className="small text-secondary">
				<T id="nginxions.policy.simulation.error" />
			</p>
		);
	}
	const period = intl.formatMessage({ id: `nginxions.policy.simulation.period.${simulation.period}` });
	if (!simulation.changed) {
		return (
			<p className="small text-secondary">
				<T id="nginxions.policy.simulation.none" data={{ period, events: simulation.events ?? 0 }} />
				{simulation.unknown ? (
					<>
						{" "}
						<T id="nginxions.policy.simulation.unknown" data={{ count: simulation.unknown }} />
					</>
				) : null}
			</p>
		);
	}
	return (
		<div className="mb-3">
			<h4>
				<T id="nginxions.policy.simulation.title" data={{ period }} />
			</h4>
			<p className="small mb-2">
				<T
					id="nginxions.policy.simulation.summary"
					data={{
						events: simulation.events ?? 0,
						changed: simulation.changed,
						pass: simulation.toPass ?? 0,
						block: simulation.toBlock ?? 0,
						detect: simulation.toDetect ?? 0,
					}}
				/>
				{simulation.unknown ? (
					<>
						{" "}
						<T id="nginxions.policy.simulation.unknown" data={{ count: simulation.unknown }} />
					</>
				) : null}
				{simulation.limited ? (
					<>
						{" "}
						<T id="nginxions.policy.simulation.limited" />
					</>
				) : null}
			</p>
			<div className="table-responsive">
				<table className="table table-sm table-vcenter small mb-0">
					<thead>
						<tr>
							<th>
								<T id="nginxions.policy.simulation.request" />
							</th>
							<th>
								<T id="nginxions.policy.simulation.source" />
							</th>
							<th>
								<T id="nginxions.policy.simulation.verdict" />
							</th>
							<th className="text-end">
								<T id="nginxions.policy.simulation.count" />
							</th>
						</tr>
					</thead>
					<tbody>
						{(simulation.samples || []).map((s) => (
							<tr key={`${s.host}|${s.uri}|${s.before}|${s.after}`}>
								<td className="font-monospace text-break">
									{s.host}
									{s.uri}
								</td>
								<td className="font-monospace">{s.source_ip}</td>
								<td className="text-nowrap">
									<span className={cn("badge", VERDICT_TONE[s.before])}>
										<T id={`nginxions.policy.verdict.${s.before}`} />
									</span>
									{" → "}
									<span className={cn("badge", VERDICT_TONE[s.after])}>
										<T id={`nginxions.policy.verdict.${s.after}`} />
									</span>
								</td>
								<td className="text-end">{s.count}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</div>
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
			<FormatNote format={preview.format} warnings={preview.warnings} />
			<SimulationNote simulation={preview.simulation} />
			<h4>
				<T id={preview.changed ? "nginxions.policy.diff" : "nginxions.policy.no-diff"} />
			</h4>
			{preview.changed && preview.diff && <Diff diff={preview.diff} />}
		</>
	);
}
