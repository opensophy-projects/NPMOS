// WAF → Policy (expert): own YAML fragments over the generated local_policy.yaml (ADR-3):
// check with a diff against the file in force, save as a new version, roll back.
import { useQueryClient } from "@tanstack/react-query";
import CodeEditor from "@uiw/react-textarea-code-editor";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useLocaleState } from "src/context";
import { formatDateTime, intl, T } from "src/locale";
import { MANAGE, VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import {
	checkWafCustomPolicy,
	rollbackWafCustomPolicy,
	saveWafCustomPolicy,
	type WafCustomCheck,
	type WafCustomPolicy,
} from "../../api";
import { useWafCustomPolicy } from "../../hooks";
import { showConfirmModal } from "../../modals/ConfirmModal";
import { showWafPolicyModal } from "../../modals/WafPolicyModal";

const example = () => `# ${intl.formatMessage({ id: "npmos.waf.expert.example" })} (docs/tutor.md)
# exceptions:
#   - name: trusted-office
#     action: accept
#     condition:
#       - key: sourceIp
#         value: 203.0.113.10
# policies:
#   default:
#     exceptions:
#       - trusted-office
`;

/** the backend writes rollbacks as "rollback to version N" */
const commentText = (comment: string) => {
	const rollback = /^rollback to version (\d+)$/.exec(comment);
	return rollback ? intl.formatMessage({ id: "npmos.waf.expert.rollback-comment" }, { id: rollback[1] }) : comment;
};

/** lines around a change shown in the diff */
const CONTEXT = 3;

function Diff({ diff }: { diff: NonNullable<WafCustomCheck["diff"]> }) {
	const shown = diff.map((_, i) => diff.slice(Math.max(0, i - CONTEXT), i + CONTEXT + 1).some((x) => x.op !== " "));
	return (
		<pre className="mb-0 p-0" style={{ maxHeight: "50vh", overflow: "auto" }}>
			{diff.map((d, i) =>
				shown[i] ? (
					<div
						// biome-ignore lint/suspicious/noArrayIndexKey: lines of a diff have no identity
						key={i}
						className={cn("px-3", { "bg-green-lt": d.op === "+", "bg-red-lt": d.op === "-" })}
					>
						{d.op} {d.line}
					</div>
				) : i > 0 && shown[i - 1] ? (
					// biome-ignore lint/suspicious/noArrayIndexKey: lines of a diff have no identity
					<div key={i} className="px-3 text-secondary">
						⋯
					</div>
				) : null,
			)}
		</pre>
	);
}

function Versions({ data, onRollback }: { data: WafCustomPolicy; onRollback: (id: number) => void }) {
	const { locale } = useLocaleState();
	if (!data.versions.length) {
		return (
			<div className="card-body text-secondary">
				<T id="npmos.waf.expert.no-versions" />
			</div>
		);
	}
	return (
		<div className="table-responsive">
			<table className="table table-vcenter card-table">
				<thead>
					<tr>
						<th>#</th>
						<th>
							<T id="npmos.waf.expert.saved-on" />
						</th>
						<th>
							<T id="npmos.waf.expert.user" />
						</th>
						<th>
							<T id="npmos.waf.expert.comment" />
						</th>
						<th />
					</tr>
				</thead>
				<tbody>
					{data.versions.map((v) => (
						<tr key={v.id}>
							<td>{v.id}</td>
							<td className="text-nowrap">{formatDateTime(v.createdOn, locale)}</td>
							<td>{v.user || "—"}</td>
							<td>{commentText(v.comment)}</td>
							<td className="text-end">
								{v.id === data.id ? (
									<span className="badge bg-green-lt">
										<T id="npmos.waf.expert.in-force" />
									</span>
								) : (
									<HasPermission rbac="waf_policy" permission={MANAGE} hideError>
										<Button size="sm" onClick={() => onRollback(v.id)}>
											<T id="npmos.waf.expert.rollback" />
										</Button>
									</HasPermission>
								)}
							</td>
						</tr>
					))}
				</tbody>
			</table>
		</div>
	);
}

function WafPolicyPage() {
	const queryClient = useQueryClient();
	const { data, isLoading, isError, error } = useWafCustomPolicy();
	const [content, setContent] = useState<string | null>(null);
	const [comment, setComment] = useState("");
	const [check, setCheck] = useState<WafCustomCheck | null>(null);
	const [busy, setBusy] = useState<"check" | "save" | null>(null);

	useEffect(() => {
		if (data && content === null) setContent(data.content);
	}, [data, content]);

	if (isLoading || content === null) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;

	const changed = content !== data.content;
	const after = async (result: WafCustomPolicy, message: string) => {
		queryClient.setQueryData(["npmos-waf-custom-policy"], result);
		queryClient.invalidateQueries({ queryKey: ["npmos-waf"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-policy"] });
		setContent(result.content);
		setComment("");
		setCheck(null);
		showSuccess(intl.formatMessage({ id: message }));
	};

	const runCheck = async () => {
		setBusy("check");
		try {
			setCheck(await checkWafCustomPolicy(content));
		} catch (err: any) {
			showError(err.message);
		} finally {
			setBusy(null);
		}
	};

	const save = async () => {
		setBusy("save");
		try {
			await after(await saveWafCustomPolicy(content, comment), "npmos.waf.expert.saved");
		} catch (err: any) {
			showError(err.message);
		} finally {
			setBusy(null);
		}
	};

	const rollback = (id: number) =>
		showConfirmModal({
			tTitle: "npmos.waf.expert.rollback",
			tConfirm: "npmos.waf.expert.rollback",
			children: (
				<p>
					<T id="npmos.waf.expert.rollback-confirm" data={{ id }} />
				</p>
			),
			onConfirm: async () => {
				try {
					await after(await rollbackWafCustomPolicy(id), "npmos.waf.expert.saved");
				} catch (err: any) {
					showError(err.message);
				}
			},
		});

	const applied = data.policy?.applied;

	return (
		<>
			<div className="card mt-4">
				<div className="card-status-top bg-red" />
				<div className="card-header">
					<div className="row w-full align-items-center">
						<div className="col">
							<h2 className="mt-1 mb-0">
								<T id="npmos.waf.expert" />
							</h2>
							<div className="text-secondary">
								<T id="npmos.waf.expert.description" />
							</div>
						</div>
						<div className="col-auto">
							<Button size="sm" onClick={showWafPolicyModal}>
								<T id="npmos.waf.policy-show" />
							</Button>
						</div>
					</div>
				</div>
				<div className="card-body">
					<p className="text-secondary small mb-2">
						<T id="npmos.waf.expert.rules" />
					</p>
					<CodeEditor
						value={content}
						language="yaml"
						placeholder={example()}
						onChange={(e) => {
							setContent(e.target.value);
							setCheck(null);
						}}
						padding={15}
						data-color-mode="dark"
						minHeight={260}
						indentWidth={2}
						style={{
							fontFamily: "ui-monospace,SFMono-Regular,SF Mono,Consolas,Liberation Mono,Menlo,monospace",
							borderRadius: "0.3rem",
							minHeight: "260px",
							backgroundColor: "var(--tblr-bg-surface-dark)",
						}}
					/>
					{check && !check.valid && (
						<Alert variant="danger" className="mt-3 mb-0">
							<pre className="mb-0 bg-transparent p-0 text-reset" style={{ whiteSpace: "pre-wrap" }}>
								{check.error}
							</pre>
						</Alert>
					)}
					{check?.valid && (
						<div className="mt-3">
							<h4>
								<T id={check.changed ? "npmos.waf.expert.diff" : "npmos.waf.expert.no-diff"} />
							</h4>
							{check.changed && check.diff && <Diff diff={check.diff} />}
						</div>
					)}
				</div>
				<HasPermission rbac="waf_policy" permission={MANAGE} hideError>
					<div className="card-footer">
						<div className="row g-2 align-items-center">
							<div className="col">
								<input
									className="form-control form-control-sm"
									maxLength={255}
									placeholder={intl.formatMessage({ id: "npmos.waf.expert.comment" })}
									value={comment}
									onChange={(e) => setComment(e.target.value)}
								/>
							</div>
							<div className="col-auto">
								<Button size="sm" isLoading={busy === "check"} onClick={runCheck}>
									<T id="npmos.waf.expert.check" />
								</Button>
								<Button
									size="sm"
									actionType="primary"
									className="ms-2"
									disabled={!changed || (check !== null && !check.valid)}
									isLoading={busy === "save"}
									onClick={save}
								>
									<T id="npmos.waf.expert.save" />
								</Button>
							</div>
						</div>
						{applied && !applied.ok && (
							<div className="text-warning small mt-2">
								<T id="npmos.waf.policy-not-sent" /> ({applied.error})
							</div>
						)}
					</div>
				</HasPermission>
			</div>
			<div className="card mt-4">
				<div className="card-header">
					<h3 className="card-title">
						<T id="npmos.waf.expert.versions" />
					</h3>
				</div>
				<Versions data={data} onRollback={rollback} />
			</div>
		</>
	);
}

const WafPolicy = () => (
	<HasPermission rbac="waf_policy" permission={VIEW} pageLoading loadingNoLogo>
		<WafPolicyPage />
	</HasPermission>
);

export default WafPolicy;
