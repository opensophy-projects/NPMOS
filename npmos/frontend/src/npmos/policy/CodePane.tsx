// "Code" of a policy (Agents → open-appsec): the same thing the GUI edits, as YAML. Edited text is checked by the
// server first and shown as a change against what is in force (as a code review); only a document that passed
// the check is applied. A text that does not pass is never saved.
import CodeEditor from "@uiw/react-textarea-code-editor";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { showError, showSuccess } from "src/notifications";
import { CodeDiff, diffLines } from "../ui/CodeDiff";

export interface CodeCheck {
	valid: boolean;
	error?: string;
	/** what the server will do, in words */
	summary?: React.ReactNode;
}

interface Props {
	/** reloads when it changes */
	id: string;
	load: () => Promise<string>;
	check: (content: string) => Promise<CodeCheck>;
	apply: (content: string) => Promise<void>;
	manage: boolean;
	/** a line above the editor: what the document holds */
	hint?: React.ReactNode;
}

export function CodePane({ id, load, check, apply, manage, hint }: Props) {
	const [original, setOriginal] = useState<string | null>(null);
	const [text, setText] = useState("");
	const [result, setResult] = useState<{ content: string; check: CodeCheck } | null>(null);
	const [busy, setBusy] = useState(false);
	const [loadError, setLoadError] = useState<string | null>(null);

	const reload = async () => {
		try {
			const content = await load();
			setOriginal(content);
			setText(content);
			setResult(null);
			setLoadError(null);
		} catch (err: any) {
			setLoadError(err.message);
		}
	};
	// biome-ignore lint/correctness/useExhaustiveDependencies: a new document when the item changes
	useEffect(() => {
		setOriginal(null);
		reload();
	}, [id]);

	if (loadError) return <Alert variant="danger">{loadError}</Alert>;
	if (original === null) return <LoadingPage noLogo />;

	const changed = text !== original;
	const checked = result && result.content === text && result.check.valid;

	const runCheck = async () => {
		setBusy(true);
		try {
			setResult({ content: text, check: await check(text) });
		} catch (err: any) {
			setResult({ content: text, check: { valid: false, error: err.message } });
		}
		setBusy(false);
	};
	const runApply = async () => {
		setBusy(true);
		try {
			await apply(text);
			showSuccess(intl.formatMessage({ id: "npmos.code.applied" }));
			await reload();
		} catch (err: any) {
			showError(err.message);
		}
		setBusy(false);
	};

	return (
		<div>
			{hint && <p className="text-secondary small mb-2">{hint}</p>}
			<CodeEditor
				value={text}
				language="yaml"
				readOnly={!manage}
				onChange={(e) => {
					setText(e.target.value);
					setResult(null);
				}}
				padding={15}
				data-color-mode="dark"
				minHeight={320}
				indentWidth={2}
				style={{
					fontFamily: "ui-monospace,SFMono-Regular,SF Mono,Consolas,Liberation Mono,Menlo,monospace",
					fontSize: 13,
					borderRadius: "0.5rem",
					minHeight: "320px",
					backgroundColor: "var(--tblr-bg-surface-dark)",
				}}
			/>
			{manage && (
				<div className="d-flex flex-wrap gap-2 mt-3">
					<Button onClick={runCheck} disabled={busy || !changed}>
						<T id="npmos.code.check" />
					</Button>
					<Button className="btn-primary" onClick={runApply} disabled={busy || !checked}>
						<T id="npmos.code.apply" />
					</Button>
					<Button
						onClick={() => {
							setText(original);
							setResult(null);
						}}
						disabled={busy || !changed}
					>
						<T id="npmos.code.reset" />
					</Button>
					<span className="text-secondary small align-self-center">
						<T
							id={
								changed
									? checked
										? "npmos.code.ready"
										: "npmos.code.check-first"
									: "npmos.code.unchanged"
							}
						/>
					</span>
				</div>
			)}
			{result && !result.check.valid && (
				<Alert variant="danger" className="mt-3 mb-0">
					<pre className="mb-0 bg-transparent p-0 text-reset" style={{ whiteSpace: "pre-wrap" }}>
						{result.check.error}
					</pre>
				</Alert>
			)}
			{result?.check.valid && (
				<div className="mt-3">
					{result.check.summary && <div className="mb-2">{result.check.summary}</div>}
					<h4 className="mb-2">
						<T id="npmos.code.review" />
					</h4>
					<CodeDiff diff={diffLines(original, result.content)} />
				</div>
			)}
		</div>
	);
}
