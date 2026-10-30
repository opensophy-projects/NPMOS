// Agents → Block page: what a visitor sees when a request is refused by open-appsec, the CrowdSec bouncer or an
// access list, instead of the page of the agent ("Check Point's Application Security has detected an attack").
// The settings in the interface or as code, with the page as it will look.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { useEffect, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, HasPermission, LoadingPage } from "src/components";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import {
	type BlockPageSettings,
	getBlockPage,
	getBlockPageCode,
	previewBlockPage,
	putBlockPageCode,
	setBlockPage,
} from "../../api";
import { CodePane } from "../../policy/CodePane";
import { useCan } from "../../rbac/hooks";
import styles from "../AgentOpenappsec/Agent.module.css";
import hostStyles from "../Hosts/Hosts.module.css";
import own from "./BlockPage.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);
const QUERY = ["npmos-block-page"];

/** the values nginx fills in, for the preview */
const SAMPLE: Record<string, string> = {
	"{{id}}": "4f2c9e1a7b3d48e6a0c5d2f1e8b7a6c9",
	"{{ip}}": "203.0.113.7",
	"{{host}}": "app.example.com",
	"{{time}}": "2026-10-30T12:00:00+00:00",
};
const sample = (html: string) => Object.entries(SAMPLE).reduce((s, [k, v]) => s.replaceAll(k, v), html);

function Form({ initial, manage }: { initial: BlockPageSettings; manage: boolean }) {
	const queryClient = useQueryClient();
	const [form, setForm] = useState(initial);
	const [preview, setPreview] = useState("");
	const [saving, setSaving] = useState(false);
	const set = (patch: Partial<BlockPageSettings>) => setForm({ ...form, ...patch });
	const changed = JSON.stringify(form) !== JSON.stringify(initial);

	// the preview follows the form a moment after typing stops
	useEffect(() => {
		const timer = setTimeout(
			() =>
				previewBlockPage(form)
					.then((r) => setPreview(r.preview))
					.catch(() => undefined),
			300,
		);
		return () => clearTimeout(timer);
	}, [form]);

	const save = async () => {
		setSaving(true);
		try {
			await setBlockPage(form);
			queryClient.invalidateQueries({ queryKey: QUERY });
			showSuccess(t("npmos.block-page.saved"));
		} catch (err: any) {
			showError(err.message);
		}
		setSaving(false);
	};

	return (
		<div className={own.layout}>
			<fieldset disabled={!manage} className={own.form}>
				<label className="form-check form-switch">
					<input
						className="form-check-input"
						type="checkbox"
						checked={form.enabled}
						onChange={(e) => set({ enabled: e.target.checked })}
					/>
					<span className="form-check-label">
						<T id="npmos.block-page.enabled" />
					</span>
				</label>
				<p className="text-secondary small">
					<T id="npmos.block-page.enabled.hint" />
				</p>
				<div className="mb-3">
					<label className="form-label" htmlFor="bp-title">
						<T id="npmos.block-page.title" />
					</label>
					<input
						id="bp-title"
						className="form-control"
						maxLength={200}
						value={form.title}
						onChange={(e) => set({ title: e.target.value })}
					/>
				</div>
				<div className="mb-3">
					<label className="form-label" htmlFor="bp-text">
						<T id="npmos.block-page.text" />
					</label>
					<textarea
						id="bp-text"
						className="form-control"
						rows={4}
						maxLength={2000}
						value={form.text}
						onChange={(e) => set({ text: e.target.value })}
					/>
					<div className="form-hint">
						<T id="npmos.block-page.text.hint" />
					</div>
				</div>
				<div className="mb-3">
					<label className="form-label" htmlFor="bp-contact">
						<T id="npmos.block-page.contact" />
					</label>
					<input
						id="bp-contact"
						className="form-control"
						maxLength={500}
						value={form.contact}
						placeholder={t("npmos.block-page.contact.placeholder")}
						onChange={(e) => set({ contact: e.target.value })}
					/>
				</div>
				<div className="row">
					<div className="col-auto mb-3">
						<label className="form-label" htmlFor="bp-accent">
							<T id="npmos.block-page.accent" />
						</label>
						<input
							id="bp-accent"
							type="color"
							className="form-control form-control-color"
							value={form.accent}
							onChange={(e) => set({ accent: e.target.value })}
						/>
					</div>
					<div className="col-auto mb-3">
						<label className="form-label" htmlFor="bp-language">
							<T id="npmos.block-page.language" />
						</label>
						<select
							id="bp-language"
							className="form-select"
							value={form.language ?? "en"}
							onChange={(e) => set({ language: e.target.value as "en" | "ru" })}
						>
							<option value="ru">Русский</option>
							<option value="en">English</option>
						</select>
					</div>
					<div className="col mb-3 d-flex align-items-end">
						<label className="form-check">
							<input
								className="form-check-input"
								type="checkbox"
								checked={form.details}
								onChange={(e) => set({ details: e.target.checked })}
							/>
							<span className="form-check-label">
								<T id="npmos.block-page.details" />
							</span>
						</label>
					</div>
				</div>
				{manage && (
					<Button className="btn-primary" onClick={save} disabled={!changed || saving} isLoading={saving}>
						<T id="save" />
					</Button>
				)}
			</fieldset>
			<div className={own.preview}>
				<div className={own.previewHead}>
					<T id="npmos.block-page.preview" />
				</div>
				{form.enabled ? (
					<iframe
						title={t("npmos.block-page.preview")}
						className={own.frame}
						srcDoc={sample(preview)}
						sandbox=""
					/>
				) : (
					<p className="text-secondary small p-3 mb-0">
						<T id="npmos.block-page.off" />
					</p>
				)}
			</div>
		</div>
	);
}

function BlockPagePage() {
	const can = useCan();
	const manage = can("waf_policy", "manage");
	const queryClient = useQueryClient();
	const [view, setView] = useState<"gui" | "code">("gui");
	const { data, isLoading, error } = useQuery({ queryKey: QUERY, queryFn: getBlockPage });
	if (isLoading) return <LoadingPage noLogo />;
	if (!data)
		return <Alert variant="danger">{(error as Error)?.message || <T id="npmos.common.unknown-error" />}</Alert>;
	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.block-page" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.block-page.description" />
					</p>
				</div>
			</div>
			<section className={cn("card", styles.pane)}>
				<div className={styles.paneHead}>
					<div>
						<h2 className={styles.paneTitle}>
							<T id="npmos.block-page.settings" />
						</h2>
						<p className={styles.paneHint}>
							<T id="npmos.block-page.where" />
						</p>
					</div>
					<div className={styles.toggle} role="group" aria-label={t("npmos.agent.view")}>
						{(["gui", "code"] as const).map((v) => (
							<button
								key={v}
								type="button"
								className={cn(styles.toggleItem, view === v && styles.toggleOn)}
								aria-pressed={view === v}
								onClick={() => setView(v)}
							>
								<T id={`npmos.agent.view.${v}`} />
							</button>
						))}
					</div>
				</div>
				<div className={styles.paneBody}>
					{view === "gui" ? (
						<Form key={JSON.stringify(data.settings)} initial={data.settings} manage={manage} />
					) : (
						<CodePane
							id="block-page"
							manage={manage}
							load={async () => (await getBlockPageCode()).content}
							check={(content) => putBlockPageCode(content, true)}
							apply={async (content) => {
								const r = await putBlockPageCode(content, false);
								if (!r.valid) throw new Error(r.error);
								queryClient.invalidateQueries({ queryKey: QUERY });
							}}
						/>
					)}
				</div>
			</section>
		</div>
	);
}

const BlockPage = () => (
	<HasPermission rbac="waf_policy" permission={VIEW} pageLoading loadingNoLogo>
		<BlockPagePage />
	</HasPermission>
);

export default BlockPage;
