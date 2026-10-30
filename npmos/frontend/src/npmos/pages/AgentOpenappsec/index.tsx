// Agents → open-appsec: one page for the agent, laid out like an editor. On the left what the policy is made
// of: the base policy, the policies of the hosts, the building blocks (objects), the versions and the YAML
// additions; on the right the chosen item, in the GUI or as code (the same thing, either way, checked before
// it is applied). Learning: the queue of what the agent is not sure about, labels, readiness of the hosts. The last
// tab is the agent itself: on/off, state, settings.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import cn from "classnames";
import { Form, Formik } from "formik";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useSearchParams } from "react-router-dom";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useProxyHosts } from "src/hooks";
import { intl, T } from "src/locale";
import { VIEW } from "src/modules/Permissions";
import { showError, showSuccess } from "src/notifications";
import { setWafHost } from "../../api";
import { fromWafForm, toWafForm, WafFields } from "../../components/WafFields";
import { useWafHost, useWafHosts } from "../../hooks";
import { LearningTab } from "../../learning/Learning";
import {
	getHostCode,
	getPolicyCode,
	getPolicyObjects,
	importPolicy,
	type ImportResult,
	KINDS,
	type Kind,
	type PolicyObjects,
	putHostCode,
} from "../../policy/api";
import { type CodeCheck, CodePane } from "../../policy/CodePane";
import { useCan } from "../../rbac/hooks";
import hostStyles from "../Hosts/Hosts.module.css";
import WafAgent from "../WafAgent";
import WafExpert from "../WafExpert";
import { DefaultPolicyTab, ObjectsTab, QUERY, VersionsTab } from "../WafPolicy";
import styles from "./Agent.module.css";

const t = (id: string, values?: Record<string, any>) => intl.formatMessage({ id }, values);

/** v1beta2 section of each kind (the export of one kind) */
const SECTION: Record<Kind, string> = {
	threat_prevention: "threatPreventionPractices",
	access_control: "accessControlPractices",
	log_trigger: "logTriggers",
	custom_response: "customResponses",
	exception: "exceptions",
	trusted_sources: "trustedSources",
	source_identifiers: "sourcesIdentifiers",
};

type Item =
	| { type: "default" }
	| { type: "host"; id: number }
	| { type: "kind"; kind: Kind }
	| { type: "versions" }
	| { type: "expert" };

const itemKey = (item: Item) =>
	item.type === "host" ? `host-${item.id}` : item.type === "kind" ? `kind-${item.kind}` : item.type;

const parseItem = (value: string | null): Item => {
	const host = /^host-(\d+)$/.exec(value ?? "");
	if (host) return { type: "host", id: Number(host[1]) };
	const kind = /^kind-([a-z_]+)$/.exec(value ?? "");
	if (kind && (KINDS as string[]).includes(kind[1])) return { type: "kind", kind: kind[1] as Kind };
	if (value === "versions" || value === "expert") return { type: value };
	return { type: "default" };
};

/** what an import of a document would do, in words */
const importSummary = (r: ImportResult) =>
	[
		r.create.length ? t("npmos.code.import.create", { names: r.create.join(", ") }) : "",
		r.update.length ? t("npmos.code.import.update", { names: r.update.join(", ") }) : "",
		r.skipped.length ? t("npmos.code.import.skipped", { names: r.skipped.join(", ") }) : "",
		r.policy ? t("npmos.code.import.policy") : "",
	]
		.filter(Boolean)
		.join(" ");

const importCheck = async (content: string): Promise<CodeCheck> => {
	const r = await importPolicy(content, true);
	if (r.errors.length) return { valid: false, error: r.errors.join("\n") };
	return { valid: true, summary: <span className="text-secondary small">{importSummary(r)}</span> };
};

const importApply = async (content: string) => {
	const r = await importPolicy(content, false);
	if (r.errors.length) throw new Error(r.errors.join("\n"));
};

function HostPolicy({ id, name, paths, manage }: { id: number; name: string; paths: string[]; manage: boolean }) {
	const queryClient = useQueryClient();
	const { data, isLoading, error } = useWafHost(id);
	if (isLoading) return <LoadingPage noLogo />;
	if (!data) return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;
	return (
		<Formik
			enableReinitialize
			initialValues={{ npmosWaf: toWafForm(data), locations: paths.map((path) => ({ path })) }}
			onSubmit={async (values, { setSubmitting }) => {
				try {
					await setWafHost(id, fromWafForm(values.npmosWaf, paths));
					queryClient.invalidateQueries({ queryKey: ["npmos-waf-host", id] });
					queryClient.invalidateQueries({ queryKey: ["npmos-waf-hosts"] });
					showSuccess(t("npmos.agent.host.saved", { name }));
				} catch (err: any) {
					showError(err.message);
				}
				setSubmitting(false);
			}}
		>
			{({ isSubmitting, dirty }) => (
				<Form>
					<fieldset disabled={!manage}>
						<WafFields />
					</fieldset>
					{manage && (
						<Button
							type="submit"
							className="btn-primary"
							disabled={!dirty || isSubmitting}
							isLoading={isSubmitting}
						>
							<T id="save" />
						</Button>
					)}
				</Form>
			)}
		</Formik>
	);
}

function Pane({
	item,
	data,
	manage,
	refresh,
	hosts,
}: {
	item: Item;
	data: PolicyObjects;
	manage: boolean;
	refresh: () => void;
	hosts: { id: number; name: string; paths: string[] }[];
}) {
	const queryClient = useQueryClient();
	const [view, setView] = useState<"gui" | "code">("gui");
	const host = item.type === "host" ? hosts.find((h) => h.id === item.id) : undefined;
	const coded = item.type === "default" || item.type === "kind" || item.type === "host";

	const title =
		item.type === "default" ? (
			<T id="npmos.policy.default" />
		) : item.type === "host" ? (
			(host?.name ?? `#${item.id}`)
		) : item.type === "kind" ? (
			<T id={`npmos.policy.kinds.${item.kind}`} />
		) : (
			<T id={`npmos.agent.item.${item.type}`} />
		);
	const hint =
		item.type === "kind"
			? t(`npmos.policy.kinds.${item.kind}.hint`)
			: item.type === "default"
				? t("npmos.agent.default.hint")
				: item.type === "host"
					? t("npmos.agent.host.hint")
					: t(`npmos.agent.item.${item.type}.hint`);

	const afterCode = () => {
		refresh();
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-hosts"] });
		if (item.type === "host") queryClient.invalidateQueries({ queryKey: ["npmos-waf-host", item.id] });
	};

	return (
		<section className={cn("card", styles.pane)}>
			<div className={styles.paneHead}>
				<div>
					<h2 className={styles.paneTitle}>{title}</h2>
					<p className={styles.paneHint}>{hint}</p>
				</div>
				{coded && (
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
				)}
			</div>
			<div className={styles.paneBody}>
				{coded && view === "code" ? (
					item.type === "host" ? (
						<CodePane
							id={itemKey(item)}
							manage={manage}
							hint={<T id="npmos.code.hint.host" />}
							load={async () => (await getHostCode(item.id)).content}
							check={async (content) => putHostCode(item.id, content, true)}
							apply={async (content) => {
								const r = await putHostCode(item.id, content, false);
								if (!r.valid) throw new Error(r.error);
								afterCode();
							}}
						/>
					) : (
						<CodePane
							id={itemKey(item)}
							manage={manage}
							hint={<T id={item.type === "kind" ? "npmos.code.hint.kind" : "npmos.code.hint.default"} />}
							load={() => getPolicyCode(item.type === "kind" ? SECTION[item.kind] : undefined)}
							check={importCheck}
							apply={async (content) => {
								await importApply(content);
								afterCode();
							}}
						/>
					)
				) : item.type === "default" ? (
					<DefaultPolicyTab data={data} manage={manage} refresh={refresh} />
				) : item.type === "kind" ? (
					<ObjectsTab kind={item.kind} data={data} manage={manage} refresh={refresh} />
				) : item.type === "host" ? (
					host ? (
						<HostPolicy id={host.id} name={host.name} paths={host.paths} manage={manage} />
					) : (
						<Alert variant="warning">
							<T id="npmos.agent.host.none" />
						</Alert>
					)
				) : item.type === "versions" ? (
					<VersionsTab manage={manage} refresh={refresh} />
				) : (
					<WafExpert />
				)}
			</div>
		</section>
	);
}

function PoliciesTab() {
	const can = useCan();
	const manage = can("waf_policy", "manage");
	const queryClient = useQueryClient();
	const [params, setParams] = useSearchParams();
	const item = parseItem(params.get("item"));
	const { data, isLoading, isError, error } = useQuery<PolicyObjects, Error>({
		queryKey: QUERY,
		queryFn: getPolicyObjects,
	});
	const proxies = useProxyHosts([]);
	const waf = useWafHosts();
	const refresh = () => {
		queryClient.invalidateQueries({ queryKey: QUERY });
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-policy-versions"] });
		queryClient.invalidateQueries({ queryKey: ["npmos-waf-policy"] });
	};
	const choose = (next: Item) => {
		const p = new URLSearchParams(params);
		if (next.type === "default") p.delete("item");
		else p.set("item", itemKey(next));
		setParams(p, { replace: true });
	};

	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data)
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;

	const hosts = (proxies.data ?? []).map((h: any) => ({
		id: h.id as number,
		name: (h.domainNames as string[]).join(", "),
		paths: ((h.locations ?? []) as { path: string }[]).map((l) => l.path).filter(Boolean),
	}));
	const mode = (id: number) => {
		const s = waf.data?.[id];
		return !s?.enabled ? "off" : s.mode === "prevent-learn" ? "prevent" : "detect";
	};
	const NavItem = ({ value, children, sub }: { value: Item; children: React.ReactNode; sub?: React.ReactNode }) => (
		<button
			type="button"
			className={cn(styles.navItem, itemKey(value) === itemKey(item) && styles.navOn)}
			onClick={() => choose(value)}
		>
			<span className={styles.navLabel}>{children}</span>
			{sub}
		</button>
	);

	return (
		<div className={styles.editor}>
			<nav className={cn("card", styles.nav)} aria-label={t("npmos.agent.policies")}>
				<div className={styles.navGroup}>
					<T id="npmos.agent.group.policies" />
				</div>
				<NavItem value={{ type: "default" }}>
					<T id="npmos.policy.default" />
				</NavItem>
				{hosts.map((h) => (
					<NavItem
						key={h.id}
						value={{ type: "host", id: h.id }}
						sub={
							<span className={cn(styles.mode, styles[mode(h.id)])}>
								{t(`npmos.hosts.waf.${mode(h.id)}`)}
							</span>
						}
					>
						{h.name}
					</NavItem>
				))}
				<div className={styles.navGroup}>
					<T id="npmos.agent.group.blocks" />
				</div>
				{KINDS.map((kind) => (
					<NavItem
						key={kind}
						value={{ type: "kind", kind }}
						sub={<span className={styles.count}>{data.objects.filter((o) => o.kind === kind).length}</span>}
					>
						<T id={`npmos.policy.kinds.${kind}`} />
					</NavItem>
				))}
				<div className={styles.navGroup}>
					<T id="npmos.agent.group.more" />
				</div>
				<NavItem value={{ type: "versions" }}>
					<T id="npmos.agent.item.versions" />
				</NavItem>
				<NavItem value={{ type: "expert" }}>
					<T id="npmos.agent.item.expert" />
				</NavItem>
			</nav>
			<Pane key={itemKey(item)} item={item} data={data} manage={manage} refresh={refresh} hosts={hosts} />
		</div>
	);
}

function AgentOpenappsecPage() {
	const [params, setParams] = useSearchParams();
	const can = useCan();
	const tabs = ["policies", ...(can("waf_learning") ? ["learning"] : []), "agent"] as const;
	const asked = params.get("tab") || "";
	const tab = (tabs as readonly string[]).includes(asked) ? asked : "policies";
	return (
		<div className={hostStyles.page}>
			<div className={hostStyles.head}>
				<div>
					<h1 className={hostStyles.title}>
						<T id="npmos.nav.agent-openappsec" />
					</h1>
					<p className={hostStyles.subtitle}>
						<T id="npmos.agent.openappsec.description" />
					</p>
				</div>
			</div>
			<ul className="nav nav-tabs">
				{tabs.map((x) => (
					<li className="nav-item" key={x}>
						<button
							type="button"
							className={cn("nav-link", { active: tab === x })}
							onClick={() => setParams(x === "policies" ? {} : { tab: x }, { replace: true })}
						>
							<T id={`npmos.agent.tab.${x}`} />
						</button>
					</li>
				))}
			</ul>
			{tab === "policies" ? <PoliciesTab /> : tab === "learning" ? <LearningTab /> : <WafAgent />}
		</div>
	);
}

const AgentOpenappsec = () => (
	<HasPermission rbac="waf_policy" permission={VIEW} pageLoading loadingNoLogo>
		<AgentOpenappsecPage />
	</HasPermission>
);

export default AgentOpenappsec;
