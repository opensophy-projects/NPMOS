// Terms that stay in English in the interface (docs/ROADMAP.md, phase 2 "Glossary"). The name is
// the term itself; its explanation is `npmos.glossary.<id>` in the locales.
export interface Term {
	id: string;
	/** as it appears in the interface */
	name: string;
	group: "hosts" | "tls" | "waf" | "crowdsec" | "system";
}

export const TERMS: Term[] = [
	{ id: "proxy-host", name: "Proxy host", group: "hosts" },
	{ id: "redirect", name: "Redirection host", group: "hosts" },
	{ id: "stream", name: "Stream", group: "hosts" },
	{ id: "dead-host", name: "404 host", group: "hosts" },
	{ id: "upstream", name: "Upstream", group: "hosts" },
	{ id: "access-list", name: "Access list", group: "hosts" },
	{ id: "tls", name: "TLS / SSL", group: "tls" },
	{ id: "acme", name: "Let's Encrypt (ACME)", group: "tls" },
	{ id: "hsts", name: "HSTS", group: "tls" },
	{ id: "mtls", name: "mTLS", group: "tls" },
	{ id: "ca", name: "CA", group: "tls" },
	{ id: "waf", name: "WAF", group: "waf" },
	{ id: "open-appsec", name: "open-appsec", group: "waf" },
	{ id: "agent", name: "Agent", group: "waf" },
	{ id: "detect-learn", name: "Detect-Learn", group: "waf" },
	{ id: "prevent-learn", name: "Prevent-Learn", group: "waf" },
	{ id: "confidence", name: "Minimum confidence", group: "waf" },
	{ id: "severity", name: "Severity: Critical / High / Medium / Low", group: "waf" },
	{ id: "policy", name: "Policy (local_policy.yaml)", group: "waf" },
	{ id: "fail-open", name: "Fail-open / fail-close", group: "waf" },
	{ id: "advanced-model", name: "Advanced model", group: "waf" },
	{ id: "tuning", name: "Tuning / smartsync", group: "waf" },
	{ id: "crowdsec", name: "CrowdSec", group: "crowdsec" },
	{ id: "bouncer", name: "Bouncer", group: "crowdsec" },
	{ id: "decision", name: "Decision", group: "crowdsec" },
	{ id: "nginx", name: "nginx", group: "system" },
	{ id: "audit-log", name: "Audit log", group: "system" },
	{ id: "air-gap", name: "Air-gap / local-first", group: "system" },
];

export const GROUPS = ["hosts", "tls", "waf", "crowdsec", "system"] as const;
