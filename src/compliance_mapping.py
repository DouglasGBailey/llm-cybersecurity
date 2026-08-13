"""Maps finding types to compliance framework controls.

Deliberately incomplete: only finding types that represent an actual
security-relevant condition get a mapping. Pure informational findings
(dns-resolution, page-title, whois-registrar, ...), "good news" findings
(spf-record-found, dnssec-enabled, ...), and operational/meta findings
(tool-unavailable, error, ...) intentionally have no entry here -- a
fabricated mapping for those would be noise, not signal.

Primary framework is OWASP Top 10 2021 (the most universally recognized),
with a secondary framework (CIS Controls v8 or PCI DSS 4.0) added where a
clear, defensible second mapping exists. LLM-specific findings map to the
OWASP Top 10 for LLM Applications instead, since that's the framework
actually built for this category.
"""
from __future__ import annotations

COMPLIANCE_MAP: dict[str, list[dict[str, str]]] = {
    # --- Web app / transport hygiene ---
    "missing-security-headers": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.1 - Establish and Maintain a Secure Configuration Process"},
    ],
    "tls-certificate-expired": [
        {"framework": "OWASP Top 10 2021", "control": "A02:2021 - Cryptographic Failures"},
        {"framework": "PCI DSS 4.0", "control": "4.2.1 - Strong cryptography for transmission"},
    ],
    "tls-certificate-expiring-soon": [
        {"framework": "OWASP Top 10 2021", "control": "A02:2021 - Cryptographic Failures"},
    ],
    "server-banner": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.1 - Establish and Maintain a Secure Configuration Process"},
    ],
    "x-powered-by": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
    ],
    "open-port": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.8 - Uninstall or Disable Unnecessary Services on Enterprise Assets"},
    ],

    # --- API hygiene ---
    "openapi-no-security-scheme-declared": [
        {"framework": "OWASP Top 10 2021", "control": "A01:2021 - Broken Access Control"},
    ],
    "openapi-spec-exposed": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
    ],
    "graphql-introspection-enabled": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
    ],
    "verbose-error-page": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
    ],

    # --- Email/DNS hygiene (no OWASP mapping -- not an application-layer control) ---
    "spf-record-missing": [
        {"framework": "CIS Controls v8", "control": "9.5 - Implement DMARC/SPF Email Authentication"},
    ],
    "dmarc-record-missing": [
        {"framework": "CIS Controls v8", "control": "9.5 - Implement DMARC/SPF Email Authentication"},
    ],

    # --- Code-level findings (bandit/semgrep severity varies by rule; this
    # is a general-purpose mapping, not per-rule) ---
    "bandit-finding": [
        {"framework": "OWASP Top 10 2021", "control": "A03:2021 - Injection"},
        {"framework": "CIS Controls v8", "control": "16.1 - Establish and Maintain a Secure Application Development Process"},
    ],
    "semgrep-finding": [
        {"framework": "OWASP Top 10 2021", "control": "A03:2021 - Injection"},
        {"framework": "CIS Controls v8", "control": "16.1 - Establish and Maintain a Secure Application Development Process"},
    ],

    # --- LLM-specific (maps to the framework built for this category, not OWASP web top 10) ---
    "llm-probe-failed": [
        {"framework": "OWASP Top 10 for LLM Applications", "control": "LLM01 - Prompt Injection"},
    ],

    # --- Confirmed exploitation (ExploitAgent) -- proven impact, not just a
    # detected weakness, but the OWASP category is the same underlying class ---
    "sqli-exploited": [
        {"framework": "OWASP Top 10 2021", "control": "A03:2021 - Injection"},
    ],
    "xss-exploited": [
        {"framework": "OWASP Top 10 2021", "control": "A03:2021 - Injection"},
    ],
    "command-injection-exploited": [
        {"framework": "OWASP Top 10 2021", "control": "A03:2021 - Injection"},
    ],
    "weak-credentials-exploited": [
        {"framework": "OWASP Top 10 2021", "control": "A07:2021 - Identification and Authentication Failures"},
    ],

    # --- Kubernetes hygiene (KubernetesAnalyzer) ---
    "k8s-privileged-container": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.1 - Establish and Maintain a Secure Configuration Process"},
    ],
    "k8s-container-runs-as-root": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.1 - Establish and Maintain a Secure Configuration Process"},
    ],
    "k8s-host-namespace-shared": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.1 - Establish and Maintain a Secure Configuration Process"},
    ],
    "k8s-missing-resource-limits": [
        {"framework": "CIS Controls v8", "control": "4.1 - Establish and Maintain a Secure Configuration Process"},
    ],
    "k8s-overly-permissive-clusterrolebinding": [
        {"framework": "OWASP Top 10 2021", "control": "A01:2021 - Broken Access Control"},
        {"framework": "CIS Controls v8", "control": "6.8 - Define and Maintain Role-Based Access Control"},
    ],
    "k8s-wildcard-clusterrole": [
        {"framework": "OWASP Top 10 2021", "control": "A01:2021 - Broken Access Control"},
        {"framework": "CIS Controls v8", "control": "6.8 - Define and Maintain Role-Based Access Control"},
    ],
    "k8s-service-publicly-exposed": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
        {"framework": "CIS Controls v8", "control": "4.8 - Uninstall or Disable Unnecessary Services on Enterprise Assets"},
    ],
    "k8s-namespace-missing-network-policy": [
        {"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"},
    ],
    "k8s-default-serviceaccount-automounts-token": [
        {"framework": "OWASP Top 10 2021", "control": "A01:2021 - Broken Access Control"},
    ],
}


def compliance_tags_for(finding_type: str) -> list[dict[str, str]]:
    return COMPLIANCE_MAP.get(finding_type, [])
