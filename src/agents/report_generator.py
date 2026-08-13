"""Report Generator: renders an EvidenceCollector bundle as a human-readable
Markdown report -- executive summary, findings grouped by a simple severity
heuristic, then a raw evidence appendix. Not a scanning agent -- no
network/tool access needed.
"""
from __future__ import annotations

import json
from typing import Any

SEVERITY_BY_TYPE = {
    "tls-certificate-expired": "high",
    "llm-probe-failed": "high",
    "tls-certificate-expiring-soon": "medium",
    "missing-security-headers": "medium",
    "openapi-no-security-scheme-declared": "medium",
    "verbose-error-page": "medium",
    "graphql-introspection-enabled": "low",
    "spf-record-missing": "low",
    "dmarc-record-missing": "low",
}
SEVERITY_ORDER = ["high", "medium", "low", "info"]
BANDIT_SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _severity_for(finding: dict[str, Any]) -> str:
    ftype = finding.get("type", "")
    if ftype == "bandit-finding":
        return BANDIT_SEVERITY_MAP.get(str(finding.get("severity", "")).upper(), "medium")
    if ftype == "semgrep-finding":
        return SEMGREP_SEVERITY_MAP.get(str(finding.get("severity", "")).upper(), "medium")
    return SEVERITY_BY_TYPE.get(ftype, "info")


class ReportGenerator:
    def generate(self, evidence: dict[str, Any]) -> str:
        lines: list[str] = []
        lines.append("# Security Assessment Report")
        lines.append("")
        lines.append(f"**Generated:** {evidence['generated_at']}")
        lines.append(f"**Target(s):** {', '.join(evidence['targets']) or '(none)'}")
        lines.append(f"**Agents run:** {', '.join(evidence['agents_run']) or '(none)'}")
        lines.append("")

        summary = evidence["summary"]
        lines.append("## Executive Summary")
        lines.append(f"- Total findings (raw, across all agents): {summary['total_findings_raw']}")
        lines.append(f"- Total findings (deduplicated): {summary['total_findings_deduplicated']}")
        lines.append("")
        lines.append("### Findings by type")
        for ftype, count in sorted(summary["by_type"].items(), key=lambda kv: -kv[1]):
            lines.append(f"- `{ftype}`: {count}")
        lines.append("")
        lines.append("### Findings by agent")
        for agent, count in sorted(summary["by_agent"].items()):
            lines.append(f"- {agent}: {count}")
        lines.append("")

        lines.append("## Detailed Findings")
        findings = evidence["findings"]
        if not findings:
            lines.append("_No findings recorded._")
        else:
            grouped: dict[str, list[dict[str, Any]]] = {level: [] for level in SEVERITY_ORDER}
            for finding in findings:
                grouped[_severity_for(finding)].append(finding)

            for level in SEVERITY_ORDER:
                bucket = grouped[level]
                if not bucket:
                    continue
                lines.append(f"### {level.upper()}")
                for finding in bucket:
                    ftype = finding.get("type", "unknown")
                    seen_by = ", ".join(finding.get("seen_by", []))
                    lines.append(f"- **`{ftype}`** (seen by: {seen_by})")
                    for key, value in finding.items():
                        if key in ("type", "seen_by"):
                            continue
                        lines.append(f"  - {key}: {value}")
                lines.append("")

        lines.append("## Raw Agent Results")
        lines.append("```json")
        lines.append(json.dumps(evidence["agent_results"], indent=2))
        lines.append("```")

        return "\n".join(lines)
