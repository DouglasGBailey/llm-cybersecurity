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
    def generate(self, evidence: dict[str, Any], diff: dict[str, Any] | None = None) -> str:
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

        lines.extend(self._render_compliance_coverage(evidence["findings"]))

        if diff is not None and not diff.get("is_first_run"):
            lines.extend(self._render_diff_section(diff))

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
                    header = f"- **`{ftype}`** (seen by: {seen_by})"
                    tags = finding.get("compliance") or []
                    if tags:
                        header += " " + " ".join(f"[{t['framework']}: {t['control']}]" for t in tags)
                    lines.append(header)
                    for key, value in finding.items():
                        if key in ("type", "seen_by", "compliance"):
                            continue
                        lines.append(f"  - {key}: {value}")
                lines.append("")

        lines.append("## Raw Agent Results")
        lines.append("```json")
        lines.append(json.dumps(evidence["agent_results"], indent=2))
        lines.append("```")

        return "\n".join(lines)

    @staticmethod
    def _render_diff_section(diff: dict[str, Any]) -> list[str]:
        lines: list[str] = ["## Changes Since Last Scan"]
        new_findings = diff.get("new_findings", [])
        resolved_findings = diff.get("resolved_findings", [])
        unchanged_count = len(diff.get("unchanged_findings", []))

        if not new_findings and not resolved_findings:
            lines.append(f"_No changes — {unchanged_count} finding(s) unchanged since the last scan._")
            lines.append("")
            return lines

        if new_findings:
            lines.append(f"### New ({len(new_findings)})")
            for finding in new_findings:
                ftype = finding.get("type", "unknown")
                detail = ", ".join(
                    f"{k}={v}" for k, v in finding.items() if k not in ("type", "seen_by", "compliance")
                )
                lines.append(f"- **`{ftype}`**" + (f" — {detail}" if detail else ""))
            lines.append("")

        if resolved_findings:
            lines.append(f"### Resolved ({len(resolved_findings)})")
            for finding in resolved_findings:
                ftype = finding.get("type", "unknown")
                detail = ", ".join(
                    f"{k}={v}" for k, v in finding.items() if k not in ("type", "seen_by", "compliance")
                )
                lines.append(f"- **`{ftype}`**" + (f" — {detail}" if detail else ""))
            lines.append("")

        lines.append(f"_{unchanged_count} finding(s) unchanged._")
        lines.append("")
        return lines

    @staticmethod
    def _render_compliance_coverage(findings: list[dict[str, Any]]) -> list[str]:
        counts: dict[tuple[str, str], int] = {}
        for finding in findings:
            for tag in finding.get("compliance") or []:
                key = (tag["framework"], tag["control"])
                counts[key] = counts.get(key, 0) + 1

        lines = ["### Compliance Coverage"]
        if not counts:
            lines.append("_No findings map to a tracked compliance control._")
            lines.append("")
            return lines

        for (framework, control), count in sorted(counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"- **{framework}** — {control}: {count} finding(s)")
        lines.append("")
        return lines
