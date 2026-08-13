"""Evidence Collector: aggregates an orchestrator run's AgentResult list
into a single normalized evidence bundle for ReportGenerator.

Not a scanning agent -- no network/tool access, no scope checks (the
individual agents already enforced scope before producing these results).
Deduplicates findings that are identical across agents (e.g. two agents
independently noting the same fact) by content, tracking which agent(s)
observed each one.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from src.agent_base import AgentResult


class EvidenceCollector:
    def collect(self, results: list[AgentResult]) -> dict[str, Any]:
        findings_index: dict[str, dict[str, Any]] = {}
        by_type: dict[str, int] = defaultdict(int)
        by_agent: dict[str, int] = defaultdict(int)

        for result in results:
            by_agent[result.agent_name] += len(result.findings)
            for finding in result.findings:
                by_type[finding.get("type", "unknown")] += 1
                key = json.dumps(finding, sort_keys=True, default=str)
                if key not in findings_index:
                    findings_index[key] = {**finding, "seen_by": []}
                if result.agent_name not in findings_index[key]["seen_by"]:
                    findings_index[key]["seen_by"].append(result.agent_name)

        deduplicated_findings = list(findings_index.values())

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "targets": sorted({r.target for r in results}),
            "agents_run": [r.agent_name for r in results],
            "summary": {
                "total_findings_raw": sum(len(r.findings) for r in results),
                "total_findings_deduplicated": len(deduplicated_findings),
                "by_type": dict(by_type),
                "by_agent": dict(by_agent),
            },
            "findings": deduplicated_findings,
            "agent_results": [r.to_dict() for r in results],
        }
