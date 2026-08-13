"""Pure diffing of two finding lists (previous run vs. current run).

Uses the same content-based identity approach EvidenceCollector already
uses for dedup (json.dumps(finding, sort_keys=True)), minus derived
metadata fields (`seen_by`, `compliance`) that aren't part of a finding's
identity across runs -- which agent observed it, and what compliance tags
it currently carries, can both change without the underlying finding being
a different finding (e.g. a second agent later corroborating it, or the
compliance mapping being edited).
"""
from __future__ import annotations

import json
from typing import Any

_DERIVED_FIELDS = ("seen_by", "compliance")


def _finding_signature(finding: dict[str, Any]) -> str:
    core = {k: v for k, v in finding.items() if k not in _DERIVED_FIELDS}
    return json.dumps(core, sort_keys=True, default=str)


def compute_diff(
    previous_findings: list[dict[str, Any]],
    current_findings: list[dict[str, Any]],
    is_first_run: bool,
) -> dict[str, Any]:
    prev_by_sig = {_finding_signature(f): f for f in previous_findings}
    curr_by_sig = {_finding_signature(f): f for f in current_findings}

    new_findings = [f for sig, f in curr_by_sig.items() if sig not in prev_by_sig]
    resolved_findings = [f for sig, f in prev_by_sig.items() if sig not in curr_by_sig]
    unchanged_findings = [f for sig, f in curr_by_sig.items() if sig in prev_by_sig]

    return {
        "is_first_run": is_first_run,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "unchanged_findings": unchanged_findings,
        # No alert on the initial baseline -- everything is technically
        # "new" on a first run, but there's nothing to compare against yet.
        "has_new_findings": bool(new_findings) and not is_first_run,
    }
