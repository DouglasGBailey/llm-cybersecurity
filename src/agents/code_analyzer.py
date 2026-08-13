"""Code Analyzer: static analysis of local source code the user owns.

Scope: static-only, non-destructive scanning of a local filesystem path via
`bandit` (Python SAST, required) and `semgrep` (multi-language SAST,
optional -- degrades gracefully if not installed, same pattern as nmap in
ReconAgent). No network target, no code execution -- this agent never
accepts a hostname/IP.

Authorization is path-based, not IP-based: `target` here is a local
directory, checked against `scope.yaml`'s `authorized_code_paths` via
`ScopeGuard.authorize_path()` -- a different scope list than the network
`authorized_targets`, since "I own this codebase" and "I'm allowed to
scan this network host" are different claims.

`semgrep --config=auto` fetches public community rules from semgrep's
registry over the network -- that's a request for rule *definitions*, not
a probe of the target, analogous to `pip install`. If that's undesirable
in an offline environment, pass a local ruleset via SEMGREP_CONFIG or skip
semgrep entirely (it's optional).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from src.agent_base import AgentResult, BaseAgent
from src.logging_setup import log_with_fields

# Never descend into these -- neither our own nor third-party dependency
# code is what a "review my code" request means.
EXCLUDE_DIRS = ["venv", ".venv", "node_modules", ".git", "__pycache__", ".pytest_cache"]


class CodeAnalyzer(BaseAgent):
    name = "code-analyzer"
    allowed_tools = ["bandit", "semgrep"]
    default_timeout_seconds = 180

    def run(self, target: str) -> AgentResult:
        self.scope_guard.authorize_path(target)
        path = str(Path(target).resolve())
        result = AgentResult(
            agent_name=self.name, target=path, timestamp=self._now(), status="ok"
        )

        for step in (self._run_bandit, self._run_semgrep):
            try:
                step(path, result)
            except FileNotFoundError as e:
                log_with_fields(self.logger, logging.WARNING, str(e), target=path)
                result.findings.append({"type": "tool-unavailable", "detail": str(e)})
            except Exception as e:  # noqa: BLE001 - surface any tool failure as a finding
                log_with_fields(self.logger, logging.ERROR, str(e), target=path)
                result.findings.append({"type": "error", "step": step.__name__, "detail": str(e)})

        return result

    def _run_bandit(self, path: str, result: AgentResult) -> None:
        proc = self._run_tool([
            "bandit", "-r", path, "-f", "json", "-q",
            "-x", ",".join(EXCLUDE_DIRS),
        ])
        stdout = proc.stdout.strip()
        if not stdout:
            return
        try:
            report = json.loads(stdout)
        except ValueError:
            result.raw_output.append(f"bandit: non-JSON output: {stdout[:500]}")
            return

        result.raw_output.append(f"bandit: {len(report.get('results', []))} issue(s) found")
        for issue in report.get("results", []):
            result.findings.append({
                "type": "bandit-finding",
                "file": issue.get("filename"),
                "line": issue.get("line_number"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "test_id": issue.get("test_id"),
                "test_name": issue.get("test_name"),
                "description": issue.get("issue_text"),
            })

    def _run_semgrep(self, path: str, result: AgentResult) -> None:
        proc = self._run_tool(["semgrep", "--config=auto", "--json", "--quiet", path])
        stdout = proc.stdout.strip()
        if not stdout:
            return
        try:
            report = json.loads(stdout)
        except ValueError:
            result.raw_output.append(f"semgrep: non-JSON output: {stdout[:500]}")
            return

        findings = report.get("results", [])
        result.raw_output.append(f"semgrep: {len(findings)} issue(s) found")
        for issue in findings:
            start = issue.get("start", {})
            extra = issue.get("extra", {})
            result.findings.append({
                "type": "semgrep-finding",
                "file": issue.get("path"),
                "line": start.get("line"),
                "severity": extra.get("severity"),
                "check_id": issue.get("check_id"),
                "description": extra.get("message"),
            })
