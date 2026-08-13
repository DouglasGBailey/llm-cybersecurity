"""Security Auditor Agent (orchestrator).

Top-level CLI dispatcher. Loads scope.yaml, resolves the requested target,
instantiates the requested agents, and runs them sequentially against that
target -- never in blind parallel, to keep request rate low and predictable
against lab infrastructure.

Defaults to --dry-run: prints the exact tool invocations each agent would
make without executing anything. Pass --execute to actually run.

`run_scan()` holds the actual scan logic (agent loop, evidence/report/diff/
alert generation) as a reusable function -- `main()` is a thin CLI shell
around it, and `src/api.py` calls it directly for the REST API, so there's
exactly one place this logic lives.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from src.agent_base import AgentResult
from src.agents.ai_triage_analyzer import AiTriageAnalyzer
from src.agents.api_analyzer import ApiAnalyzer
from src.agents.code_analyzer import CodeAnalyzer
from src.agents.evidence_collector import EvidenceCollector
from src.agents.exploit_agent import ExploitAgent
from src.agents.infra_analyzer import InfraAnalyzer
from src.agents.llm_security_analyzer import LlmSecurityAnalyzer
from src.agents.recon_agent import ReconAgent
from src.agents.report_generator import ReportGenerator
from src.agents.webapp_analyzer import WebAppAnalyzer
from src.alerting import send_alerts
from src.diff_engine import compute_diff
from src.history_store import DEFAULT_DB_PATH, HistoryStore
from src.logging_setup import get_logger
from src.scope_guard import AuthorizedTarget, ExploitTarget, OutOfScopeError, ScopeConfigError, ScopeGuard

# Exit codes: 0 = success/no new findings, 1 = scope/config/argument error,
# 3 = success but new findings appeared since the last run for this target
# (the hook cron/systemd/CI use to alert -- see scripts/run-scheduled-scan.sh).
EXIT_OK = 0
EXIT_CONFIG_ERROR = 1
EXIT_NEW_FINDINGS = 3

AGENT_REGISTRY = {
    "recon": ReconAgent,
    "webapp": WebAppAnalyzer,
    "api": ApiAnalyzer,
    "infra": InfraAnalyzer,
    "code": CodeAnalyzer,
    "llm": LlmSecurityAnalyzer,
    "exploit": ExploitAgent,
}
# Agents that take a local filesystem path (authorized via
# scope.yaml's authorized_code_paths) instead of a network target.
PATH_BASED_AGENTS = {"code"}
# Agents that require a *separate* authorized_exploit_targets entry
# (with resettable: true) -- recon authorization does not imply
# exploitation is authorized. See src/scope_guard.py.
EXPLOIT_AGENTS = {"exploit"}

DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

logger = get_logger("orchestrator")


def run_scan(
    guard: ScopeGuard,
    authorized_target: AuthorizedTarget,
    agent_keys: list[str],
    code_path: str | None = None,
    exploit_target: ExploitTarget | None = None,
    execute: bool = False,
    ai_triage: bool = False,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    history_db_path: str | Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    """Run the requested agents against authorized_target and produce all
    the usual output files. Used by both main() (CLI) and src/api.py."""
    reports_dir = Path(reports_dir)
    dry_run = not execute
    mode = "DRY-RUN (no actions executed)" if dry_run else "EXECUTE (live actions)"
    print("=== Security Auditor Agent ===")
    print(f"Target: {authorized_target.name} ({authorized_target.host})")
    print(f"Agents: {agent_keys}")
    print(f"Mode:   {mode}")
    print()

    results: list[AgentResult] = []
    for agent_key in agent_keys:
        agent_cls = AGENT_REGISTRY[agent_key]
        agent = agent_cls(guard, dry_run=dry_run)
        if agent_key in PATH_BASED_AGENTS:
            agent_target = code_path
        elif agent_key in EXPLOIT_AGENTS:
            agent_target = exploit_target
        else:
            agent_target = authorized_target.host
            if agent_key in ("webapp", "api", "llm") and authorized_target.web_port:
                agent_target = f"{authorized_target.host}:{authorized_target.web_port}"
            elif agent_key == "infra" and authorized_target.tls_port:
                agent_target = f"{authorized_target.host}:{authorized_target.tls_port}"
        logger.info(f"Running {agent.name} against {agent_target}")
        try:
            result = agent.run(agent_target)
        except Exception as e:  # noqa: BLE001 - one agent's failure shouldn't kill the run
            logger.error(f"{agent.name} failed: {e}")
            result = AgentResult(
                agent_name=agent.name, target=agent_target,
                timestamp=agent._now(), status="error", error=str(e),
            )
        results.append(result)
        print(f"--- {agent.name} ---")
        print(f"status: {result.status}")
        for finding in result.findings:
            print(f"  finding: {finding}")
        print()

    reports_dir.mkdir(exist_ok=True, parents=True)
    results_path = reports_dir / f"{authorized_target.name}-results.json"
    results_path.write_text(json.dumps([r.to_dict() for r in results], indent=2))
    print(f"Results written to {results_path}")

    evidence = EvidenceCollector().collect(results)
    evidence_path = reports_dir / f"{authorized_target.name}-evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2))
    print(f"Evidence bundle written to {evidence_path}")

    diff = None
    diff_path = None
    alerted_channels: list[str] = []
    if not dry_run:
        # dry-run produces no real findings, so history/diffing is skipped --
        # recording a dry-run's (empty/placeholder) findings as a "run" would
        # corrupt the history used for diffing real scans against each other.
        history = HistoryStore(db_path=history_db_path)
        previous_run = history.get_previous_run(authorized_target.name)
        diff = compute_diff(
            previous_findings=previous_run["findings"] if previous_run else [],
            current_findings=evidence["findings"],
            is_first_run=previous_run is None,
        )
        history.save_run(authorized_target.name, evidence["generated_at"], evidence["findings"])

        diff_path = reports_dir / f"{authorized_target.name}-diff.json"
        diff_path.write_text(json.dumps(diff, indent=2))
        print(f"Diff written to {diff_path}")
        if diff["is_first_run"]:
            print("  first run for this target -- no prior history to compare against")
        else:
            print(f"  {len(diff['new_findings'])} new, {len(diff['resolved_findings'])} resolved, "
                  f"{len(diff['unchanged_findings'])} unchanged since last run")

        alerted_channels = send_alerts(authorized_target.name, diff)
        if alerted_channels:
            print(f"  alert sent via: {', '.join(alerted_channels)}")

    report = ReportGenerator().generate(evidence, diff=diff)
    report_path = reports_dir / f"{authorized_target.name}-report.md"
    report_path.write_text(report)
    print(f"Report written to {report_path}")

    ai_triage_narrative = None
    ai_triage_path = None
    if ai_triage:
        triage_agent = AiTriageAnalyzer(guard, dry_run=dry_run)
        logger.info("Running ai-triage-analyzer over evidence bundle")
        triage_result = triage_agent.run(evidence)
        ai_triage_narrative = next(
            (f["narrative"] for f in triage_result.findings if f["type"] == "ai-triage-narrative"),
            None,
        )
        if ai_triage_narrative:
            ai_triage_path = reports_dir / f"{authorized_target.name}-ai-triage.md"
            ai_triage_path.write_text(
                "<!-- AI-GENERATED: this narrative was produced by Claude reading the "
                "evidence bundle below. Verify against the deterministic report.md before "
                "acting on it. -->\n\n# AI Triage Narrative\n\n" + ai_triage_narrative + "\n"
            )
            print(f"AI triage narrative written to {ai_triage_path}")
        else:
            print(f"AI triage did not produce a narrative: {triage_result.findings}")

    exit_code = EXIT_NEW_FINDINGS if (diff is not None and diff["has_new_findings"]) else EXIT_OK

    return {
        "exit_code": exit_code,
        "results": results,
        "evidence": evidence,
        "diff": diff,
        "report": report,
        "ai_triage_narrative": ai_triage_narrative,
        "alerted_channels": alerted_channels,
        "paths": {
            "results": results_path,
            "evidence": evidence_path,
            "report": report_path,
            "diff": diff_path,
            "ai_triage": ai_triage_path,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description="Controlled, scope-gated security assessment orchestrator. "
        "Runs read-only, non-exploitative agents against explicitly "
        "authorized lab targets only.",
    )
    parser.add_argument(
        "--scope", required=True, help="Path to scope.yaml (see config/scope.example.yaml)"
    )
    parser.add_argument(
        "--target", required=True,
        help="Named target from scope.yaml's authorized_targets (the `name` field)",
    )
    parser.add_argument(
        "--agents", default="recon,webapp",
        help=f"Comma-separated agent list. Available: {', '.join(AGENT_REGISTRY)}",
    )
    parser.add_argument(
        "--code-path",
        help="Local directory to scan (required if 'code' is in --agents). "
        "Must be under an authorized_code_paths entry in scope.yaml.",
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Actually run tools/requests. Without this flag, runs in --dry-run "
        "mode and only prints planned actions.",
    )
    parser.add_argument(
        "--ai-triage", action="store_true",
        help="After the report is generated, invoke the `claude` CLI to produce "
        "a prioritized triage narrative from the evidence bundle. Opt-in: sends "
        "evidence data to Anthropic's API and consumes your Claude usage. "
        "Written to reports/<target>-ai-triage.md, clearly labeled as AI-generated.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        guard = ScopeGuard(args.scope)
    except ScopeConfigError as e:
        print(f"Scope configuration error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    try:
        authorized_target = guard.resolve_target(args.target)
    except OutOfScopeError as e:
        print(f"Target error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    requested_agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    unknown = [a for a in requested_agents if a not in AGENT_REGISTRY]
    if unknown:
        print(f"Unknown agent(s): {unknown}. Available: {list(AGENT_REGISTRY)}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    if "code" in requested_agents and not args.code_path:
        print("--code-path is required when 'code' is in --agents", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    exploit_target = None
    if EXPLOIT_AGENTS & set(requested_agents):
        try:
            exploit_target = guard.resolve_exploit_target(args.target)
        except OutOfScopeError as e:
            print(f"Exploit target error: {e}", file=sys.stderr)
            return EXIT_CONFIG_ERROR

    result = run_scan(
        guard, authorized_target, requested_agents,
        code_path=args.code_path, exploit_target=exploit_target,
        execute=args.execute, ai_triage=args.ai_triage,
    )
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
