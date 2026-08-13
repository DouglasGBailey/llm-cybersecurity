"""Security Auditor Agent (orchestrator).

Top-level CLI dispatcher. Loads scope.yaml, resolves the requested target,
instantiates the requested agents, and runs them sequentially against that
target -- never in blind parallel, to keep request rate low and predictable
against lab infrastructure.

Defaults to --dry-run: prints the exact tool invocations each agent would
make without executing anything. Pass --execute to actually run.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from src.agent_base import AgentResult
from src.agents.ai_triage_analyzer import AiTriageAnalyzer
from src.agents.api_analyzer import ApiAnalyzer
from src.agents.code_analyzer import CodeAnalyzer
from src.agents.evidence_collector import EvidenceCollector
from src.agents.infra_analyzer import InfraAnalyzer
from src.agents.llm_security_analyzer import LlmSecurityAnalyzer
from src.agents.recon_agent import ReconAgent
from src.agents.report_generator import ReportGenerator
from src.agents.webapp_analyzer import WebAppAnalyzer
from src.diff_engine import compute_diff
from src.history_store import HistoryStore
from src.logging_setup import get_logger
from src.scope_guard import OutOfScopeError, ScopeConfigError, ScopeGuard

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
}
# Agents that take a local filesystem path (authorized via
# scope.yaml's authorized_code_paths) instead of a network target.
PATH_BASED_AGENTS = {"code"}

logger = get_logger("orchestrator")


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

    dry_run = not args.execute
    mode = "DRY-RUN (no actions executed)" if dry_run else "EXECUTE (live actions)"
    print(f"=== Security Auditor Agent ===")
    print(f"Target: {authorized_target.name} ({authorized_target.host})")
    print(f"Agents: {requested_agents}")
    print(f"Mode:   {mode}")
    print()

    results: list[AgentResult] = []
    for agent_key in requested_agents:
        agent_cls = AGENT_REGISTRY[agent_key]
        agent = agent_cls(guard, dry_run=dry_run)
        if agent_key in PATH_BASED_AGENTS:
            agent_target = args.code_path
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

    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    out_path = reports_dir / f"{authorized_target.name}-results.json"
    out_path.write_text(json.dumps([r.to_dict() for r in results], indent=2))
    print(f"Results written to {out_path}")

    evidence = EvidenceCollector().collect(results)
    evidence_path = reports_dir / f"{authorized_target.name}-evidence.json"
    evidence_path.write_text(json.dumps(evidence, indent=2))
    print(f"Evidence bundle written to {evidence_path}")

    diff = None
    if not dry_run:
        # dry-run produces no real findings, so history/diffing is skipped --
        # recording a dry-run's (empty/placeholder) findings as a "run" would
        # corrupt the history used for diffing real scans against each other.
        history = HistoryStore()
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

    report = ReportGenerator().generate(evidence, diff=diff)
    report_path = reports_dir / f"{authorized_target.name}-report.md"
    report_path.write_text(report)
    print(f"Report written to {report_path}")

    if args.ai_triage:
        triage_agent = AiTriageAnalyzer(guard, dry_run=dry_run)
        logger.info("Running ai-triage-analyzer over evidence bundle")
        triage_result = triage_agent.run(evidence)
        narrative = next(
            (f["narrative"] for f in triage_result.findings if f["type"] == "ai-triage-narrative"),
            None,
        )
        if narrative:
            triage_path = reports_dir / f"{authorized_target.name}-ai-triage.md"
            triage_path.write_text(
                "<!-- AI-GENERATED: this narrative was produced by Claude reading the "
                "evidence bundle below. Verify against the deterministic report.md before "
                "acting on it. -->\n\n# AI Triage Narrative\n\n" + narrative + "\n"
            )
            print(f"AI triage narrative written to {triage_path}")
        else:
            print(f"AI triage did not produce a narrative: {triage_result.findings}")

    if diff is not None and diff["has_new_findings"]:
        return EXIT_NEW_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
