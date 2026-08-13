"""Generates a static, self-contained HTML dashboard from HistoryStore data.

Not a live server -- no new web framework dependency, consistent with the
platform's "no scheduler daemon" precedent (see scripts/run-scheduled-scan.sh).
Regenerate by re-running `python -m src.dashboard --scope config/scope.yaml`.

For each authorized network target in scope.yaml: a finding-count trend
over recent runs (inline SVG polyline, no chart library), the latest run's
severity breakdown, the latest diff (new/resolved counts, if a diff.json
exists for that target), and compliance coverage from the latest run's
findings. Targets with no run history yet show "no runs" instead of an
empty chart.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.agents.report_generator import SEVERITY_ORDER, severity_for
from src.history_store import DEFAULT_DB_PATH, HistoryStore
from src.scope_guard import ScopeGuard

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS_DIR = ROOT / "reports"
DEFAULT_OUT_PATH = DEFAULT_REPORTS_DIR / "dashboard.html"

SEVERITY_COLOR = {"high": "#f38ba8", "medium": "#f9e2af", "low": "#89b4fa", "info": "#6c7086"}

SPARKLINE_WIDTH = 260
SPARKLINE_HEIGHT = 56
SPARKLINE_PAD = 6


def _sparkline_svg(counts: list[int]) -> str:
    if not counts:
        return ""
    if len(counts) == 1:
        counts = [counts[0], counts[0]]
    max_count = max(counts) or 1
    n = len(counts)
    usable_w = SPARKLINE_WIDTH - 2 * SPARKLINE_PAD
    usable_h = SPARKLINE_HEIGHT - 2 * SPARKLINE_PAD
    points = []
    for i, c in enumerate(counts):
        x = SPARKLINE_PAD + (usable_w * i / (n - 1))
        y = SPARKLINE_PAD + usable_h - (usable_h * c / max_count)
        points.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(points)
    last_x, last_y = points[-1].split(",")
    return (
        f'<svg width="{SPARKLINE_WIDTH}" height="{SPARKLINE_HEIGHT}" '
        f'viewBox="0 0 {SPARKLINE_WIDTH} {SPARKLINE_HEIGHT}" class="sparkline">'
        f'<polyline points="{polyline}" fill="none" stroke="#cba6f7" stroke-width="2" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
        f'<circle cx="{last_x}" cy="{last_y}" r="3.5" fill="#cba6f7"/>'
        f"</svg>"
    )


def _severity_breakdown(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[severity_for(finding)] += 1
    return counts


def _compliance_breakdown(findings: list[dict[str, Any]], top_n: int = 5) -> list[tuple[str, str, int]]:
    counts: dict[tuple[str, str], int] = {}
    for finding in findings:
        for tag in finding.get("compliance") or []:
            key = (tag["framework"], tag["control"])
            counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])[:top_n]
    return [(framework, control, count) for (framework, control), count in ranked]


def _load_latest_diff(reports_dir: Path, target_name: str) -> dict[str, Any] | None:
    diff_path = reports_dir / f"{target_name}-diff.json"
    if not diff_path.exists():
        return None
    return json.loads(diff_path.read_text())


def _render_target_card(target_name: str, history: list[dict[str, Any]], reports_dir: Path) -> str:
    report_link = f"{target_name}-report.md"
    has_report = (reports_dir / report_link).exists()

    if not history:
        return f"""
        <section class="card">
          <h2>{target_name}</h2>
          <p class="muted">No runs yet.</p>
        </section>
        """

    ordered = list(reversed(history))  # oldest -> newest, for left-to-right chart
    counts = [len(run["findings"]) for run in ordered]
    latest_findings = ordered[-1]["findings"]
    latest_timestamp = ordered[-1]["timestamp"]
    severity = _severity_breakdown(latest_findings)
    compliance = _compliance_breakdown(latest_findings)
    diff = _load_latest_diff(reports_dir, target_name)

    severity_html = "".join(
        f'<span class="pill" style="border-color:{SEVERITY_COLOR[level]};color:{SEVERITY_COLOR[level]}">'
        f"{level}: {count}</span>"
        for level, count in severity.items() if count
    ) or '<span class="muted">no findings</span>'

    if diff is None:
        diff_html = '<p class="muted">No diff recorded yet.</p>'
    elif diff.get("is_first_run"):
        diff_html = '<p class="muted">Baseline run — nothing to compare yet.</p>'
    else:
        diff_html = (
            f'<p><span class="stat new">{len(diff["new_findings"])} new</span> · '
            f'<span class="stat resolved">{len(diff["resolved_findings"])} resolved</span> · '
            f'<span class="stat unchanged">{len(diff["unchanged_findings"])} unchanged</span></p>'
        )

    compliance_html = "".join(
        f"<li>{framework} — {control}: {count}</li>" for framework, control, count in compliance
    ) or '<li class="muted">No mapped findings</li>'

    report_html = f'<a href="{report_link}">View full report →</a>' if has_report else ""

    return f"""
    <section class="card">
      <h2>{target_name}</h2>
      <p class="muted">Last run: {latest_timestamp} · {len(history)} run(s) recorded</p>
      {_sparkline_svg(counts)}
      <div class="pills">{severity_html}</div>
      <h3>Changes</h3>
      {diff_html}
      <h3>Compliance Coverage</h3>
      <ul class="compliance-list">{compliance_html}</ul>
      {report_html}
    </section>
    """


def generate_dashboard(
    scope_path: str | Path,
    history_db_path: str | Path = DEFAULT_DB_PATH,
    reports_dir: str | Path = DEFAULT_REPORTS_DIR,
) -> str:
    reports_dir = Path(reports_dir)
    guard = ScopeGuard(scope_path)
    history_store = HistoryStore(db_path=history_db_path)

    cards = "".join(
        _render_target_card(
            target.name, history_store.get_run_history(target.name, limit=30), reports_dir
        )
        for target in guard.scope.authorized_targets
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Scan Dashboard</title>
<style>
  :root {{
    --bg: #1e1e2e; --surface: #262637; --text: #cdd6f4; --dim: #6c7086;
    --accent: #cba6f7; --border: #3a3a52;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); margin: 0; padding: 32px;
    font-family: ui-monospace, "DejaVu Sans Mono", Menlo, Consolas, monospace;
  }}
  h1 {{ font-size: 1.6rem; margin: 0 0 4px; }}
  .subtitle {{ color: var(--dim); margin: 0 0 28px; }}
  .grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 20px;
  }}
  .card {{
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 20px;
  }}
  .card h2 {{ margin: 0 0 4px; font-size: 1.1rem; color: var(--accent); }}
  .card h3 {{ margin: 16px 0 6px; font-size: 0.85rem; color: var(--dim); text-transform: uppercase; letter-spacing: 0.04em; }}
  .muted {{ color: var(--dim); }}
  .sparkline {{ display: block; margin: 8px 0; }}
  .pills {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .pill {{
    border: 1px solid; border-radius: 999px; padding: 2px 10px; font-size: 0.8rem;
  }}
  .stat.new {{ color: #f38ba8; }}
  .stat.resolved {{ color: #a6e3a1; }}
  .stat.unchanged {{ color: var(--dim); }}
  .compliance-list {{ margin: 0; padding-left: 18px; font-size: 0.85rem; color: var(--text); }}
  .compliance-list li.muted {{ list-style: none; margin-left: -18px; }}
  a {{ color: var(--accent); text-decoration: none; font-size: 0.85rem; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
  <h1>Security Scan Dashboard</h1>
  <p class="subtitle">LLM Cybersecurity Agent Platform — generated from data/history.db</p>
  <div class="grid">
    {cards}
  </div>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dashboard", description="Generate a static HTML dashboard from scan history.")
    parser.add_argument("--scope", required=True, help="Path to scope.yaml")
    parser.add_argument("--history-db", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR))
    parser.add_argument("--out", default=str(DEFAULT_OUT_PATH))
    args = parser.parse_args(argv)

    html = generate_dashboard(args.scope, history_db_path=args.history_db, reports_dir=args.reports_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    print(f"Dashboard written to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
