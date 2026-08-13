import textwrap

import pytest

from src.orchestrator import run_scan
from src.scope_guard import ScopeGuard


def make_guard(tmp_path) -> ScopeGuard:
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
        max_scan_rate: 1000
    """))
    return ScopeGuard(p)


def test_run_scan_rejects_code_agent_without_code_path(tmp_path):
    guard = make_guard(tmp_path)
    target = guard.resolve_target("local")
    with pytest.raises(ValueError, match="code_path"):
        run_scan(guard, target, ["code"], reports_dir=tmp_path / "reports")


def test_run_scan_rejects_exploit_agent_without_exploit_target(tmp_path):
    guard = make_guard(tmp_path)
    target = guard.resolve_target("local")
    with pytest.raises(ValueError, match="exploit_target"):
        run_scan(guard, target, ["exploit"], reports_dir=tmp_path / "reports")


def test_run_scan_with_no_agents_succeeds(tmp_path):
    guard = make_guard(tmp_path)
    target = guard.resolve_target("local")
    result = run_scan(guard, target, [], reports_dir=tmp_path / "reports")
    assert result["exit_code"] == 0
    assert result["results"] == []
