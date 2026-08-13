import json
import subprocess
import textwrap
from unittest.mock import patch

import pytest

from src.agents.code_analyzer import CodeAnalyzer
from src.scope_guard import OutOfScopeError, ScopeGuard


@pytest.fixture
def code_dir(tmp_path):
    d = tmp_path / "myproject"
    d.mkdir()
    (d / "app.py").write_text("import os\n")
    return d


@pytest.fixture
def guard(tmp_path, code_dir):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(f"""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
        max_scan_rate: 1000
        authorized_code_paths:
          - {code_dir}
    """))
    return ScopeGuard(p)


def empty_proc(cmd, **kwargs):
    return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def test_path_outside_scope_rejected_before_any_subprocess(guard, tmp_path):
    other_dir = tmp_path / "unrelated"
    other_dir.mkdir()
    agent = CodeAnalyzer(guard, dry_run=False)
    with patch("subprocess.run") as mock_run:
        with pytest.raises(OutOfScopeError):
            agent.run(str(other_dir))
        mock_run.assert_not_called()


def test_dry_run_does_not_invoke_subprocess(guard, code_dir):
    agent = CodeAnalyzer(guard, dry_run=True)
    with patch("subprocess.run") as mock_run, patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(str(code_dir))
        mock_run.assert_not_called()
    assert result.status == "ok"


def test_bandit_findings_parsed(guard, code_dir):
    agent = CodeAnalyzer(guard, dry_run=False)
    bandit_report = {
        "results": [
            {
                "filename": str(code_dir / "app.py"),
                "line_number": 1,
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
                "test_id": "B404",
                "test_name": "blacklist",
                "issue_text": "Consider possible security implications associated with the subprocess module.",
            }
        ]
    }

    def fake_run(cmd, **kwargs):
        if cmd[0] == "bandit":
            return subprocess.CompletedProcess(cmd, 1, stdout=json.dumps(bandit_report), stderr="")
        return empty_proc(cmd)

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(str(code_dir))

    bandit_findings = [f for f in result.findings if f["type"] == "bandit-finding"]
    assert bandit_findings
    assert bandit_findings[0]["test_id"] == "B404"
    assert bandit_findings[0]["severity"] == "LOW"


def test_semgrep_findings_parsed(guard, code_dir):
    agent = CodeAnalyzer(guard, dry_run=False)
    semgrep_report = {
        "results": [
            {
                "path": str(code_dir / "app.py"),
                "start": {"line": 3},
                "check_id": "python.lang.security.eval",
                "extra": {"severity": "ERROR", "message": "Detected use of eval()"},
            }
        ]
    }

    def fake_run(cmd, **kwargs):
        if cmd[0] == "semgrep":
            return subprocess.CompletedProcess(cmd, 1, stdout=json.dumps(semgrep_report), stderr="")
        return empty_proc(cmd)

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(str(code_dir))

    semgrep_findings = [f for f in result.findings if f["type"] == "semgrep-finding"]
    assert semgrep_findings
    assert semgrep_findings[0]["check_id"] == "python.lang.security.eval"


def test_no_issues_found_produces_no_findings(guard, code_dir):
    agent = CodeAnalyzer(guard, dry_run=False)

    def fake_run(cmd, **kwargs):
        if cmd[0] == "bandit":
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"results": []}), stderr="")
        return empty_proc(cmd)

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(str(code_dir))

    assert result.status == "ok"
    assert not [f for f in result.findings if f["type"] in ("bandit-finding", "semgrep-finding")]


def test_missing_tool_recorded_not_crashed(guard, code_dir):
    agent = CodeAnalyzer(guard, dry_run=False)
    with patch("shutil.which", return_value=None):
        result = agent.run(str(code_dir))
    assert result.status == "ok"
    assert any(f["type"] == "tool-unavailable" for f in result.findings)


def test_exclude_dirs_passed_to_bandit(guard, code_dir):
    agent = CodeAnalyzer(guard, dry_run=False)
    seen_cmds = []

    def fake_run(cmd, **kwargs):
        seen_cmds.append(cmd)
        return empty_proc(cmd)

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        agent.run(str(code_dir))

    bandit_cmd = next(c for c in seen_cmds if c[0] == "bandit")
    assert "venv" in bandit_cmd[bandit_cmd.index("-x") + 1]
    assert "node_modules" in bandit_cmd[bandit_cmd.index("-x") + 1]
