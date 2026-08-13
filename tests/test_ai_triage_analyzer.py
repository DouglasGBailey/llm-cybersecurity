import subprocess
import textwrap
from unittest.mock import patch

import pytest

from src.agents.ai_triage_analyzer import AiTriageAnalyzer
from src.scope_guard import ScopeGuard


@pytest.fixture
def guard(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
        max_scan_rate: 1000
    """))
    return ScopeGuard(p)


@pytest.fixture
def evidence():
    return {
        "targets": ["127.0.0.1"],
        "agents_run": ["webapp-analyzer"],
        "summary": {"total_findings_raw": 1, "total_findings_deduplicated": 1},
        "findings": [{"type": "missing-security-headers", "headers": ["CSP"]}],
    }


def test_dry_run_does_not_invoke_claude(guard, evidence):
    agent = AiTriageAnalyzer(guard, dry_run=True)
    with patch("subprocess.run") as mock_run:
        result = agent.run(evidence)
        mock_run.assert_not_called()
    assert result.status == "ok"
    assert [f for f in result.findings if f["type"] == "ai-triage-skipped"]


def test_narrative_returned_on_success(guard, evidence):
    agent = AiTriageAnalyzer(guard, dry_run=False)
    fake_narrative = "## Top priorities\n- Fix missing CSP header"

    def fake_run(cmd, **kwargs):
        assert cmd[0] == "claude"
        assert "-p" in cmd
        return subprocess.CompletedProcess(cmd, 0, stdout=fake_narrative, stderr="")

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(evidence)

    assert result.status == "ok"
    narratives = [f for f in result.findings if f["type"] == "ai-triage-narrative"]
    assert narratives and narratives[0]["narrative"] == fake_narrative


def test_missing_claude_binary_recorded_not_crashed(guard, evidence):
    agent = AiTriageAnalyzer(guard, dry_run=False)
    with patch("shutil.which", return_value=None):
        result = agent.run(evidence)
    assert result.status == "ok"
    assert [f for f in result.findings if f["type"] == "tool-unavailable"]


def test_nonzero_exit_recorded_as_error(guard, evidence):
    agent = AiTriageAnalyzer(guard, dry_run=False)

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="API error: rate limited")

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run(evidence)

    assert result.status == "error"
    assert "rate limited" in result.error


def test_prompt_includes_findings_and_evidence(guard, evidence):
    agent = AiTriageAnalyzer(guard, dry_run=False)
    seen_prompts = []

    def fake_run(cmd, **kwargs):
        seen_prompts.append(cmd[cmd.index("-p") + 1])
        return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        agent.run(evidence)

    assert "missing-security-headers" in seen_prompts[0]
    assert "Top priorities" in seen_prompts[0]
