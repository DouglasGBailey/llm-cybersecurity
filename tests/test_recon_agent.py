import subprocess
import textwrap
from unittest.mock import patch

import pytest

from src.agent_base import DisallowedToolError
from src.agents.recon_agent import ReconAgent
from src.scope_guard import OutOfScopeError, ScopeGuard


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


def test_out_of_scope_target_rejected_before_any_subprocess(guard):
    agent = ReconAgent(guard, dry_run=False)
    with patch("subprocess.run") as mock_run:
        with pytest.raises(OutOfScopeError):
            agent.run("8.8.8.8")
        mock_run.assert_not_called()


def test_dry_run_does_not_invoke_subprocess(guard):
    agent = ReconAgent(guard, dry_run=True)
    with patch("subprocess.run") as mock_run, patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run("127.0.0.1")
        mock_run.assert_not_called()
    assert result.status == "ok"
    assert result.target == "127.0.0.1"


def test_disallowed_tool_raises():
    class BadAgent(ReconAgent):
        allowed_tools = ["nmap"]  # dig/whois deliberately excluded here

    guard_targets = textwrap.dedent("""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        max_scan_rate: 1000
    """)

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "scope.yaml"
        p.write_text(guard_targets)
        agent = BadAgent(ScopeGuard(p), dry_run=False)
        with patch("shutil.which", return_value="/usr/bin/fake"):
            with pytest.raises(DisallowedToolError):
                agent._run_tool(["dig", "+short", "127.0.0.1"])


def test_findings_parsed_from_tool_output(guard):
    agent = ReconAgent(guard, dry_run=False)

    def fake_run(cmd, **kwargs):
        binary = cmd[0]
        if binary == "dig":
            return subprocess.CompletedProcess(cmd, 0, stdout="127.0.0.1\n", stderr="")
        if binary == "whois":
            return subprocess.CompletedProcess(cmd, 0, stdout="Registrar: Example Registrar\n", stderr="")
        if binary == "nmap":
            return subprocess.CompletedProcess(
                cmd, 0,
                stdout="80/tcp   open  http\n443/tcp  open  https\n",
                stderr="",
            )
        raise AssertionError(f"unexpected binary {binary}")

    with patch("subprocess.run", side_effect=fake_run), patch("shutil.which", return_value="/usr/bin/fake"):
        result = agent.run("127.0.0.1")

    types = {f["type"] for f in result.findings}
    assert "dns-resolution" in types
    assert "whois-registrar" in types
    open_ports = [f for f in result.findings if f["type"] == "open-port"]
    assert {p["port"] for p in open_ports} == {80, 443}


def test_missing_tool_is_recorded_as_finding_not_crash(guard):
    agent = ReconAgent(guard, dry_run=False)
    with patch("shutil.which", return_value=None):
        result = agent.run("127.0.0.1")
    assert result.status == "ok"
    assert any(f["type"] == "tool-unavailable" for f in result.findings)
