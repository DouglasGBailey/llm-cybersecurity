import textwrap
from unittest.mock import patch

import pytest

from src.orchestrator import run_scan
from src.scope_guard import ExploitTarget, K8sCluster, ScopeGuard


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


def test_run_scan_rejects_k8s_agent_without_k8s_cluster(tmp_path):
    guard = make_guard(tmp_path)
    target = guard.resolve_target("local")
    with pytest.raises(ValueError, match="k8s_cluster"):
        run_scan(guard, target, ["k8s"], reports_dir=tmp_path / "reports")


def test_run_scan_with_no_agents_succeeds(tmp_path):
    guard = make_guard(tmp_path)
    target = guard.resolve_target("local")
    result = run_scan(guard, target, [], reports_dir=tmp_path / "reports")
    assert result["exit_code"] == 0
    assert result["results"] == []


def test_run_scan_k8s_agent_uses_context_string_as_target(tmp_path):
    """k8s_cluster.context (a plain string, never a dataclass) is what
    reaches the agent -- avoids the whole class of leak/serialization bugs
    ExploitTarget had, since there's nothing sensitive to redact."""
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("""
        authorized_targets:
          - name: local
            host: 127.0.0.1
        excluded: []
        max_scan_rate: 1000
        authorized_k8s_clusters:
          - name: local
            context: kind-lab
    """))
    guard = ScopeGuard(p)
    target = guard.resolve_target("local")
    k8s_cluster = K8sCluster(name="local", context="kind-lab")

    with patch("shutil.which", return_value=None):  # kubectl "not installed" -- degrades gracefully
        result = run_scan(
            guard, target, ["k8s"], k8s_cluster=k8s_cluster,
            reports_dir=tmp_path / "reports",
        )

    assert result["results"][0].status == "ok"
    assert result["results"][0].target == "kind-lab"


def make_exploit_target() -> ExploitTarget:
    return ExploitTarget(
        name="local", host="127.0.0.1", resettable=True,
        known_vulnerabilities={
            "auth_setup": {
                "login_path": "/login.php", "username_field": "u", "password_field": "p",
                "username": "admin", "password": "super-secret-pw",
            },
        },
    )


def test_run_scan_never_logs_exploit_target_credentials(tmp_path):
    """Regression: the per-agent 'Running <agent> against <target>' log
    line must never log an ExploitTarget's repr, since that embeds
    plaintext auth_setup/credentials passwords from known_vulnerabilities."""
    guard = make_guard(tmp_path)
    target = guard.resolve_target("local")
    exploit_target = make_exploit_target()

    with patch("src.orchestrator.logger") as mock_logger:
        run_scan(
            guard, target, ["exploit"], exploit_target=exploit_target,
            reports_dir=tmp_path / "reports",
        )

    logged_text = " ".join(str(call) for call in mock_logger.info.call_args_list)
    assert "super-secret-pw" not in logged_text
    assert "local" in logged_text
    assert "127.0.0.1" in logged_text


def test_run_scan_handles_exploit_agent_exception_without_crashing(tmp_path):
    """Regression: if ExploitAgent.run() raises before returning (e.g. the
    exploit target isn't separately authorized), the except-branch
    AgentResult.target must be JSON-serializable -- not the raw
    ExploitTarget dataclass, which crashes json.dumps() when results.json
    is written and would also leak credentials via that same object."""
    guard = make_guard(tmp_path)  # no authorized_exploit_targets entry
    target = guard.resolve_target("local")
    exploit_target = make_exploit_target()

    result = run_scan(
        guard, target, ["exploit"], exploit_target=exploit_target,
        reports_dir=tmp_path / "reports",
    )

    assert result["results"][0].status == "error"
    assert isinstance(result["results"][0].target, str)
    assert "super-secret-pw" not in result["results"][0].target
