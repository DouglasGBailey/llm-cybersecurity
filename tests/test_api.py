import textwrap

import pytest
from fastapi.testclient import TestClient

from src.api import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def scratch_env(tmp_path, monkeypatch):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(textwrap.dedent("""
        authorized_targets:
          - name: test-target
            host: 127.0.0.1
            notes: "scratch test target"
        excluded: []
        max_scan_rate: 1000
    """))
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    history_db = tmp_path / "history.db"

    monkeypatch.setenv("SCOPE_PATH", str(scope_path))
    monkeypatch.setenv("REPORTS_DIR", str(reports_dir))
    monkeypatch.setenv("HISTORY_DB_PATH", str(history_db))
    monkeypatch.delenv("API_KEY", raising=False)

    return {"scope_path": scope_path, "reports_dir": reports_dir, "history_db": history_db}


def test_health_needs_no_setup():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_list_targets_returns_scratch_scope():
    resp = client.get("/targets")
    assert resp.status_code == 200
    targets = resp.json()
    assert len(targets) == 1
    assert targets[0]["name"] == "test-target"
    assert targets[0]["host"] == "127.0.0.1"


def test_create_scan_with_no_agents_writes_files_and_returns_summary():
    resp = client.post("/scans", json={"target": "test-target", "agents": [], "execute": True})
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"] == "test-target"
    assert body["exit_code"] == 0
    assert body["new_findings_count"] == 0
    assert body["report_url"] == "/scans/test-target/report"
    assert body["diff_url"] == "/scans/test-target/diff"


def test_create_scan_dry_run_has_no_diff_url():
    resp = client.post("/scans", json={"target": "test-target", "agents": [], "execute": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["diff_url"] is None
    assert body["new_findings_count"] is None


def test_create_scan_unknown_target_returns_404():
    resp = client.post("/scans", json={"target": "does-not-exist", "agents": []})
    assert resp.status_code == 404


def test_create_scan_unknown_agent_returns_400():
    resp = client.post("/scans", json={"target": "test-target", "agents": ["not-a-real-agent"]})
    assert resp.status_code == 400


def test_create_scan_code_agent_without_code_path_returns_400():
    resp = client.post("/scans", json={"target": "test-target", "agents": ["code"]})
    assert resp.status_code == 400


def test_create_scan_k8s_agent_without_authorized_cluster_returns_403():
    resp = client.post("/scans", json={"target": "test-target", "agents": ["k8s"]})
    assert resp.status_code == 403


def test_get_report_and_evidence_after_scan():
    client.post("/scans", json={"target": "test-target", "agents": [], "execute": True})

    report_resp = client.get("/scans/test-target/report")
    assert report_resp.status_code == 200
    assert "Security Assessment Report" in report_resp.text

    evidence_resp = client.get("/scans/test-target/evidence")
    assert evidence_resp.status_code == 200
    assert evidence_resp.json()["targets"] == []


def test_get_report_before_any_scan_returns_404():
    resp = client.get("/scans/test-target/report")
    assert resp.status_code == 404


def test_get_diff_before_any_scan_returns_404():
    resp = client.get("/scans/test-target/diff")
    assert resp.status_code == 404


def test_dashboard_renders_without_error():
    client.post("/scans", json={"target": "test-target", "agents": [], "execute": True})
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Security Scan Dashboard" in resp.text
    assert "test-target" in resp.text


def test_endpoints_unauthenticated_when_no_api_key_configured():
    # scratch_env fixture already ensures API_KEY is unset
    resp = client.get("/targets")
    assert resp.status_code == 200


def test_endpoints_require_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("API_KEY", "secret123")

    no_auth = client.get("/targets")
    assert no_auth.status_code == 401

    wrong_auth = client.get("/targets", headers={"Authorization": "Bearer wrong"})
    assert wrong_auth.status_code == 401

    correct_auth = client.get("/targets", headers={"Authorization": "Bearer secret123"})
    assert correct_auth.status_code == 200


def test_health_never_requires_api_key(monkeypatch):
    monkeypatch.setenv("API_KEY", "secret123")
    resp = client.get("/health")
    assert resp.status_code == 200
