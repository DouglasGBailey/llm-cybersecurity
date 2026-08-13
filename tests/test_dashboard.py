import json
import textwrap

import pytest

from src.dashboard import generate_dashboard
from src.history_store import HistoryStore


@pytest.fixture
def scope_path(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent("""
        authorized_targets:
          - name: local-dvwa
            host: 127.0.0.1
          - name: other-target
            host: 127.0.0.2
        excluded: []
        max_scan_rate: 5
    """))
    return p


@pytest.fixture
def reports_dir(tmp_path):
    d = tmp_path / "reports"
    d.mkdir()
    return d


def test_dashboard_generates_with_no_history_at_all(scope_path, tmp_path, reports_dir):
    db_path = tmp_path / "history.db"
    html = generate_dashboard(scope_path, history_db_path=db_path, reports_dir=reports_dir)

    assert "Security Scan Dashboard" in html
    assert "local-dvwa" in html
    assert "other-target" in html
    assert html.count("No runs yet.") == 2


def test_dashboard_shows_history_for_target_with_runs(scope_path, tmp_path, reports_dir):
    db_path = tmp_path / "history.db"
    store = HistoryStore(db_path=db_path)
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", [
        {"type": "missing-security-headers", "headers": ["CSP"]},
    ])
    store.save_run("local-dvwa", "2026-08-13T01:00:00+00:00", [
        {"type": "missing-security-headers", "headers": ["CSP"]},
        {"type": "server-banner", "value": "nginx"},
    ])

    html = generate_dashboard(scope_path, history_db_path=db_path, reports_dir=reports_dir)

    dvwa_card = html.split("other-target")[0]  # local-dvwa's card comes first
    assert "No runs yet." not in dvwa_card
    assert "2 run(s) recorded" in html
    assert "<svg" in html  # sparkline rendered
    assert "medium: 1" in html  # missing-security-headers severity
    assert html.count("No runs yet.") == 1  # only other-target has none


def test_dashboard_shows_diff_when_diff_file_present(scope_path, tmp_path, reports_dir):
    db_path = tmp_path / "history.db"
    store = HistoryStore(db_path=db_path)
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", [{"type": "open-port", "port": 80}])

    diff = {
        "is_first_run": False,
        "new_findings": [{"type": "open-port", "port": 443}],
        "resolved_findings": [],
        "unchanged_findings": [{"type": "open-port", "port": 80}],
        "has_new_findings": True,
    }
    (reports_dir / "local-dvwa-diff.json").write_text(json.dumps(diff))

    html = generate_dashboard(scope_path, history_db_path=db_path, reports_dir=reports_dir)
    assert "1 new" in html
    assert "1 unchanged" in html


def test_dashboard_shows_no_diff_message_when_diff_file_absent(scope_path, tmp_path, reports_dir):
    db_path = tmp_path / "history.db"
    store = HistoryStore(db_path=db_path)
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", [{"type": "open-port", "port": 80}])

    html = generate_dashboard(scope_path, history_db_path=db_path, reports_dir=reports_dir)
    assert "No diff recorded yet." in html


def test_dashboard_shows_compliance_coverage(scope_path, tmp_path, reports_dir):
    db_path = tmp_path / "history.db"
    store = HistoryStore(db_path=db_path)
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", [
        {
            "type": "missing-security-headers",
            "headers": ["CSP"],
            "compliance": [{"framework": "OWASP Top 10 2021", "control": "A05:2021 - Security Misconfiguration"}],
        },
    ])

    html = generate_dashboard(scope_path, history_db_path=db_path, reports_dir=reports_dir)
    assert "OWASP Top 10 2021" in html
    assert "A05:2021 - Security Misconfiguration" in html


def test_dashboard_links_to_report_when_present(scope_path, tmp_path, reports_dir):
    db_path = tmp_path / "history.db"
    store = HistoryStore(db_path=db_path)
    store.save_run("local-dvwa", "2026-08-13T00:00:00+00:00", [{"type": "open-port", "port": 80}])
    (reports_dir / "local-dvwa-report.md").write_text("# report")

    html = generate_dashboard(scope_path, history_db_path=db_path, reports_dir=reports_dir)
    assert 'href="local-dvwa-report.md"' in html
