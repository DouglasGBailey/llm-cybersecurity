from src.diff_engine import compute_diff


def test_first_run_has_no_alert_even_though_everything_is_new():
    current = [{"type": "open-port", "port": 80}, {"type": "server-banner", "value": "nginx"}]
    diff = compute_diff([], current, is_first_run=True)

    assert diff["is_first_run"] is True
    assert len(diff["new_findings"]) == 2
    assert diff["resolved_findings"] == []
    assert diff["unchanged_findings"] == []
    assert diff["has_new_findings"] is False


def test_new_finding_detected_on_non_first_run():
    previous = [{"type": "open-port", "port": 80}]
    current = [{"type": "open-port", "port": 80}, {"type": "open-port", "port": 443}]
    diff = compute_diff(previous, current, is_first_run=False)

    assert diff["has_new_findings"] is True
    assert diff["new_findings"] == [{"type": "open-port", "port": 443}]
    assert diff["resolved_findings"] == []
    assert diff["unchanged_findings"] == [{"type": "open-port", "port": 80}]


def test_resolved_finding_detected():
    previous = [{"type": "open-port", "port": 80}, {"type": "open-port", "port": 443}]
    current = [{"type": "open-port", "port": 80}]
    diff = compute_diff(previous, current, is_first_run=False)

    assert diff["resolved_findings"] == [{"type": "open-port", "port": 443}]
    assert diff["new_findings"] == []
    assert diff["has_new_findings"] is False


def test_identical_findings_are_all_unchanged():
    findings = [{"type": "open-port", "port": 80}, {"type": "server-banner", "value": "nginx"}]
    diff = compute_diff(findings, list(findings), is_first_run=False)

    assert diff["new_findings"] == []
    assert diff["resolved_findings"] == []
    assert len(diff["unchanged_findings"]) == 2
    assert diff["has_new_findings"] is False


def test_seen_by_differences_do_not_cause_false_new_finding():
    previous = [{"type": "server-banner", "value": "nginx", "seen_by": ["webapp-analyzer"]}]
    current = [{"type": "server-banner", "value": "nginx", "seen_by": ["webapp-analyzer", "api-analyzer"]}]
    diff = compute_diff(previous, current, is_first_run=False)

    assert diff["new_findings"] == []
    assert diff["resolved_findings"] == []
    assert len(diff["unchanged_findings"]) == 1
    assert diff["has_new_findings"] is False


def test_empty_to_empty_produces_no_findings():
    diff = compute_diff([], [], is_first_run=False)
    assert diff["new_findings"] == []
    assert diff["resolved_findings"] == []
    assert diff["unchanged_findings"] == []
    assert diff["has_new_findings"] is False
