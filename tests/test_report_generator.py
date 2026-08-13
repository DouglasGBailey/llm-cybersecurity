from src.agent_base import AgentResult
from src.agents.evidence_collector import EvidenceCollector
from src.agents.report_generator import ReportGenerator, _severity_for
from src.diff_engine import compute_diff


def make_result(agent_name, target, findings):
    return AgentResult(
        agent_name=agent_name, target=target, timestamp="2026-08-13T00:00:00+00:00",
        status="ok", findings=findings,
    )


def test_severity_mapping_known_types():
    assert _severity_for({"type": "tls-certificate-expired"}) == "high"
    assert _severity_for({"type": "llm-probe-failed"}) == "high"
    assert _severity_for({"type": "missing-security-headers"}) == "medium"
    assert _severity_for({"type": "graphql-introspection-enabled"}) == "low"
    assert _severity_for({"type": "server-banner"}) == "info"
    assert _severity_for({"type": "some-unknown-type"}) == "info"


def test_severity_mapping_bandit_and_semgrep():
    assert _severity_for({"type": "bandit-finding", "severity": "HIGH"}) == "high"
    assert _severity_for({"type": "bandit-finding", "severity": "LOW"}) == "low"
    assert _severity_for({"type": "semgrep-finding", "severity": "ERROR"}) == "high"
    assert _severity_for({"type": "semgrep-finding", "severity": "INFO"}) == "low"


def test_report_with_no_findings():
    evidence = EvidenceCollector().collect([])
    report = ReportGenerator().generate(evidence)
    assert "# Security Assessment Report" in report
    assert "_No findings recorded._" in report


def test_report_contains_summary_and_grouped_findings():
    results = [
        make_result("infra-analyzer", "127.0.0.1:8443", [
            {"type": "tls-certificate-expired", "not_after": "2020-01-01T00:00:00+00:00"},
        ]),
        make_result("webapp-analyzer", "127.0.0.1", [
            {"type": "server-banner", "value": "Apache/2.4.25"},
        ]),
    ]
    evidence = EvidenceCollector().collect(results)
    report = ReportGenerator().generate(evidence)

    assert "Total findings (raw, across all agents): 2" in report
    assert "### HIGH" in report
    assert "tls-certificate-expired" in report
    assert "### INFO" in report
    assert "server-banner" in report
    assert "## Raw Agent Results" in report
    assert "infra-analyzer" in report


def test_report_findings_grouped_by_severity_order():
    results = [
        make_result("agent-a", "target", [
            {"type": "server-banner", "value": "x"},  # info
            {"type": "spf-record-missing", "host": "target"},  # low
            {"type": "missing-security-headers", "headers": []},  # medium
            {"type": "llm-probe-failed", "probe_id": "p1"},  # high
        ]),
    ]
    evidence = EvidenceCollector().collect(results)
    report = ReportGenerator().generate(evidence)

    high_idx = report.index("### HIGH")
    medium_idx = report.index("### MEDIUM")
    low_idx = report.index("### LOW")
    info_idx = report.index("### INFO")
    assert high_idx < medium_idx < low_idx < info_idx


def test_no_diff_section_when_diff_not_passed():
    evidence = EvidenceCollector().collect([])
    report = ReportGenerator().generate(evidence)
    assert "## Changes Since Last Scan" not in report


def test_no_diff_section_on_first_run():
    evidence = EvidenceCollector().collect([])
    diff = compute_diff([], [], is_first_run=True)
    report = ReportGenerator().generate(evidence, diff=diff)
    assert "## Changes Since Last Scan" not in report


def test_diff_section_shows_new_and_resolved_findings():
    results = [make_result("webapp-analyzer", "127.0.0.1", [{"type": "open-port", "port": 443}])]
    evidence = EvidenceCollector().collect(results)
    diff = compute_diff(
        previous_findings=[{"type": "open-port", "port": 80}],
        current_findings=[{"type": "open-port", "port": 443}],
        is_first_run=False,
    )
    report = ReportGenerator().generate(evidence, diff=diff)

    assert "## Changes Since Last Scan" in report
    assert "### New (1)" in report
    assert "port=443" in report
    assert "### Resolved (1)" in report
    assert "port=80" in report


def test_diff_section_no_changes_message_when_nothing_changed():
    evidence = EvidenceCollector().collect([])
    diff = compute_diff(
        previous_findings=[{"type": "open-port", "port": 80}],
        current_findings=[{"type": "open-port", "port": 80}],
        is_first_run=False,
    )
    report = ReportGenerator().generate(evidence, diff=diff)

    assert "## Changes Since Last Scan" in report
    assert "No changes" in report
    assert "1 finding(s) unchanged" in report
