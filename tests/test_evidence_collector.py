from src.agent_base import AgentResult
from src.agents.evidence_collector import EvidenceCollector


def make_result(agent_name, target, findings):
    return AgentResult(
        agent_name=agent_name, target=target, timestamp="2026-08-13T00:00:00+00:00",
        status="ok", findings=findings,
    )


def test_empty_results_produces_empty_evidence():
    evidence = EvidenceCollector().collect([])
    assert evidence["targets"] == []
    assert evidence["agents_run"] == []
    assert evidence["summary"]["total_findings_raw"] == 0
    assert evidence["summary"]["total_findings_deduplicated"] == 0
    assert evidence["findings"] == []


def test_findings_from_single_agent_pass_through():
    results = [make_result("recon-agent", "127.0.0.1", [
        {"type": "open-port", "port": 80},
        {"type": "open-port", "port": 443},
    ])]
    evidence = EvidenceCollector().collect(results)

    assert evidence["targets"] == ["127.0.0.1"]
    assert evidence["agents_run"] == ["recon-agent"]
    assert evidence["summary"]["total_findings_raw"] == 2
    assert evidence["summary"]["total_findings_deduplicated"] == 2
    assert evidence["summary"]["by_type"] == {"open-port": 2}
    assert evidence["summary"]["by_agent"] == {"recon-agent": 2}
    ports = {f["port"] for f in evidence["findings"]}
    assert ports == {80, 443}


def test_identical_findings_from_different_agents_deduplicated():
    shared_finding = {"type": "server-banner", "value": "Apache/2.4.25"}
    results = [
        make_result("webapp-analyzer", "127.0.0.1", [shared_finding]),
        make_result("api-analyzer", "127.0.0.1", [dict(shared_finding)]),
    ]
    evidence = EvidenceCollector().collect(results)

    assert evidence["summary"]["total_findings_raw"] == 2
    assert evidence["summary"]["total_findings_deduplicated"] == 1
    assert len(evidence["findings"]) == 1
    assert set(evidence["findings"][0]["seen_by"]) == {"webapp-analyzer", "api-analyzer"}


def test_multiple_targets_and_agents_aggregated():
    results = [
        make_result("recon-agent", "127.0.0.1", [{"type": "dns-resolution", "records": ["127.0.0.1"]}]),
        make_result("webapp-analyzer", "127.0.0.1:8080", [{"type": "server-banner", "value": "nginx"}]),
    ]
    evidence = EvidenceCollector().collect(results)

    assert evidence["targets"] == ["127.0.0.1", "127.0.0.1:8080"]
    assert evidence["agents_run"] == ["recon-agent", "webapp-analyzer"]
    assert evidence["summary"]["by_agent"] == {"recon-agent": 1, "webapp-analyzer": 1}


def test_agent_results_preserved_in_evidence():
    results = [make_result("recon-agent", "127.0.0.1", [{"type": "open-port", "port": 22}])]
    evidence = EvidenceCollector().collect(results)

    assert evidence["agent_results"] == [results[0].to_dict()]
