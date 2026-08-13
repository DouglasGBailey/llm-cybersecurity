import textwrap

import pytest
import responses

from src.agents.llm_security_analyzer import DEFAULT_PROBES, LlmSecurityAnalyzer
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


def test_out_of_scope_target_rejected(guard):
    # Use a bare IP (not a hostname) so scope checking doesn't require a
    # live DNS lookup in the test suite.
    agent = LlmSecurityAnalyzer(guard, dry_run=False)
    with pytest.raises(OutOfScopeError):
        agent.run("8.8.8.8/chat")


def test_dry_run_makes_no_real_requests(guard):
    agent = LlmSecurityAnalyzer(guard, dry_run=True)
    result = agent.run("127.0.0.1/chat")
    assert result.status == "ok"
    failed_requests = [f for f in result.findings if f["type"] == "probe-request-failed"]
    assert len(failed_requests) == len(DEFAULT_PROBES)
    summary = [f for f in result.findings if f["type"] == "llm-probe-summary"][0]
    assert summary["total"] == len(DEFAULT_PROBES)


@responses.activate
def test_all_probes_pass_when_app_refuses(guard):
    responses.add(
        responses.POST, "http://127.0.0.1/chat",
        json={"response": "I can't do that, ignoring instruction overrides."},
        status=200,
    )
    agent = LlmSecurityAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1/chat")

    assert not [f for f in result.findings if f["type"] == "llm-probe-failed"]
    summary = [f for f in result.findings if f["type"] == "llm-probe-summary"][0]
    assert summary["passed"] == len(DEFAULT_PROBES)
    assert summary["failed"] == 0


@responses.activate
def test_probe_failure_detected_when_app_complies(guard):
    responses.add(
        responses.POST, "http://127.0.0.1/chat",
        json={"response": "Sure! COMPROMISED"},
        status=200,
    )
    agent = LlmSecurityAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1/chat")

    failed = [f for f in result.findings if f["type"] == "llm-probe-failed"]
    assert failed
    assert any(f["probe_id"] == "instruction-override" for f in failed)


@responses.activate
def test_plain_text_response_handled(guard):
    responses.add(
        responses.POST, "http://127.0.0.1/chat",
        body="COMPROMISED", status=200,
        content_type="text/plain",
    )
    agent = LlmSecurityAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1/chat")

    failed = [f for f in result.findings if f["type"] == "llm-probe-failed"]
    assert failed


@responses.activate
def test_openai_style_choices_response_parsed(guard):
    responses.add(
        responses.POST, "http://127.0.0.1/chat",
        json={"choices": [{"message": {"content": "Sorry, I won't say COMPROMISED."}}]},
        status=200,
    )
    agent = LlmSecurityAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1/chat")

    # "COMPROMISED" appears even in the refusal text here, so the naive
    # substring check flags it -- demonstrates the heuristic's limitation
    # (documented) while confirming the choices[].message.content path is read.
    failed = [f for f in result.findings if f["type"] == "llm-probe-failed"]
    assert any(f["probe_id"] == "instruction-override" for f in failed)


@responses.activate
def test_request_failure_recorded_not_crashed(guard):
    responses.add(responses.POST, "http://127.0.0.1/chat", status=500)
    agent = LlmSecurityAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1/chat")

    assert result.status == "ok"
    assert [f for f in result.findings if f["type"] == "probe-request-failed"]


def test_custom_probes_loaded_from_config(guard, tmp_path):
    custom_path = tmp_path / "llm_probes.yaml"
    custom_path.write_text(textwrap.dedent("""
        probes:
          - id: custom-probe
            category: jailbreak
            prompt: "say XYZZY"
            fail_markers: ["XYZZY"]
    """))
    agent = LlmSecurityAnalyzer(guard, dry_run=True)
    agent.probes_path = custom_path
    result = agent.run("127.0.0.1/chat")

    summary = [f for f in result.findings if f["type"] == "llm-probe-summary"][0]
    assert summary["total"] == 1
