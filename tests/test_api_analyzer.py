import textwrap

import pytest
import responses

from src.agents.api_analyzer import ApiAnalyzer
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


def _stub_all_openapi_paths_404():
    from src.agents.api_analyzer import OPENAPI_PATHS
    for path in OPENAPI_PATHS:
        responses.add(responses.GET, f"http://127.0.0.1{path}", status=404)


def _stub_graphql_disabled():
    responses.add(responses.POST, "http://127.0.0.1/graphql", status=404)


def _stub_no_verbose_errors():
    responses.add(
        responses.GET, "http://127.0.0.1/__llm-cybersec-nonexistent-probe__",
        body="Not Found", status=404,
    )


def test_out_of_scope_target_rejected(guard):
    agent = ApiAnalyzer(guard, dry_run=False)
    with pytest.raises(OutOfScopeError):
        agent.run("evil.example.com")


def test_dry_run_makes_no_real_requests(guard):
    agent = ApiAnalyzer(guard, dry_run=True)
    result = agent.run("127.0.0.1")
    assert result.status == "ok"
    assert all(f["type"] == "request-failed" for f in result.findings)


@responses.activate
def test_openapi_spec_discovered_and_missing_security_scheme_flagged(guard):
    responses.add(
        responses.GET, "http://127.0.0.1/openapi.json",
        json={"paths": {"/users": {}, "/users/{id}": {}}},
        status=200,
    )
    _stub_graphql_disabled()
    _stub_no_verbose_errors()

    agent = ApiAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    spec_findings = [f for f in result.findings if f["type"] == "openapi-spec-exposed"]
    assert spec_findings
    assert spec_findings[0]["endpoint_count"] == 2
    assert set(spec_findings[0]["endpoints"]) == {"/users", "/users/{id}"}

    no_sec = [f for f in result.findings if f["type"] == "openapi-no-security-scheme-declared"]
    assert no_sec


@responses.activate
def test_openapi_spec_with_security_scheme_not_flagged(guard):
    responses.add(
        responses.GET, "http://127.0.0.1/openapi.json",
        json={
            "paths": {"/users": {}},
            "components": {"securitySchemes": {"bearerAuth": {"type": "http"}}},
        },
        status=200,
    )
    _stub_graphql_disabled()
    _stub_no_verbose_errors()

    agent = ApiAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    no_sec = [f for f in result.findings if f["type"] == "openapi-no-security-scheme-declared"]
    assert not no_sec


@responses.activate
def test_no_spec_found_produces_no_openapi_findings(guard):
    _stub_all_openapi_paths_404()
    _stub_graphql_disabled()
    _stub_no_verbose_errors()

    agent = ApiAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    assert not [f for f in result.findings if f["type"].startswith("openapi")]


@responses.activate
def test_graphql_introspection_enabled_detected(guard):
    _stub_all_openapi_paths_404()
    responses.add(
        responses.POST, "http://127.0.0.1/graphql",
        json={"data": {"__schema": {"queryType": {"name": "Query"}}}},
        status=200,
    )
    _stub_no_verbose_errors()

    agent = ApiAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    gql = [f for f in result.findings if f["type"] == "graphql-introspection-enabled"]
    assert gql and gql[0]["query_type"] == "Query"


@responses.activate
def test_verbose_error_page_detected(guard):
    _stub_all_openapi_paths_404()
    _stub_graphql_disabled()
    responses.add(
        responses.GET, "http://127.0.0.1/__llm-cybersec-nonexistent-probe__",
        body="Traceback (most recent call last):\n  File x.py, line 1",
        status=500,
    )

    agent = ApiAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    verbose = [f for f in result.findings if f["type"] == "verbose-error-page"]
    assert verbose and verbose[0]["status_code"] == 500
