import textwrap

import pytest
import responses

from src.agents.webapp_analyzer import WebAppAnalyzer
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
    agent = WebAppAnalyzer(guard, dry_run=False)
    with pytest.raises(OutOfScopeError):
        agent.run("evil.example.com")


def test_dry_run_makes_no_real_requests(guard):
    agent = WebAppAnalyzer(guard, dry_run=True)
    result = agent.run("127.0.0.1")
    assert result.status == "ok"
    assert all(f["type"] == "request-failed" for f in result.findings)


@responses.activate
def test_missing_security_headers_detected(guard):
    responses.add(
        responses.GET, "http://127.0.0.1/",
        body="<html><head><title>Test Page</title></head></html>",
        status=200,
        headers={"Server": "nginx/1.18.0"},
    )
    responses.add(responses.GET, "http://127.0.0.1/robots.txt", status=404)

    agent = WebAppAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    missing_headers_findings = [f for f in result.findings if f["type"] == "missing-security-headers"]
    assert missing_headers_findings
    assert "Content-Security-Policy" in missing_headers_findings[0]["headers"]

    banner = [f for f in result.findings if f["type"] == "server-banner"]
    assert banner and banner[0]["value"] == "nginx/1.18.0"

    title = [f for f in result.findings if f["type"] == "page-title"]
    assert title and title[0]["value"] == "Test Page"


@responses.activate
def test_robots_txt_parsed(guard):
    responses.add(responses.GET, "http://127.0.0.1/", body="<html></html>", status=200)
    responses.add(
        responses.GET, "http://127.0.0.1/robots.txt",
        body="User-agent: *\nDisallow: /admin\nDisallow: /private\n",
        status=200,
    )

    agent = WebAppAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    robots_findings = [f for f in result.findings if f["type"] == "robots-txt"]
    assert robots_findings
    assert set(robots_findings[0]["disallowed_paths"]) == {"/admin", "/private"}


@responses.activate
def test_generator_meta_tag_detected(guard):
    html = '<html><head><meta name="generator" content="WordPress 6.2"/></head></html>'
    responses.add(responses.GET, "http://127.0.0.1/", body=html, status=200)
    responses.add(responses.GET, "http://127.0.0.1/robots.txt", status=404)

    agent = WebAppAnalyzer(guard, dry_run=False)
    result = agent.run("127.0.0.1")

    gen_findings = [f for f in result.findings if f["type"] == "generator-meta-tag"]
    assert gen_findings and gen_findings[0]["value"] == "WordPress 6.2"
