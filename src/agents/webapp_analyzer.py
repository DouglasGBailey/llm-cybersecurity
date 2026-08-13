"""Web App Analyzer: passive HTTP-level checks against an authorized target.

Scope: read-only GET/HEAD requests only (via `requests`). Checks security
headers, basic tech fingerprinting, and robots.txt/sitemap discovery.
No form submission, no auth bypass attempts, no fuzzing.
"""
from __future__ import annotations

import logging

import requests
from bs4 import BeautifulSoup

from src.agent_base import AgentResult, BaseAgent
from src.logging_setup import log_with_fields

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class WebAppAnalyzer(BaseAgent):
    name = "webapp-analyzer"
    # No external binaries -- this agent only makes HTTP GET/HEAD requests
    # via the `requests` library, so allowed_tools stays empty.
    allowed_tools: list[str] = []
    request_timeout_seconds = 10

    def run(self, target: str) -> AgentResult:
        self.scope_guard.authorize(self._host_from_target(target))
        result = AgentResult(
            agent_name=self.name, target=target, timestamp=self._now(), status="ok"
        )
        base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"

        for step in (self._check_headers, self._check_robots, self._fingerprint):
            try:
                step(base_url, result)
            except Exception as e:  # noqa: BLE001 - one step's failure shouldn't lose findings from the rest
                log_with_fields(self.logger, logging.WARNING, str(e), target=base_url)
                result.findings.append({"type": "request-failed", "step": step.__name__, "detail": str(e)})

        return result

    def _get(self, url: str) -> requests.Response:
        try:
            self._prepare_request("GET", url)
        except RuntimeError as e:
            raise requests.RequestException(str(e)) from e
        return requests.get(url, timeout=self.request_timeout_seconds)

    def _check_headers(self, base_url: str, result: AgentResult) -> None:
        resp = self._get(base_url)
        result.raw_output.append(f"GET {base_url} -> {resp.status_code}")
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        if missing:
            result.findings.append({"type": "missing-security-headers", "headers": missing})
        server = resp.headers.get("Server")
        if server:
            result.findings.append({"type": "server-banner", "value": server})
        powered_by = resp.headers.get("X-Powered-By")
        if powered_by:
            result.findings.append({"type": "x-powered-by", "value": powered_by})

    def _check_robots(self, base_url: str, result: AgentResult) -> None:
        resp = self._get(f"{base_url.rstrip('/')}/robots.txt")
        if resp.status_code == 200 and resp.text.strip():
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in resp.text.splitlines()
                if line.lower().startswith("disallow:")
            ]
            result.findings.append({"type": "robots-txt", "disallowed_paths": disallowed})

    def _fingerprint(self, base_url: str, result: AgentResult) -> None:
        resp = self._get(base_url)
        soup = BeautifulSoup(resp.text, "html.parser")
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            result.findings.append({"type": "generator-meta-tag", "value": generator["content"]})
        title = soup.find("title")
        if title and title.text.strip():
            result.findings.append({"type": "page-title", "value": title.text.strip()})
