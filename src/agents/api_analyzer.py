"""API Analyzer: passive/read-only checks against a REST/GraphQL API.

Scope: OpenAPI/Swagger spec discovery, endpoint/security-scheme enumeration
from that spec, GraphQL introspection detection, and verbose-error-page
detection. All requests are GET, or a single standard read-only GraphQL
introspection POST -- no fuzzing, no auth bypass attempts, no exploitation
of discovered endpoints.
"""
from __future__ import annotations

import logging

import requests

from src.agent_base import AgentResult, BaseAgent
from src.logging_setup import log_with_fields

# Common locations a REST API's OpenAPI/Swagger spec is published at.
OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v1/openapi.json",
    "/api/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
]

# Minimal, read-only introspection query -- does not mutate any data.
GRAPHQL_INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } } }"
}

# Substrings that suggest a raw stack trace / debug page leaked to the client.
STACK_TRACE_MARKERS = [
    "Traceback (most recent call last)",
    "at java.",
    "Exception in thread",
    "Fatal error:",
    "Warning: include(",
    "System.Exception",
    "django.core.exceptions",
    "Whitelabel Error Page",
]


class ApiAnalyzer(BaseAgent):
    name = "api-analyzer"
    # No external binaries -- this agent only makes HTTP GET/POST requests
    # via the `requests` library, so allowed_tools stays empty.
    allowed_tools: list[str] = []
    request_timeout_seconds = 10

    def run(self, target: str) -> AgentResult:
        self.scope_guard.authorize(self._host_from_target(target))
        result = AgentResult(
            agent_name=self.name, target=target, timestamp=self._now(), status="ok"
        )
        base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"

        for step in (
            self._discover_openapi_spec,
            self._check_graphql_introspection,
            self._check_verbose_errors,
        ):
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

    def _post(self, url: str, json_body: dict) -> requests.Response:
        try:
            self._prepare_request("POST", url)
        except RuntimeError as e:
            raise requests.RequestException(str(e)) from e
        return requests.post(url, json=json_body, timeout=self.request_timeout_seconds)

    def _discover_openapi_spec(self, base_url: str, result: AgentResult) -> None:
        for path in OPENAPI_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            resp = self._get(url)
            if resp.status_code != 200:
                continue
            try:
                spec = resp.json()
            except ValueError:
                continue
            if "paths" not in spec:
                continue

            result.raw_output.append(f"OpenAPI spec found at {url}")
            endpoints = list(spec.get("paths", {}).keys())
            result.findings.append({
                "type": "openapi-spec-exposed",
                "url": url,
                "endpoint_count": len(endpoints),
                "endpoints": endpoints[:50],  # cap to keep findings readable
            })

            security_schemes = (
                spec.get("components", {}).get("securitySchemes")
                or spec.get("securityDefinitions")
                or {}
            )
            if not security_schemes:
                result.findings.append({
                    "type": "openapi-no-security-scheme-declared",
                    "url": url,
                })
            return  # stop at first spec found

    def _check_graphql_introspection(self, base_url: str, result: AgentResult) -> None:
        url = f"{base_url.rstrip('/')}/graphql"
        resp = self._post(url, GRAPHQL_INTROSPECTION_QUERY)
        if resp.status_code != 200:
            return
        try:
            body = resp.json()
        except ValueError:
            return
        query_type = body.get("data", {}).get("__schema", {}).get("queryType", {}).get("name")
        if query_type:
            result.findings.append({
                "type": "graphql-introspection-enabled",
                "url": url,
                "query_type": query_type,
            })

    def _check_verbose_errors(self, base_url: str, result: AgentResult) -> None:
        # Request a path that should not exist to see how errors are surfaced.
        probe_path = "/__llm-cybersec-nonexistent-probe__"
        resp = self._get(f"{base_url.rstrip('/')}{probe_path}")
        body = resp.text or ""
        hit = next((marker for marker in STACK_TRACE_MARKERS if marker in body), None)
        if hit:
            result.findings.append({
                "type": "verbose-error-page",
                "status_code": resp.status_code,
                "marker_matched": hit,
            })
