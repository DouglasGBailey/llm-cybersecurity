"""REST API over the orchestrator -- lets external systems (CI, a future
UI, K8s Jobs) trigger scans and read results programmatically instead of
shelling out to the CLI.

Scan execution is synchronous for this first pass: POST /scans blocks
until the scan finishes and returns its result. No task queue, matching
the platform's "don't add infrastructure before there's a real need for
it" precedent (same reasoning that ruled out a scheduler daemon and a live
dashboard server).

Auth is opt-in, not required, for this first pass -- set API_KEY to
require `Authorization: Bearer <key>` on every endpoint except /health.
With API_KEY unset, the API is intentionally still usable (per explicit
product decision), but:
  - it binds to 127.0.0.1 by default when run directly (see `main()`  --
    exposing it beyond localhost requires deliberately setting API_HOST)
  - it prints a loud startup warning
This mitigates a repeat of an earlier incident where a different local
tool (the static dashboard server) was accidentally bound to a public
interface with no auth in front of it.
"""
from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from src.dashboard import generate_dashboard
from src.history_store import DEFAULT_DB_PATH
from src.logging_setup import get_logger
from src.orchestrator import AGENT_REGISTRY, DEFAULT_REPORTS_DIR, EXPLOIT_AGENTS, run_scan
from src.scope_guard import OutOfScopeError, ScopeConfigError, ScopeGuard

logger = get_logger("api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not os.environ.get("API_KEY"):
        logger.warning(
            "API_KEY not set -- all endpoints are UNAUTHENTICATED. "
            "Do not bind beyond localhost without setting one."
        )
    yield


app = FastAPI(title="LLM Cybersecurity Agent Platform API", version="1.0.0", lifespan=lifespan)


def _scope_path() -> str:
    return os.environ.get("SCOPE_PATH", "config/scope.yaml")


def _reports_dir() -> Path:
    return Path(os.environ.get("REPORTS_DIR", str(DEFAULT_REPORTS_DIR)))


def _history_db_path() -> Path:
    return Path(os.environ.get("HISTORY_DB_PATH", str(DEFAULT_DB_PATH)))


async def require_api_key(request: Request) -> None:
    """No-op if API_KEY isn't set (opt-in auth). If it IS set, every
    request must present a matching Bearer token."""
    expected = os.environ.get("API_KEY")
    if not expected:
        return
    auth_header = request.headers.get("authorization", "")
    if not hmac.compare_digest(auth_header, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")


class ScanRequest(BaseModel):
    target: str
    agents: list[str] = ["recon", "webapp"]
    execute: bool = False
    code_path: str | None = None
    ai_triage: bool = False


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/targets", dependencies=[Depends(require_api_key)])
async def list_targets() -> list[dict[str, Any]]:
    try:
        guard = ScopeGuard(_scope_path())
    except ScopeConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return [
        {"name": t.name, "host": t.host, "notes": t.notes}
        for t in guard.scope.authorized_targets
    ]


@app.post("/scans", dependencies=[Depends(require_api_key)])
async def create_scan(req: ScanRequest) -> dict[str, Any]:
    try:
        guard = ScopeGuard(_scope_path())
    except ScopeConfigError as e:
        raise HTTPException(status_code=500, detail=str(e))

    try:
        authorized_target = guard.resolve_target(req.target)
    except OutOfScopeError as e:
        raise HTTPException(status_code=404, detail=str(e))

    unknown = [a for a in req.agents if a not in AGENT_REGISTRY]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown agent(s): {unknown}. Available: {list(AGENT_REGISTRY)}",
        )
    if "code" in req.agents and not req.code_path:
        raise HTTPException(status_code=400, detail="code_path is required when 'code' is in agents")

    exploit_target = None
    if EXPLOIT_AGENTS & set(req.agents):
        try:
            exploit_target = guard.resolve_exploit_target(req.target)
        except OutOfScopeError as e:
            raise HTTPException(status_code=403, detail=str(e))

    result = run_scan(
        guard, authorized_target, req.agents,
        code_path=req.code_path, exploit_target=exploit_target,
        execute=req.execute, ai_triage=req.ai_triage,
        reports_dir=_reports_dir(), history_db_path=_history_db_path(),
    )

    diff = result["diff"]
    return {
        "target": authorized_target.name,
        "exit_code": result["exit_code"],
        "new_findings_count": len(diff["new_findings"]) if diff else None,
        "resolved_findings_count": len(diff["resolved_findings"]) if diff else None,
        "alerted_channels": result["alerted_channels"],
        "report_url": f"/scans/{authorized_target.name}/report",
        "evidence_url": f"/scans/{authorized_target.name}/evidence",
        "diff_url": f"/scans/{authorized_target.name}/diff" if diff else None,
    }


@app.get("/scans/{target}/report", dependencies=[Depends(require_api_key)])
async def get_report(target: str) -> PlainTextResponse:
    path = _reports_dir() / f"{target}-report.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"No report found for target '{target}'")
    return PlainTextResponse(path.read_text(), media_type="text/markdown")


@app.get("/scans/{target}/evidence", dependencies=[Depends(require_api_key)])
async def get_evidence(target: str) -> JSONResponse:
    path = _reports_dir() / f"{target}-evidence.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"No evidence found for target '{target}'")
    return JSONResponse(json.loads(path.read_text()))


@app.get("/scans/{target}/diff", dependencies=[Depends(require_api_key)])
async def get_diff(target: str) -> JSONResponse:
    path = _reports_dir() / f"{target}-diff.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"No diff found for target '{target}'")
    return JSONResponse(json.loads(path.read_text()))


@app.get("/dashboard", dependencies=[Depends(require_api_key)])
async def get_dashboard() -> HTMLResponse:
    html = generate_dashboard(
        _scope_path(), history_db_path=_history_db_path(), reports_dir=_reports_dir()
    )
    return HTMLResponse(html)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="api", description="Run the REST API server.")
    parser.add_argument("--host", default=os.environ.get("API_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("API_PORT", "8000")))
    args = parser.parse_args(argv)

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
