# Development Status - LLM Cybersecurity Agent Platform

## Last Updated
**Date**: 2026-08-13
**Session Duration**: Multi-session build (9 sessions in one day)
**Claude Code Session**: Full platform (6 scanning agents + Evidence
Collector + Report Generator + opt-in AI Triage) built, then extended
toward commercial/enterprise viability across several sessions: scheduled
scanning + diffing, then email alerting + compliance mapping + a static
dashboard, then this session — containerization + a REST API, after the
user asked "what more to make this enterprise-grade, what about k8s?"

## Current Project State

### What's Working — feature-complete platform + enterprise-readiness layer
All components implemented, unit-tested, live-verified against a real
local lab (DVWA container) and a real Docker build.

**Scanning agents** (subclass `BaseAgent`, `src/agent_base.py`, scope-
checked via `ScopeGuard`): `ReconAgent`, `WebAppAnalyzer`, `ApiAnalyzer`,
`InfraAnalyzer`, `CodeAnalyzer`, `LlmSecurityAnalyzer` — unchanged this
session.

**Aggregation & reporting**: `EvidenceCollector` (dedup + compliance
tagging), `ReportGenerator` (Markdown + compliance/diff sections),
`AiTriageAnalyzer` (opt-in, the one genuinely AI-powered piece) —
unchanged this session.

**Scheduled scanning, diffing, alerting, compliance, dashboard** (prior
sessions, unchanged this session): `HistoryStore`, `diff_engine`,
`alerting.py`, `compliance_mapping.py`, `dashboard.py`,
`scripts/run-scheduled-scan.sh`.

**This session — containerization + REST API:**

- **Refactored `src/orchestrator.py`**: extracted `run_scan(guard,
  authorized_target, agent_keys, code_path=None, execute=False,
  ai_triage=False, reports_dir=..., history_db_path=...) -> dict` — the
  exact body that used to live inline in `main()` (agent loop, file
  writes, diff/alert calls), moved not rewritten. `main()` is now a thin
  CLI shell: parse args → validate → `ScopeGuard` → `resolve_target` →
  `run_scan(...)` → `return result["exit_code"]`. Verified as a pure
  extraction: full test suite passed unchanged before touching tests, and
  one live CLI run produced byte-identical console output/behavior to
  before the refactor.
- **`src/api.py`** (new) — FastAPI app wrapping `run_scan()` directly (no
  subprocess, no CLI-output parsing). Endpoints: `GET /health`, `GET
  /targets`, `POST /scans` (synchronous — blocks until the scan finishes,
  no task queue for this pass), `GET /scans/{target}/{report,evidence,
  diff}`, `GET /dashboard` (regenerates fresh via `dashboard.py` on every
  request). Config read from env vars **at request time**
  (`SCOPE_PATH`/`REPORTS_DIR`/`HISTORY_DB_PATH`/`API_KEY`), so tests can
  `monkeypatch.setenv` per-test without import-time coupling.
- **Auth**: opt-in via `API_KEY` (user explicitly declined mandatory auth
  for this pass). Mitigation for that choice, given the immediately prior
  incident where the static dashboard server was accidentally bound
  publicly with no auth: the API **defaults to binding `127.0.0.1`** when
  run directly (`python -m src.api`, via `main()`'s argparse defaults
  reading `API_HOST`/`--host`), and prints a loud startup warning (FastAPI
  `lifespan` context manager, not the deprecated `@app.on_event`) when
  `API_KEY` is unset. This doesn't override the user's decision — it just
  means exposing the API beyond localhost requires a deliberate `--host
  0.0.0.0` or `API_HOST` env var, not an accident.
- **`Dockerfile`** (new) — `python:3.12-slim` + `nmap`/`dnsutils`/`whois`
  installed via apt, `requirements.txt` installed, `src/` and
  `config/*.example.yaml` copied in. Real `scope.yaml`/`alerts.yaml`/
  `data/`/`reports/`/`logs/` are NOT baked in (user-specific, gitignored)
  — volumes at run time. `CMD` binds `0.0.0.0:8000` **inside** the
  container, which is correct/standard (exposure is controlled by `docker
  run -p`'s host-side address, not the in-container bind — documented
  explicitly in the README so it doesn't read as contradicting the
  bind-127.0.0.1-by-default rule for running the API directly on a host).
- **`k8s/scan-job.example.yaml` + `k8s/api-deployment.example.yaml`**
  (new) — illustrative only, not tested against a real cluster (none
  available in this environment). Deliberately minimal investment: the
  actual "enterprise-grade" bottleneck identified was auth/multi-tenancy/
  API surface, not compute scale, so K8s got two reference manifests and a
  documented "not yet, here's why" rather than a real cluster deployment.
- **`tests/test_api.py`** (new, 14 tests) — FastAPI `TestClient`
  (in-process, no real server/port). Covers all endpoints, the
  unknown-target/unknown-agent/missing-code-path error paths, and both
  auth states (unset `API_KEY` → everything open; set → `401` without a
  matching `Authorization` header, `200` with one, `/health` always open
  regardless).

### Testing Status
**124/124 tests passing** (`pytest tests/ -v`), no live network, installed
security tools, `claude` CLI, SMTP server, or running API server required:
| File | Count |
|---|---|
| `test_scope_guard.py` | 12 |
| `test_recon_agent.py` | 5 |
| `test_webapp_analyzer.py` | 5 |
| `test_api_analyzer.py` | 7 |
| `test_infra_analyzer.py` | 9 |
| `test_code_analyzer.py` | 7 |
| `test_llm_security_analyzer.py` | 8 |
| `test_ai_triage_analyzer.py` | 5 |
| `test_evidence_collector.py` | 7 |
| `test_report_generator.py` | 13 |
| `test_history_store.py` | 6 |
| `test_diff_engine.py` | 6 |
| `test_compliance_mapping.py` | 6 |
| `test_alerting.py` | 8 |
| `test_dashboard.py` | 6 |
| `test_api.py` | 14 (new) |

Note: `test_api_analyzer.py` is the pre-existing OpenAPI/GraphQL scanning
agent's tests, not to be confused with the new `test_api.py` for the REST
API itself — same-sounding names, different components.

### Live Verification (this session)
1. **Orchestrator refactor**: full suite green pre/post-refactor; live
   `python -m src.orchestrator ... --execute` against `local-dvwa`
   produced identical console output/file writes to before the change.
2. **API server, direct**: started `python -m src.api --port 8095`
   (port 8000 was already taken by another service on this host).
   Confirmed: default bind is `127.0.0.1` (not `0.0.0.0`), startup warning
   printed when `API_KEY` unset. Exercised every endpoint against real
   DVWA data: `GET /targets` returned real scope targets, `POST /scans`
   triggered a real `webapp` scan and returned correct summary/links,
   `GET /scans/local-dvwa/{report,evidence,diff}` all returned correct
   real content, `GET /dashboard` rendered with real data. Verified error
   paths live: unknown target → `404`, unknown agent → `400`.
3. **Auth**: restarted with `API_KEY=testsecret`. Confirmed no startup
   warning, `401` with no/wrong `Authorization` header, `200` with the
   correct one, `/health` open regardless of `API_KEY`.
4. **Docker**: `docker build` succeeded cleanly. Smoke-tested the built
   image: `python3 -c "from src.api import app"` succeeded, `nmap`/`dig`/
   `whois`/`bandit` all present and on PATH inside the container. Then
   actually ran the container (`docker run -d -p 8096:8000`) and hit
   `GET /health` through the published port successfully — full
   containerized deployment path confirmed working, not just a build check.

### Known Issues / Limitations
- Carried forward: `nmap`/`semgrep` optional/not installed on this dev
  machine (though now confirmed present *inside* the Docker image);
  `LlmSecurityAnalyzer`'s substring-heuristic fail-marker matching;
  `EvidenceCollector`'s exact-content-match dedup; compliance mapping
  covers ~14 of ~30 finding types by design; alerting is email-only;
  dashboard is static/manual-regenerate.
- **API auth is opt-in, not required** — a deliberate, explicit user
  decision, mitigated by localhost-default-bind + a startup warning, not
  by requiring auth. If this API is ever deployed anywhere shared (not a
  single developer's own machine), `API_KEY` should be treated as
  mandatory at that point — the K8s Deployment example
  (`k8s/api-deployment.example.yaml`) already reflects this by sourcing
  `API_KEY` from a Secret rather than leaving it unset.
- **Scan execution is synchronous** — `POST /scans` blocks for the scan's
  full duration. Fine for the current scan sizes (seconds), but a slow
  scan (e.g. a large `nmap` sweep) would hold that request open the whole
  time. No task queue/background-job infrastructure added yet — deferred
  per the user's explicit choice for this pass.
- **K8s manifests are unvalidated** — no cluster available in this
  environment to test against. Treat them as a starting point, not a
  known-working deployment.
- Still open from the original "commercially viable"/"enterprise-grade"
  discussions: Slack/Jira alerting, real CVE matching, an audit/
  attestation trail, actual multi-tenancy.

## Architecture Decisions
Carried forward unchanged: scope file as sole authority; hard per-agent
tool allowlists; no `shell=True`; dry-run default; sequential agent
execution; no default ports/paths; two independent scope lists; evidence/
report generation generic over `AgentResult.findings`; AI-generated
content opt-in and never unlabeled; history/diffing skipped in dry-run;
diff identity strips derived metadata; first run never alerts; only new
findings trigger exit code 3; no scheduler daemon; alerting opt-in by file
presence and failures never propagate; credentials as env-var references
never literal config values; compliance tags are derived metadata, not
finding identity; compliance mapping deliberately incomplete; dashboard
stays static.

**New this session:**
- **One scan-execution code path, two callers**: `run_scan()` lives once
  in `orchestrator.py`; both the CLI (`main()`) and the API
  (`src/api.py`) call it directly. Rejected alternative: having the API
  shell out to the CLI as a subprocess — would have meant either parsing
  stdout (fragile) or duplicating the scan logic (drift risk). A direct
  function call avoids both.
- **Config read at request time, not import time**: `src/api.py`'s
  `_scope_path()`/`_reports_dir()`/`_history_db_path()` read `os.environ`
  fresh on every call rather than being resolved once at module load.
  This is what lets tests `monkeypatch.setenv` per-test without any
  dependency-injection machinery — a deliberate simplicity choice for a
  single-process app, not something that would scale to a multi-worker
  deployment reading different config per request (not a concern here).
- **Auth is opt-in, mitigated by bind-address default, not overridden by
  the assistant**: the user explicitly declined mandatory API auth for
  v1. Rather than either (a) silently complying with an unauthenticated-
  by-default API with no safety net, or (b) unilaterally overriding their
  stated choice and requiring auth anyway, the resolution was to build a
  different mitigation that doesn't contradict their decision: default
  bind stays localhost-only, and the auth mechanism is fully built and
  ready to enable via one env var, just not mandatory. This was flagged
  explicitly in the plan's Context section before implementation, not
  silently decided.
- **Docker's in-container `0.0.0.0` vs. the API's host-run `127.0.0.1`
  default are not a contradiction**: documented explicitly, because on
  the surface they look like inconsistent advice. Container exposure is
  controlled by `docker run -p`'s host-side address; a bare `0.0.0.0`
  bind inside a container that publishes no ports is not reachable from
  anywhere. Conflating "bind address inside a container" with "bind
  address on a bare host" is a common source of confusion worth
  preempting in the docs.
- **K8s gets examples, not a real investment**: consistent with the
  original recommendation (containerize + API first, hold off on K8s
  until real multi-tenant scaling need exists) — two illustrative,
  clearly-unvalidated manifests, not a tested Helm chart or CI pipeline
  targeting a cluster.

## File Structure Status
- Core: `src/scope_guard.py`, `src/agent_base.py`, `src/logging_setup.py`,
  `src/orchestrator.py` (refactored — now exports `run_scan()`),
  `src/history_store.py`, `src/diff_engine.py`, `src/alerting.py`,
  `src/compliance_mapping.py`, `src/dashboard.py`, `src/api.py` (new)
- Agents: `src/agents/{recon_agent,webapp_analyzer,api_analyzer,
  infra_analyzer,code_analyzer,llm_security_analyzer,evidence_collector,
  report_generator,ai_triage_analyzer}.py` — all 9 implemented
- `scripts/run-scheduled-scan.sh` — cron/systemd entry point
- `Dockerfile`, `.dockerignore` (new)
- `k8s/scan-job.example.yaml`, `k8s/api-deployment.example.yaml` (new,
  illustrative/unvalidated)
- `config/scope.yaml` — `local-dvwa` → live `llm-cybersec-dvwa` container;
  `authorized_code_paths` → this project's own `src/`
- `config/scope.example.yaml`, `config/llm_probes.example.yaml`,
  `config/alerts.example.yaml` — templates
- `tests/` — 124 tests across 16 files, all passing
- `data/` — gitignored; `history.db`
- `reports/` — gitignored; per-target `results.json`/`evidence.json`/
  `report.md`/`diff.json` (+ `ai-triage.md` if requested), plus
  `dashboard.html`

### Dependencies
`requirements.txt`: requests, beautifulsoup4, pyyaml, dnspython,
cryptography, bandit, **fastapi, uvicorn** (new — the API server),
pytest, responses, **httpx** (new — required by FastAPI's `TestClient`).
`sqlite3`/`smtplib` remain stdlib. `nmap`, `semgrep`, and the `claude` CLI
remain optional; `nmap`/`dnsutils`(`dig`)/`whois` ARE now installed inside
the Docker image (not in `requirements.txt` — apt packages).

## Notes for Next Session

### Context for a new Claude session
- Platform now covers: scan → aggregate (+ compliance) → report (+
  compliance/diff) → (optional AI triage) → diff against history →
  (optional) email alert → dashboard on demand, all triggerable via CLI
  **or** REST API, and the whole thing containerizes. This was the latest
  step in an ongoing, user-driven "what makes this commercially viable /
  enterprise-grade" conversation — expect more asks in this vein.
- If asked to add a new scanning agent: same pattern as always (README's
  "Adding a new agent"). It gets diffing, dashboard inclusion, and API
  exposure (via the existing `/scans` endpoint's `agents` list) all for
  free, since everything downstream of `AGENT_REGISTRY` is generic.
- If asked to make scan execution async/background: this is the flagged,
  deferred piece from this session (see Known Issues) — would need an
  actual task queue (Celery+Redis, or something lighter like FastAPI
  `BackgroundTasks` + a polling status endpoint if full durability isn't
  needed). Treat as a real architectural addition, not a small tweak.
- If asked to require API auth or otherwise harden the API for shared/
  production deployment: `API_KEY` enforcement is already built (`src/
  api.py`'s `require_api_key` dependency) — just needs `API_KEY` to
  actually be set wherever it's deployed. The K8s Deployment example
  already does this via a Secret.
- **Never let an agent (or now, an API deployment) default/guess a port,
  path, endpoint, or bind address that could resolve to something wider
  than intended.** This session's API bind-address default is a direct
  continuation of that standing rule, applied to a new kind of component.

### Possible next steps
1. Async scan execution (task queue) if scan durations or concurrent load
   become a real problem
2. Require `API_KEY` by default once this is deployed anywhere beyond a
   single developer's machine
3. Slack/Jira alerting (extends `src/alerting.py`)
4. Deeper findings — real CVE matching against detected software versions
5. Auth/attestation trail — who authorized a scan, when, against what scope
6. Actual multi-tenancy, if this ever serves more than one org
7. Install `nmap`/`semgrep` locally (outside Docker) to live-verify those
   code paths on this dev machine too
8. `llm-cybersec-dvwa` container still running as the standing lab target

### Warnings/Cautions
- Never add a target to scope.yaml that isn't personally owned/authorized.
- Do not loosen `_run_tool`'s allowlist check or add `shell=True` anywhere.
- Do not let any agent (or API endpoint) default/guess a port, path, or
  bind address that isn't explicitly scoped/configured.
- Do not make `AiTriageAnalyzer` or alerting run without explicit opt-in,
  and never let AI-generated output be mistaken for deterministic tool
  output without the AI-GENERATED label.
- Do not let dry-run writes touch `data/history.db`.
- Do not write a literal credential into `alerts.yaml` or any committed
  file — env-var-name indirection only.
- Do not let `compliance`/`seen_by` affect dedup or diff identity if
  either is refactored.
- Do not change `src/api.py`'s default bind address to `0.0.0.0` "for
  convenience" — that's the exact mistake this session's design explicitly
  guards against. If broader exposure is genuinely needed, that's a
  `--host`/`API_HOST` choice made explicitly at run time, not a new default.
