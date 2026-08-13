# Technical Specification — LLM Cybersecurity Agent Platform

See `FUNCTIONAL_SPEC.md` for what the system does and why. This document
covers how it is built: architecture, data models, module responsibilities,
storage, APIs, deployment, and testing strategy. Reflects the codebase as
of this writing (~2,740 lines across `src/`, 140 tests).

## 1. Architecture overview

```
                          ┌─────────────────┐
                          │   config/        │
                          │   scope.yaml     │  (gitignored, operator-owned)
                          └────────┬─────────┘
                                   │ loaded by
                                   ▼
                          ┌─────────────────┐
                          │  ScopeGuard      │  sole authorization authority
                          └────────┬─────────┘
                                   │ authorizes
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                     ▼
     ┌──────────────┐     ┌──────────────┐      ┌──────────────┐
     │  Scanning     │     │ ExploitAgent  │      │ CodeAnalyzer  │
     │  agents (x6)  │     │ (separately   │      │ (path-scope,  │
     │  BaseAgent    │     │  scoped)      │      │  not network) │
     └──────┬────────┘     └──────┬────────┘      └──────┬────────┘
            │  AgentResult list   │                       │
            └───────────┬─────────┴───────────────────────┘
                         ▼
                ┌─────────────────┐
                │ EvidenceCollector│  dedup + compliance tagging
                └────────┬─────────┘
                         │ evidence bundle (dict)
         ┌───────────────┼────────────────┬─────────────────┐
         ▼               ▼                ▼                 ▼
 ┌───────────────┐ ┌──────────┐  ┌────────────────┐ ┌────────────────┐
 │ HistoryStore + │ │ Report   │  │ AiTriageAnalyzer│ │  alerting.py   │
 │  diff_engine   │ │ Generator│  │  (opt-in)       │ │  (opt-in)      │
 └────────┬───────┘ └──────────┘  └────────────────┘ └────────────────┘
          │
          ▼
  ┌───────────────┐
  │  dashboard.py  │  reads history across all targets
  └───────────────┘

Entry points:  src/orchestrator.py (CLI: run_scan())  ←──┐
               src/api.py (FastAPI, calls run_scan() directly)
```

Two entry points (`orchestrator.main()` for the CLI, `api.create_scan()`
for HTTP) both call the same `run_scan()` function — there is exactly one
place the scan-execution logic lives, avoiding drift between the two.

## 2. Core abstractions

### 2.1 `ScopeGuard` (`src/scope_guard.py`, 231 lines)

The single authority on what any agent is allowed to touch. No other
module makes an authorization decision independently.

**Three independent scope lists**, each answering a different question:

| List | Question answered | Key type | Load-time validation |
|---|---|---|---|
| `authorized_targets` | Can I recon/scan this network host? | `AuthorizedTarget` | none beyond required fields |
| `authorized_code_paths` | Can I statically analyze this local path? | `str` (path) | none |
| `authorized_exploit_targets` | Can I exploit this host? | `ExploitTarget` | **every entry must have `resettable: true`, or the whole scope file fails to load** |

```python
@dataclass
class AuthorizedTarget:
    name: str
    host: str
    notes: str = ""
    web_port: int | None = None
    tls_port: int | None = None

@dataclass
class ExploitTarget:
    name: str
    host: str
    resettable: bool
    known_vulnerabilities: dict = field(default_factory=dict)
    notes: str = ""
    web_port: int | None = None
```

**Host matching** supports exact match and CIDR ranges
(`ipaddress.ip_network`), resolving hostnames via `socket.getaddrinfo`.
`excluded` entries are checked first and short-circuit a match even
within an otherwise-authorized CIDR range.

**Key methods:**
- `resolve_target(name)` / `resolve_exploit_target(name)` — lookup by
  the scope file's friendly `name`, raising `OutOfScopeError` if absent.
- `authorize(host)` / `authorize_exploit(host)` — raise
  `OutOfScopeError` unless the literal host is covered. Called as the
  *first line* of every agent's `run()` method, defensively, even when
  the caller already resolved the target via `resolve_*` (belt-and-braces
  — cheap, and keeps every agent's authorization check structurally
  identical regardless of how it was invoked).
- `is_path_authorized(path)` / `authorize_path(path)` — path must resolve
  to a location at or under a configured `authorized_code_paths` entry.

### 2.2 `BaseAgent` (`src/agent_base.py`, 110 lines)

Abstract base every scanning/exploitation agent subclasses.

```python
class BaseAgent(ABC):
    name: str
    allowed_tools: list[str] = []          # subprocess allowlist
    default_timeout_seconds: int = 60

    def __init__(self, scope_guard: ScopeGuard, dry_run: bool = True): ...

    @abstractmethod
    def run(self, target) -> AgentResult: ...

    def _run_tool(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Refuses to execute any binary not in self.allowed_tools.
        Never shell=True. Always has a timeout. No-ops (returns an empty
        CompletedProcess) in dry-run mode."""

    def _respect_rate_limit(self) -> None:
        """Sleeps as needed to stay under scope.yaml's max_scan_rate."""
```

`AgentResult` is the uniform output type every agent produces:

```python
@dataclass
class AgentResult:
    agent_name: str
    target: str
    timestamp: str
    status: str                              # "ok" | "error"
    findings: list[dict] = field(default_factory=list)
    raw_output: list[str] = field(default_factory=list)
    error: str | None = None
```

A finding is an untyped dict with at minimum a `"type"` key; individual
agents attach whatever additional fields are relevant to that finding
type. This looseness is deliberate — `EvidenceCollector`,
`ReportGenerator`, `diff_engine`, and `dashboard.py` are all written to be
generic over arbitrary finding shapes, so adding a new agent or finding
type requires no changes to any downstream consumer.

### 2.3 Agent target types

Not every agent takes the same kind of "target," and `run()`'s parameter
type varies accordingly — a deliberate deviation from strict Liskov
substitution, since forcing every agent into a `run(target: str)` shape
would make several of them lie about what they operate on:

| Agent group | `run()` parameter |
|---|---|
| Recon, WebApp, API, Infra, LLM Security | `str` — `host` or `host:port` |
| `CodeAnalyzer` | `str` — a local filesystem path |
| `ExploitAgent` | `ExploitTarget` — the full scope-resolved object, since it needs `known_vulnerabilities` |

## 3. The six scanning agents

All in `src/agents/`, all pure functions of (target, scope) → findings,
no shared mutable state between runs.

| Agent | File / lines | External tools (`allowed_tools`) |
|---|---|---|
| `ReconAgent` | `recon_agent.py`, 66 | `dig`, `whois`, `nmap` |
| `WebAppAnalyzer` | `webapp_analyzer.py`, 96 | none (pure `requests`/`bs4`) |
| `ApiAnalyzer` | `api_analyzer.py`, 159 | none |
| `InfraAnalyzer` | `infra_analyzer.py`, 154 | `dig` (TLS via stdlib `ssl`+`cryptography`, not `openssl` subprocess) |
| `CodeAnalyzer` | `code_analyzer.py`, 109 | `bandit`, `semgrep` |
| `LlmSecurityAnalyzer` | `llm_security_analyzer.py`, 158 | none |

Any tool listed but not installed on the host produces a
`tool-unavailable` finding rather than crashing the run (checked via
`shutil.which` before invocation).

**Notable design point — `InfraAnalyzer` never assumes a default TLS
port.** If a target has no `tls_port` configured, the certificate check
is skipped and recorded as `tls-check-skipped`, never silently defaulted
to 443. This exists because of a real incident during development: on a
shared multi-tenant host, defaulting to 443 caused the agent to fetch and
report an unrelated service's real TLS certificate instead of the
intended lab target's (which had no TLS listener at all). The fix —
require the port explicitly or skip — is enforced in code and treated as
a standing rule for any future agent that might need to guess a
port/path/endpoint.

## 4. `ExploitAgent` (`src/agents/exploit_agent.py`, 243 lines)

The one agent that performs live exploitation. Architecturally distinct
from the six scanning agents in several ways:

- Scoped via `authorized_exploit_targets`, not `authorized_targets` (§2.1).
- Config-driven, not auto-discovering: `known_vulnerabilities` in the
  resolved `ExploitTarget` declares exactly which paths/params/technique
  details to test. No fuzzing, no parameter discovery.
- Builds a `requests.Session()` per run so an optional login step
  (`_setup_auth`) can establish cookies/session state that later modules
  reuse.

**Modules** (each independently triggered by the presence of its key in
`known_vulnerabilities`):

```python
ALLOWED_COMMANDS = {"whoami", "id", "hostname", "uname -a", "pwd"}
```

| Module | Technique | Confirmation logic |
|---|---|---|
| `_setup_auth` | POST login form (+ optional CSRF token scraped from a hidden field), then optional follow-up requests | n/a — sets up session state |
| `_run_sqli` | UNION-based injection: `' UNION SELECT {union_select} FROM {from_table} -- -` | Compares extracted `<pre>` blocks against a **baseline** (non-injected) request; differs → exploited |
| `_run_xss` | Injects `<script>document.title='xsspoc'</script>` | Payload appears **unescaped** (verbatim) in response HTML |
| `_run_command_injection` | `<benign-input>; <command>` for each `command` in config's `allowed_commands` **intersected with `ALLOWED_COMMANDS`** | Compares response `<pre>` blocks against a **baseline** (non-injected) request — see design note below |
| `_run_credentials` | Tries each `[user, pass]` in config's `candidates` | `success_indicator` string present in response; **stops at first success** |

**Design note — why command injection needed a baseline diff.** An
initial version considered any non-empty response "exploited," which is
wrong whenever the vulnerable endpoint always echoes *some* output
regardless of injection (e.g. DVWA's command-exec page always runs a
`ping` and shows its output, injected or not). Live testing against the
actual target caught this — the fix mirrors the SQLi module's approach:
only output that *differs from a same-shaped baseline request* proves the
injected command specifically ran. A regression test
(`test_command_injection_not_flagged_when_output_matches_baseline`) locks
this in.

**Hard-coded, non-configurable limits** (enforced in code, not docs):
SQLi payload construction only ever builds `SELECT`/`UNION` — no
write/delete verbs are ever assembled. Command injection commands are
filtered against `ALLOWED_COMMANDS` before use; anything outside it is
recorded as an `error` finding and never sent. These sets are Python
constants, not reachable from YAML config.

## 5. Aggregation layer

### 5.1 `EvidenceCollector` (`src/agents/evidence_collector.py`, 57 lines)

```python
class EvidenceCollector:
    def collect(self, results: list[AgentResult]) -> dict:
        ...
```

Algorithm: for each finding across all `AgentResult`s, compute a content
hash (`json.dumps(finding, sort_keys=True)`) as a dedup key. First
occurrence of a key creates the canonical record; subsequent occurrences
just append the observing agent's name to that record's `seen_by` list.
Compliance tags (`compliance_mapping.compliance_tags_for(finding["type"])`)
are attached **after** the hash is computed, so they never affect
identity/dedup.

Returns:
```python
{
  "generated_at": iso8601_str,
  "targets": [str, ...],
  "agents_run": [str, ...],
  "summary": {
    "total_findings_raw": int, "total_findings_deduplicated": int,
    "by_type": {finding_type: count}, "by_agent": {agent_name: count},
  },
  "findings": [ {..., "seen_by": [...], "compliance": [...]}, ... ],
  "agent_results": [AgentResult.to_dict(), ...],
}
```

### 5.2 `diff_engine` (`src/diff_engine.py`, 44 lines)

Pure function, no I/O:

```python
def compute_diff(previous_findings, current_findings, is_first_run: bool) -> dict:
    # returns {is_first_run, new_findings, resolved_findings,
    #          unchanged_findings, has_new_findings}
```

Same content-hash approach as `EvidenceCollector`, but strips **both**
`seen_by` and `compliance` before hashing — neither is part of a
finding's identity across time (which agent observed it, and what
compliance tags it currently carries, can both change without the
underlying finding being "different"). `has_new_findings` is hard-coded
`False` when `is_first_run` is true — a baseline scan is never itself an
alert-worthy event, even though every finding in it is technically "new."

### 5.3 `HistoryStore` (`src/history_store.py`, 73 lines)

SQLite, one table:
```sql
CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    findings_json TEXT NOT NULL
)
```
`findings_json` stores `evidence["findings"]` (the deduplicated,
compliance-tagged list) as-is. `get_previous_run(target_name)` returns
the most recent row by `id DESC LIMIT 1`, or `None`. Default location:
`data/history.db`, gitignored.

**Not written to on dry-run scans** — dry-run findings are
placeholders/skip-markers, and recording them would corrupt the diff
baseline used for real scans.

### 5.4 `ReportGenerator` (`src/agents/report_generator.py`, 157 lines)

```python
class ReportGenerator:
    def generate(self, evidence: dict, diff: dict | None = None) -> str:
        ...  # returns a Markdown string
```

Severity is a lookup table (`SEVERITY_BY_TYPE`) plus special-cased
handling for `bandit-finding`/`semgrep-finding` (severity comes from the
underlying tool's own rating). Findings are grouped and rendered in
`high → medium → low → info` order. When `diff` is provided and isn't a
first-run, a "Changes Since Last Scan" section is inserted listing new/
resolved findings. A "Compliance Coverage" section aggregates
`(framework, control)` pairs across all findings, sorted by count.

### 5.5 `compliance_mapping` (`src/compliance_mapping.py`, 99 lines)

A static dict, `COMPLIANCE_MAP: dict[str, list[dict[str, str]]]`, mapping
~14 of the ~30 possible finding types to one or more
`{"framework": ..., "control": ...}` tags. Deliberately incomplete —
purely informational finding types (`dns-resolution`, `page-title`, ...)
have no entry rather than a forced mapping. Primary framework is OWASP
Top 10 2021; secondary (CIS Controls v8 / PCI DSS 4.0) where a clear
mapping exists; LLM-specific findings map to the OWASP Top 10 for LLM
Applications instead.

### 5.6 `AiTriageAnalyzer` (`src/agents/ai_triage_analyzer.py`, 105 lines)

The only component that invokes an LLM. Shells out to the `claude` CLI
(`_run_tool(["claude", "-p", prompt, ...])`, reusing `BaseAgent`'s
allowlisted-subprocess machinery) with a prompt containing the evidence
bundle, asking for a Markdown triage narrative. Opt-in
(`--ai-triage`/`ai_triage=True`); output is always written to its own
file (`<target>-ai-triage.md`) prefixed with an HTML comment disclaiming
it as AI-generated — never merged into the deterministic `report.md`.

## 6. `alerting.py` (111 lines)

```python
def send_alerts(target_name: str, diff: dict, config_path=DEFAULT_ALERTS_CONFIG) -> list[str]:
    ...  # returns e.g. ["email"], or [] if not configured / no new findings
```

Opt-in via file presence: `load_alert_config` returns `None` if
`config/alerts.yaml` doesn't exist, and `send_alerts` no-ops in that case.
SMTP via stdlib `smtplib`; `username_env`/`password_env` in config are
**environment variable names**, resolved via `os.environ` at send time —
never a literal credential in the (gitignored) config file. Any exception
during sending is caught, logged, and swallowed — `send_alerts` never
raises, so a broken mail server can never fail a scan run.

## 7. `dashboard.py` (231 lines)

```python
def generate_dashboard(scope_path, history_db_path=DEFAULT_DB_PATH, reports_dir=DEFAULT_REPORTS_DIR) -> str:
    ...  # returns a full, self-contained HTML document
```

For each `authorized_targets` entry: pulls up to 30 recent runs via
`HistoryStore.get_run_history`, renders a finding-count trend as a
hand-computed inline SVG polyline (`_sparkline_svg` — no charting
library/CDN dependency), the latest run's severity breakdown (reusing
`report_generator._severity_for`), the latest `<target>-diff.json` from
disk if present, and a compliance-coverage summary. No live server; the
CLI (`python -m src.dashboard`) and the API's `GET /dashboard` both just
call `generate_dashboard()` and return the string fresh each time.

## 8. `src/orchestrator.py` (287 lines) — the shared scan-execution core

```python
def run_scan(
    guard: ScopeGuard,
    authorized_target: AuthorizedTarget,
    agent_keys: list[str],
    code_path: str | None = None,
    exploit_target: ExploitTarget | None = None,
    execute: bool = False,
    ai_triage: bool = False,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
    history_db_path: str | Path = DEFAULT_DB_PATH,
) -> dict:
```

This is the single implementation of "run some agents, aggregate,
diff, report, maybe alert, maybe AI-triage" — both `main()` (CLI) and
`src/api.py`'s `create_scan()` call it directly. Returns a dict with
`exit_code`, `results`, `evidence`, `diff`, `report`,
`ai_triage_narrative`, `alerted_channels`, and a `paths` dict of every
file written.

**`AGENT_REGISTRY`** maps CLI/API agent-key strings to classes:
```python
AGENT_REGISTRY = {
    "recon": ReconAgent, "webapp": WebAppAnalyzer, "api": ApiAnalyzer,
    "infra": InfraAnalyzer, "code": CodeAnalyzer, "llm": LlmSecurityAnalyzer,
    "exploit": ExploitAgent,
}
PATH_BASED_AGENTS = {"code"}       # dispatched with a filesystem path
EXPLOIT_AGENTS = {"exploit"}       # dispatched with an ExploitTarget,
                                    # requires a separate scope resolution
```

**Exit codes** (module constants `EXIT_OK`/`EXIT_CONFIG_ERROR`/
`EXIT_NEW_FINDINGS`):

| Code | Meaning |
|---|---|
| `0` | Success; no new findings (or first run) |
| `1` | Scope/config/argument error, or (this session) exploit-target not separately authorized |
| `3` | Success; new findings appeared since the last run — the hook external schedulers use to alert |

**`main()`** (CLI shell): parses `argparse` flags, loads `ScopeGuard`,
resolves the target (and, if `exploit` was requested, additionally
resolves + validates the exploit target — **before running any agent**,
failing fast), calls `run_scan()`, returns its exit code.

## 9. `src/api.py` (199 lines) — REST API

FastAPI app, `uvicorn` ASGI server. Config is read from environment
variables **at request time** (`_scope_path()`, `_reports_dir()`,
`_history_db_path()` functions, not module-level constants) specifically
so tests can `monkeypatch.setenv` per-test without any dependency-
injection machinery.

| Method & path | Auth required (if `API_KEY` set) | Notes |
|---|---|---|
| `GET /health` | never | liveness-probe friendly |
| `GET /targets` | yes | lists `authorized_targets` |
| `POST /scans` | yes | body: `{target, agents, execute, code_path, ai_triage}`; synchronous; resolves `exploit_target` and 403s if `exploit` requested without authorization |
| `GET /scans/{target}/report` | yes | `text/markdown` |
| `GET /scans/{target}/evidence` | yes | JSON |
| `GET /scans/{target}/diff` | yes | JSON, 404 if none yet |
| `GET /dashboard` | yes | regenerated fresh every call |

**Auth model**: `require_api_key` (a FastAPI `Depends`) is a no-op if
`API_KEY` is unset; if set, every non-health endpoint requires
`Authorization: Bearer <API_KEY>` or returns `401`. A `lifespan` context
manager logs a startup warning when unauthenticated. **`main()`'s CLI
entry point defaults to binding `127.0.0.1`** (`--host`/`API_HOST` env
var override it) — auth is opt-in per product decision, but the bind
address default means exposing the API beyond the local machine is
always a deliberate action, never an accident.

## 10. Deployment

### 10.1 Container (`Dockerfile`, `.dockerignore`)

`python:3.12-slim` base; installs `nmap`, `dnsutils` (for `dig`), `whois`
via `apt`; `pip install -r requirements.txt` (includes `bandit`). `CMD`
runs `uvicorn src.api:app --host 0.0.0.0 --port 8000` — `0.0.0.0` here is
correct/standard for a container (exposure is controlled by `docker run
-p`'s host-side address, not the in-container bind). Real
`scope.yaml`/`alerts.yaml`/`data/`/`reports/`/`logs/` are **not** baked
into the image — mounted as volumes.

### 10.2 Kubernetes (`k8s/*.example.yaml`)

Two illustrative, **unvalidated** manifests (no cluster available in
development to test against): `scan-job.example.yaml` (a one-shot `Job`
mirroring `scripts/run-scheduled-scan.sh`'s use case — note `backoffLimit:
0`, since exit code 3 is informational, not a failure to retry past) and
`api-deployment.example.yaml` (`Deployment` + `Service`, sourcing
`API_KEY` from a `Secret` — unlike local/dev use, a cluster-reachable API
should not run unauthenticated).

### 10.3 Scheduling (`scripts/run-scheduled-scan.sh`)

No built-in scheduler daemon. The wrapper script activates the venv, runs
the orchestrator with `--execute`, and propagates its exit code —
cron/systemd own the actual schedule and act on the exit code (see
`README.md` for concrete crontab/systemd-timer examples).

## 11. Storage summary

| Store | Technology | Location | Committed to git? |
|---|---|---|---|
| Scope/config | YAML | `config/scope.yaml`, `config/alerts.yaml`, `config/llm_probes.yaml` | No — gitignored, operator-specific. `.example.yaml` templates are committed. |
| Scan history | SQLite | `data/history.db` | No |
| Reports | JSON + Markdown + HTML files | `reports/` | No |
| Activity log | JSONL | `logs/agent-activity.jsonl` | No |

## 12. Testing strategy

140 tests across 17 files, zero live network/tool/API-key dependencies:

| Technique | Used for |
|---|---|
| Mock `subprocess.run` | `ReconAgent`, `CodeAnalyzer`, `InfraAnalyzer` (dig calls), `AiTriageAnalyzer` (the `claude` CLI) |
| `responses` library (mocked HTTP) | `WebAppAnalyzer`, `ApiAnalyzer`, `LlmSecurityAnalyzer`, `ExploitAgent` |
| `patch.object` on an isolated method | `InfraAnalyzer._fetch_peer_cert` — real self-signed certs built with `cryptography` for the TLS-parsing test, without mocking raw sockets |
| Real temp SQLite file (`tmp_path`) | `HistoryStore` |
| Pure function tests, no I/O | `diff_engine`, `compliance_mapping` |
| Mock `smtplib.SMTP` + `monkeypatch.setenv` | `alerting` |
| FastAPI `TestClient` (in-process, no real server) | `api.py` |

No dedicated `orchestrator.py` unit test file — `run_scan()`/`main()` are
verified live against the real DVWA lab container instead, on the
principle that the orchestrator's job is wiring already-tested components
together, and that wiring is best proven by actually running it.

CI: GitHub Actions (`.github/workflows/tests.yml`), `pytest tests/ -v` on
push/PR to `master`, `ubuntu-latest`, Python 3.12 — no external services,
so it's fast and hermetic.

## 13. Dependencies

```
requests, beautifulsoup4, pyyaml, dnspython, cryptography, bandit,
fastapi, uvicorn, pytest, responses, httpx
```
All in `requirements.txt`. `sqlite3` and `smtplib` are Python stdlib.
Optional, not pinned as dependencies: `nmap`, `semgrep`, the `claude` CLI
— each agent that uses one degrades gracefully (a `tool-unavailable`
finding) if it's absent.

## 14. Threat model / security design summary

- **Untrusted input surfaces**: `scope.yaml` (operator-controlled, but
  still validated — malformed/unsafe entries are rejected at load time,
  not just at use time) and, for `ExploitAgent`, the
  `known_vulnerabilities` config (which selects *from* hardcoded
  allowlists, never expands them).
- **No `shell=True`** anywhere in the codebase — all subprocess
  invocations use list-form arguments.
- **No arbitrary command execution path** — `BaseAgent._run_tool`
  enforces a per-agent binary allowlist; `ExploitAgent`'s command
  injection module additionally enforces a hardcoded command-content
  allowlist on top of that.
- **No arbitrary SQL** — `ExploitAgent`'s SQLi module only ever
  constructs `SELECT`/`UNION` statements.
- **Credentials never at rest in config** — `alerting.py`'s SMTP
  credentials and any future similar integration are environment-variable
  references, resolved only at send time.
- **Fail-closed on missing authorization** — every capability's default
  behavior on an unauthorized target is to raise before acting, not to
  warn-and-continue.
- **API surface defaults to least exposure** — localhost-only bind by
  default when run directly on a host; auth is available but not forced
  on for local/dev use (a deliberate, documented product tradeoff, not an
  oversight).
