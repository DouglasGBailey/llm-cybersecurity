# LLM Cybersecurity Agent Platform

[![Tests](https://github.com/DouglasGBailey/llm-cybersecurity/actions/workflows/tests.yml/badge.svg)](https://github.com/DouglasGBailey/llm-cybersecurity/actions/workflows/tests.yml)

A controlled, multi-agent security assessment platform for learning to build
scoped, auditable security automation — not a "hack anything" LLM wrapper.

## Ethics & Scope — read this first

This tool will **refuse to run against any target that is not explicitly
listed** in your `config/scope.yaml`. Only add targets you personally own or
are explicitly authorized to test (your own lab VMs/containers, an active
HackTheBox/TryHackMe VPN range, etc).

- The six scanning agents (Recon through LLM Security) perform read-only
  enumeration and hygiene checks only — no exploitation, no brute force,
  no denial-of-service.
- Real exploitation exists in one place, `ExploitAgent`, and is gated far
  more tightly than everything else: it requires a **separate**
  `authorized_exploit_targets` entry (being allowed to recon-scan a host
  does not authorize exploiting it), and that entry must declare
  `resettable: true` — enforced at scope-file load time, not just
  documented — because full exploitation (real data extraction, real
  command execution) is only justified against a target you can tear down
  and recreate. See "Exploitation (ExploitAgent)" below for the full
  design, including the hard lines it never crosses regardless of config
  (no destructive SQL, no arbitrary commands, no credential brute-forcing).
- Every agent's allowed tools/commands are hard-coded (`allowed_tools`) — an
  LLM directing this platform cannot expand what an agent is permitted to do.
- Every action is logged to `logs/agent-activity.jsonl`.
- The orchestrator defaults to `--dry-run`; you must pass `--execute` to run
  anything for real.

## Architecture

```
Security Auditor Agent (orchestrator.py)
│
├── Recon Agent            [working]  nmap / dig / whois
├── Web App Analyzer       [working]  HTTP headers, robots.txt, fingerprinting
├── API Analyzer           [working]  OpenAPI/GraphQL discovery, verbose-error detection
├── Infrastructure Analyzer[working]  TLS cert hygiene, SPF/DMARC/DNSSEC checks
├── Code Analyzer          [working]  bandit / semgrep over a local path
├── LLM Security Analyzer  [working]  prompt-injection / jailbreak probe suite
├── Exploit Agent          [working]  config-driven SQLi/XSS/cmd-injection/weak-creds exploitation (opt-in, separately scoped)
├── Evidence Collector     [working]  aggregates AgentResult -> evidence.json (+ compliance tags)
├── Report Generator       [working]  evidence.json -> Markdown report (+ compliance, diff sections)
└── AI Triage Analyzer     [working]  evidence.json -> Claude-written narrative (opt-in)

Supporting modules (not scanning agents):
├── history_store.py       SQLite run history, keyed by target
├── diff_engine.py         new/resolved/unchanged findings vs. last run
├── alerting.py            email alert on new findings (opt-in, SMTP)
├── compliance_mapping.py  finding type -> OWASP/CIS/PCI control tags
├── dashboard.py           static HTML dashboard over history.db
└── api.py                 REST API wrapping orchestrator.run_scan()
```

All six scanning agents plus Evidence Collector and Report Generator are
implemented — this completes the platform sketched in the original design.

### Is this actually "AI-powered"?

Mostly no, and that's deliberate. Every scanning agent (Recon, WebApp, API,
Infra, Code, LLM Security) plus Evidence Collector and Report Generator are
**fully deterministic, rule-based code** — regex parsing, header presence
checks, date arithmetic, substring matching. No LLM call, no judgment call,
fully auditable. That was the point of the original design: restricted,
predictable agent logic instead of "ChatGPT, hack this server."

The **one** genuinely AI-powered piece is `AiTriageAnalyzer`
(`src/agents/ai_triage_analyzer.py`), enabled with `--ai-triage`. It shells
out to the `claude` CLI (already installed/authenticated in a Claude Code
environment) with the evidence bundle and asks for a prioritized,
human-readable triage narrative — risk ranking, remediation order, and
cross-finding patterns the deterministic agents can't reason about (e.g.
correlating "missing HSTS" + "no TLS port configured" into one "transport
security needs attention" observation). It's opt-in because it sends
evidence data to Anthropic's API and consumes your Claude usage, and its
output is always written to a separate file with an explicit
AI-GENERATED disclaimer — never blended into the deterministic
`report.md` without attribution.

Every agent subclasses `BaseAgent` (`src/agent_base.py`):
- `run(target)` must call `ScopeGuard.authorize(target)` before doing anything
- `_run_tool(cmd)` refuses to execute any binary not in that agent's
  `allowed_tools` list, and enforces the scope file's `max_scan_rate`
- Every agent's result is a uniform `AgentResult` (agent name, target,
  timestamp, findings, raw output, status)

`ScopeGuard` (`src/scope_guard.py`) is the single source of truth for what's
in-scope — it resolves hostnames, checks CIDR membership, and honors
exclusions. No other part of the codebase makes scope decisions. Local
source-code paths (for Code Analyzer) are authorized separately via
`authorized_code_paths` — "I own this codebase" is a different claim than
"I'm allowed to scan this network host."

### Compliance framework mapping

`EvidenceCollector` tags each finding with the compliance controls it maps
to (`src/compliance_mapping.py`) — primarily OWASP Top 10 2021, plus a
second framework (CIS Controls v8 or PCI DSS 4.0) where a clear mapping
exists, and the OWASP Top 10 for LLM Applications for `LlmSecurityAnalyzer`
findings. Not every finding type is mapped — pure informational findings
(`dns-resolution`, `page-title`, ...) intentionally have no tag; inventing
one would be noise. `report.md` shows tags inline on each finding plus a
"Compliance Coverage" summary (which controls this scan actually touches,
by finding count). This is metadata, not identity — it never affects
dedup (`EvidenceCollector`) or diffing (`diff_engine`).

## Setup

```bash
cd llm-cybersecurity
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config/scope.example.yaml config/scope.yaml
# Edit config/scope.yaml: list only targets you own/are authorized to test
```

`nmap` must be installed separately for the Recon Agent's port scan step
(`dig`/`whois` are typically preinstalled on Linux). `bandit` is installed
via `requirements.txt`; `semgrep` is optional (heavier, and
`--config=auto` fetches community rules over the network) — install it
separately with `pip install semgrep` if you want it. Any missing tool
degrades gracefully and records a `tool-unavailable` finding instead of
crashing.

## Usage

Dry run (default — prints planned actions, executes nothing):

```bash
source venv/bin/activate
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa
```

Live run against an authorized target:

```bash
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa --execute
```

Run a subset of agents (available: `recon`, `webapp`, `api`, `infra`, `code`, `llm`, `exploit`):

```bash
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa --agents webapp,api --execute
```

Code Analyzer scans a local path, not the network target, so it needs
`--code-path` and a matching `authorized_code_paths` entry in `scope.yaml`:

```bash
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa --agents code --code-path ./src --execute
```

If a target's web app / API lives on a non-80 port, add `web_port:` to its
entry in `scope.yaml` — the `webapp` and `api` agents will use it
automatically (see `config/scope.example.yaml`).

Infra Analyzer's TLS certificate check **never guesses a port** (e.g. 443)
— it only runs when a target has `tls_port:` explicitly set. This matters
on a shared host: an authorized bare IP does not authorize probing every
port on it, since unrelated real services may be listening elsewhere on
that same address. Leave `tls_port` unset to skip the TLS check entirely
(it still runs the SPF/DMARC/DNSSEC DNS checks).

LLM Security Analyzer sends a small set of harmless prompt-injection/
jailbreak probes (POST `{"message": "<probe>"}`) to a target's LLM app
endpoint and checks the response for a canary string that should never
appear if the app correctly resists the probe. It's for testing **your
own** deployed LLM app, not attacking a third-party model. The
request/response shape is app-specific — the default assumes a JSON POST
and looks for common response field names (or OpenAI-style
`choices[0].message.content`); customize probes (and canary tokens for
system-prompt-leak detection) in `config/llm_probes.yaml` — see
`config/llm_probes.example.yaml`.

## Exploitation (ExploitAgent)

Everything above is enumerate-and-flag. `ExploitAgent` is different: it
proves impact — real SQL injection data extraction, real reflected-XSS
confirmation, real command execution, real login with weak/default
credentials — against a target you've separately, explicitly authorized
for it.

**It does not discover vulnerabilities.** It executes declared, known
techniques against declared, known endpoints, read from
`known_vulnerabilities` in a scope.yaml `authorized_exploit_targets`
entry. Auto-discovery/fuzzing would be a much larger undertaking and
drifts toward "autonomous hacking tool" — the opposite of this project's
founding idea of restricted, declarative agents you build yourself rather
than "ChatGPT, hack this server."

**Authorization is separate and stricter than recon.** Being listed in
`authorized_targets` (so `webapp`/`api`/etc. can scan a host) does **not**
authorize `ExploitAgent` against it. A target needs its own
`authorized_exploit_targets` entry, and that entry **must** set
`resettable: true` — `ScopeGuard` refuses to even load a scope file where
an exploit-target entry is missing this. `resettable: true` is not a
formality: it's the reason full exploitation (real data extraction, real
command execution) is acceptable here at all — the target is a disposable
container you can tear down and recreate, not something where a mistake
has lasting consequences.

```yaml
authorized_exploit_targets:
  - name: local-dvwa
    host: 127.0.0.1
    web_port: 8080
    resettable: true          # required -- ScopeGuard rejects the file without this
    notes: "docker container -- docker rm + re-run to reset"
    known_vulnerabilities:
      auth_setup:              # optional: log in (+ follow-up requests) before other modules run
        login_path: /login.php
        username_field: username
        password_field: password
        username: admin
        password: password
        csrf_field: user_token
        extra_fields: {Login: Login}
        post_login_requests:
          - path: /security.php
            data: {security: low, seclev_submit: Submit}
      sqli:
        - path: /vulnerabilities/sqli/
          param: id
          union_select: "user,password"   # SELECT-only -- never write/delete
          from_table: users
      xss:
        - path: /vulnerabilities/xss_r/
          param: name
      command_injection:
        - path: /vulnerabilities/exec/
          param: ip
          allowed_commands: [whoami, hostname]   # must be a subset of ALLOWED_COMMANDS in code
      credentials:
        login_path: /login.php
        username_field: username
        password_field: password
        csrf_field: user_token
        extra_fields: {Login: Login}
        success_indicator: "Logout"
        candidates:                       # a handful of common defaults, NOT a wordlist
          - [admin, password]
          - [admin, admin]
```

**Hard lines that are not config-overridable** (see
`src/agents/exploit_agent.py` for where these are enforced in code):
- **SQL injection is read-only.** `union_select`/`from_table` build a
  `SELECT`/`UNION` payload only — this agent never constructs
  `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`.
- **Command injection only ever runs a command from a hardcoded
  allowlist** (`ALLOWED_COMMANDS` — `whoami`, `id`, `hostname`, `uname -a`,
  `pwd`). A command in a target's `allowed_commands` config that isn't in
  that hardcoded set is rejected and never sent — config can *select
  from* what this agent will attempt, never *expand* it.
- **Credential testing tries the configured `candidates` and stops at the
  first success.** This is default/weak-credential confirmation, not a
  brute-force/wordlist attack — mass credential stuffing risks account
  lockouts and reads as a DoS-adjacent technique even when authorized.

Run it like any other agent, but note it takes its own
`--target`-resolved `authorized_exploit_targets` entry, checked *before*
anything runs:

```bash
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa --agents exploit --execute
```

Findings (`sqli-exploited`, `xss-exploited`, `command-injection-exploited`,
`weak-credentials-exploited`) are all `HIGH` severity and mapped to OWASP
Top 10 2021 A03 (Injection) / A07 (Auth Failures) in the report like
everything else — `ReportGenerator`/`EvidenceCollector`/`dashboard.py`
needed zero changes to support this agent.

Every run writes to `reports/`:
- `<target-name>-results.json` — raw `AgentResult` list, one per agent run
- `<target-name>-evidence.json` — `EvidenceCollector`'s deduplicated bundle
  (findings merged across agents by content, with per-type/per-agent counts)
- `<target-name>-report.md` — `ReportGenerator`'s human-readable Markdown
  report, findings grouped by a simple severity heuristic (high/medium/low/
  info — see `SEVERITY_BY_TYPE` in `src/agents/report_generator.py`), plus
  a raw evidence appendix
- `<target-name>-diff.json` (on `--execute` runs only) — what changed since
  the last run for this target; see "Scheduled Scanning & Diffing" below

Add `--ai-triage` to also get `<target-name>-ai-triage.md` — a
Claude-written prioritized narrative over the same evidence bundle (see
"Is this actually AI-powered?" above). Requires the `claude` CLI to be
installed and authenticated:

```bash
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa --agents webapp,api,infra --execute --ai-triage
```

Full activity log (every tool/request invocation, with timestamps) is at
`logs/agent-activity.jsonl`.

## Scheduled Scanning & Diffing

Every `--execute` run is recorded in a local SQLite history
(`data/history.db`, one row per run per target) and diffed against that
target's most recent prior run. This is what makes running the tool
repeatedly actually useful — instead of re-reading a full report every
time, you get a `<target-name>-diff.json` and a "Changes Since Last Scan"
section in `report.md` showing only what's new or resolved. Dry runs don't
touch history — they produce no real findings, so diffing them would
corrupt the baseline for real scans.

The very first run for a target has nothing to diff against
(`is_first_run: true` in the diff, and no "Changes Since Last Scan" section
in the report) — that run establishes the baseline.

**Exit codes** (`src/orchestrator.py`) are how a scheduler knows whether to
alert:
| Code | Meaning |
|---|---|
| `0` | Success, no new findings since last run (or this was the first run) |
| `1` | Scope/config/argument error |
| `3` | Success, but **new findings appeared** since the last run |

There's no built-in scheduler daemon — the orchestrator stays a one-shot
CLI, and you run it on a schedule with cron or systemd, using
`scripts/run-scheduled-scan.sh` as the entry point (it activates the venv
and propagates the exit code):

```bash
# crontab -e — daily at 6am, mail on exit code 3 (new findings) via cron's default behavior
0 6 * * * /path/to/llm-cybersecurity/scripts/run-scheduled-scan.sh local-dvwa >> /path/to/llm-cybersecurity/logs/cron.log 2>&1 || echo "New findings detected" | mail -s "Scan alert: local-dvwa" you@example.com
```

Or with systemd (`~/.config/systemd/user/dvwa-scan.service` +
`dvwa-scan.timer`):

```ini
# dvwa-scan.service
[Unit]
Description=Scheduled security scan of local-dvwa

[Service]
Type=oneshot
ExecStart=/path/to/llm-cybersecurity/scripts/run-scheduled-scan.sh local-dvwa
```
```ini
# dvwa-scan.timer
[Unit]
Description=Run dvwa-scan.service daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```
Then check `systemctl --user status dvwa-scan.service` after a run — a
`Main PID exited, code=exited, status=3` means new findings appeared, which
you can hook into `OnFailure=` for a notification unit.

`data/` is gitignored — it's per-installation scan history of your
specific targets, not something to commit.

### Email alerting on new findings

Opt-in, like `--ai-triage`: copy `config/alerts.example.yaml` to
`config/alerts.yaml` and the orchestrator will email you whenever a diff
reports `has_new_findings` (i.e. on exit code `3`). With no `alerts.yaml`
present, alerting is silently skipped — no error, no configuration
required to use the rest of the platform.

```bash
cp config/alerts.example.yaml config/alerts.yaml
# edit config/alerts.yaml: smtp_host, smtp_port, from_addr, to_addrs
```

Credentials are never written into `alerts.yaml` directly — it references
environment variable *names* (`username_env`/`password_env`), resolved at
send time:

```bash
export ALERT_SMTP_USERNAME=your-smtp-username
export ALERT_SMTP_PASSWORD=your-smtp-password
```

Set these in whatever environment actually runs the scan (your shell,
cron's environment, or a systemd `EnvironmentFile=`). A send failure (bad
host, auth failure, network issue) is logged and swallowed — alerting can
never cause a scan run itself to fail.

## Dashboard

`python -m src.dashboard --scope config/scope.yaml` generates a
self-contained static HTML file (`reports/dashboard.html`, open directly
in a browser) — no live server, no new web-framework dependency, same
reasoning that ruled out a scheduler daemon. For each target in
`scope.yaml`: a finding-count trend (inline SVG sparkline, no chart
library) over recent runs from `data/history.db`, the latest run's
severity breakdown, the latest diff (new/resolved counts), compliance
coverage, and a link to that target's `report.md`. Targets with no run
history yet just show "No runs yet." Regenerate by re-running the command
after new scans.

## REST API

`src/api.py` (FastAPI) wraps the same `run_scan()` function the CLI uses —
one place the scan logic lives, two ways to trigger it. This is what
unlocks CI integration, a future UI, or running scans as Kubernetes Jobs
instead of shelling out to the CLI directly.

```bash
python -m src.api                    # defaults to 127.0.0.1:8000
python -m src.api --host 0.0.0.0 --port 8080   # explicit, deliberate exposure
```

| Method & path | Behavior |
|---|---|
| `GET /health` | `{"status": "ok"}` — always open, no auth |
| `GET /targets` | List `authorized_targets` from scope.yaml |
| `POST /scans` | Body: `{target, agents, execute, code_path, ai_triage}`. Runs synchronously, blocks until the scan finishes |
| `GET /scans/{target}/report` | The Markdown report |
| `GET /scans/{target}/evidence` | The evidence bundle JSON |
| `GET /scans/{target}/diff` | The diff JSON (`404` if no diff yet) |
| `GET /dashboard` | The dashboard HTML, regenerated fresh on every request |

Scan execution is **synchronous** for this first pass — a `POST /scans`
request blocks for the scan's duration. No task queue, matching the
platform's "don't add infrastructure before there's a real need for it"
precedent (the same reasoning that ruled out a scheduler daemon and a live
dashboard server elsewhere in this project).

**Auth is opt-in, not required**, for this first pass: set `API_KEY` to
require `Authorization: Bearer <key>` on every endpoint except `/health`.
With `API_KEY` unset, the API still works — but:
- it **binds to `127.0.0.1` by default** when run directly (`--host
  0.0.0.0` or `API_HOST` is a deliberate choice, not the default)
- it prints a loud startup warning: `API_KEY not set -- all endpoints are
  UNAUTHENTICATED. Do not bind beyond localhost without setting one.`

This exists because an earlier session accidentally exposed a *different*
local tool (the static dashboard server) on a public interface with no
auth in front of it. The localhost-default + visible warning here means
exposing this API beyond your own machine is always a deliberate action,
not an accident — while still respecting the explicit decision not to
require auth for local/dev use.

Config is read from env vars per-request: `SCOPE_PATH`, `REPORTS_DIR`,
`HISTORY_DB_PATH`, `API_KEY`, `API_HOST`, `API_PORT`.

## Docker

```bash
docker build -t llm-cybersecurity .
docker run -d --name llm-cybersecurity \
  -p 127.0.0.1:8000:8000 \
  -v $(pwd)/config/scope.yaml:/config/scope.yaml:ro \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/reports:/app/reports \
  -e API_KEY=your-key-here \
  llm-cybersecurity
```

The image installs `nmap`/`dig`/`whois`/`bandit`. `semgrep` and the
`claude` CLI (for `--ai-triage`) are not baked in — install them in a
custom image layer if you need those inside the container. `config/
scope.yaml`, `config/alerts.yaml`, `data/`, `reports/`, and `logs/` are
**not** part of the image (user-specific, gitignored) — mount them as
volumes, as shown above.

The `-p 127.0.0.1:8000:8000` above only publishes the port to your own
machine's loopback interface, even though the container's own `CMD` binds
`0.0.0.0` internally (that's correct/standard for a container — the
`0.0.0.0` there just means "accept connections arriving inside the
container," and `docker run -p`'s host-side address is what actually
controls external reachability). Change the host-side address deliberately
if you want it reachable beyond your own machine.

## Kubernetes

`k8s/scan-job.example.yaml` (a one-off `Job` running a single scan, the
K8s equivalent of `scripts/run-scheduled-scan.sh`) and `k8s/
api-deployment.example.yaml` (`Deployment` + `Service` for the API) are
**illustrative examples**, not tested against a real cluster (this project
has none to validate against) — adapt the image reference, secret names,
and PVC claims before using. This project deliberately hasn't invested
further in Kubernetes: the actual bottleneck for "enterprise-grade" right
now is auth/multi-tenancy/API surface (the API above is the first piece of
that), not compute scale. K8s earns its complexity once there's a real
need to run many concurrent, isolated scans — not before.

## Testing

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

140/140 tests passing as of this build (scope guard: 18, recon agent: 5,
web app analyzer: 5, api analyzer: 7, infra analyzer: 9, code analyzer: 7,
llm security analyzer: 8, exploit agent: 10, evidence collector: 7, report
generator: 13, ai triage analyzer: 5, history store: 6, diff engine: 6,
compliance mapping: 6, alerting: 8, dashboard: 6, REST API: 14). All tests
mock subprocess/HTTP/SMTP calls or use a temp SQLite file/scope file/
in-process FastAPI TestClient — no live network access, installed security
tools, a live `claude` CLI, an SMTP server, or a running API server are
required to run the suite. `ExploitAgent`'s tests mock HTTP the same way
`WebAppAnalyzer`/`ApiAnalyzer`'s do — no real exploitation happens in CI.

## Adding a new agent

The pattern established by the scanning agents:

1. Subclass `BaseAgent` (`src/agent_base.py`); `run(target)` must call
   `self.scope_guard.authorize(...)` (or `authorize_path(...)` for a
   filesystem-based agent like `CodeAnalyzer`) before doing anything, and
   declare a minimal `allowed_tools` list if it shells out
2. Register it in `AGENT_REGISTRY` in `src/orchestrator.py`, and in
   `PATH_BASED_AGENTS` if it takes a filesystem path instead of a network
   target
3. Add a test file mirroring `tests/test_recon_agent.py` (mock subprocess)
   or `tests/test_webapp_analyzer.py` (mock HTTP via the `responses`
   library) — no real network/tool calls in the test suite
4. `EvidenceCollector`/`ReportGenerator`/`diff_engine`/`dashboard` need no
   changes — they all consume any agent's `AgentResult.findings`
   generically. If a new finding `type` deserves a non-default severity,
   add it to `SEVERITY_BY_TYPE` in `src/agents/report_generator.py`; if it
   maps to a compliance control, add it to `COMPLIANCE_MAP` in
   `src/compliance_mapping.py` (optional — unmapped types just get no tag).
