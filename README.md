# LLM Cybersecurity Agent Platform

[![Tests](https://github.com/DouglasGBailey/llm-cybersecurity/actions/workflows/tests.yml/badge.svg)](https://github.com/DouglasGBailey/llm-cybersecurity/actions/workflows/tests.yml)

A controlled, multi-agent security assessment platform for learning to build
scoped, auditable security automation — not a "hack anything" LLM wrapper.

## Ethics & Scope — read this first

This tool will **refuse to run against any target that is not explicitly
listed** in your `config/scope.yaml`. Only add targets you personally own or
are explicitly authorized to test (your own lab VMs/containers, an active
HackTheBox/TryHackMe VPN range, etc).

- No agent performs exploitation, brute force, or denial-of-service actions.
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
├── Evidence Collector     [working]  aggregates AgentResult -> evidence.json
├── Report Generator       [working]  evidence.json -> Markdown report
└── AI Triage Analyzer     [working]  evidence.json -> Claude-written narrative (opt-in)
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

Run a subset of agents (available: `recon`, `webapp`, `api`, `infra`, `code`, `llm`):

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

## Testing

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

84/84 tests passing as of this build (scope guard: 12, recon agent: 5, web
app analyzer: 5, api analyzer: 7, infra analyzer: 9, code analyzer: 7, llm
security analyzer: 8, evidence collector: 5, report generator: 9, ai
triage analyzer: 5, history store: 6, diff engine: 6). All tests mock
subprocess/HTTP calls or use a temp SQLite file — no live network access
or installed security tools (including no live `claude` CLI calls) are
required to run the suite.

## Adding a new agent

The pattern established by the six scanning agents:

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
4. `EvidenceCollector`/`ReportGenerator` need no changes — they consume any
   agent's `AgentResult.findings` generically. If a new finding `type`
   deserves a non-default severity, add it to `SEVERITY_BY_TYPE` in
   `src/agents/report_generator.py`.
