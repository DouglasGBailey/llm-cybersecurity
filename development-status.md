# Development Status - LLM Cybersecurity Agent Platform

## Last Updated
**Date**: 2026-08-13
**Session Duration**: Multi-session build (7 sessions in one day)
**Claude Code Session**: Full platform built (6 scanning agents + Evidence
Collector + Report Generator + opt-in AI Triage), then extended with
scheduled scanning + diffing (SQLite run history, new/resolved-finding
detection, exit-code-based alerting) as the first step toward commercial
viability.

## Current Project State

### What's Working — feature-complete platform + scheduled scanning
All planned components are implemented, unit-tested, and live-verified
against a real local lab (DVWA container):

**Scanning agents** (all subclass `BaseAgent`, `src/agent_base.py`, all
scope-checked via `ScopeGuard` before touching anything):
- `ReconAgent` — dig + whois + capped nmap. Degrades gracefully if `nmap`
  isn't installed.
- `WebAppAnalyzer` — missing security headers, server banner, robots.txt,
  fingerprinting.
- `ApiAnalyzer` — OpenAPI/Swagger discovery, GraphQL introspection,
  verbose-error detection.
- `InfraAnalyzer` — TLS cert expiry (via `cryptography`) + SPF/DMARC/DNSSEC.
  TLS check **only runs with an explicit `tls_port`** — never guesses a
  port (see "Key lesson learned" below, still the platform's most
  important safety precedent).
- `CodeAnalyzer` — bandit (required) + semgrep (optional) over a local
  path, authorized via a separate `authorized_code_paths` scope list.
- `LlmSecurityAnalyzer` — 3 built-in (config-overridable) prompt-injection/
  jailbreak probes against a user-owned LLM app endpoint.

**Aggregation & reporting** (not scanning agents — consume `AgentResult`
lists directly, no scope/network/tool concerns):
- `EvidenceCollector` (`src/agents/evidence_collector.py`) — deduplicates
  findings across agents by content, per-type/per-agent summary counts.
- `ReportGenerator` (`src/agents/report_generator.py`) — Markdown report,
  findings grouped by severity heuristic, **plus a "Changes Since Last
  Scan" section when a diff is passed** (new this session).
- `AiTriageAnalyzer` (`src/agents/ai_triage_analyzer.py`) — the one
  genuinely AI-powered piece. Shells out to the `claude` CLI for a
  prioritized narrative. Opt-in (`--ai-triage`), output always in its own
  clearly-labeled file, never blended into the deterministic report.

**Scheduled scanning + diffing** (new this session):
- `HistoryStore` (`src/history_store.py`) — SQLite-backed
  (`data/history.db`, gitignored), one row per run per target
  (`target_name`, `timestamp`, `findings_json`). `save_run`,
  `get_previous_run`, `get_run_history`.
- `diff_engine.compute_diff` (`src/diff_engine.py`) — pure function,
  content-based finding identity (same approach `EvidenceCollector` uses,
  minus `seen_by` since which agent saw something isn't part of a
  finding's identity across runs). Returns `new_findings`,
  `resolved_findings`, `unchanged_findings`, `has_new_findings`.
  `has_new_findings` is deliberately `False` on the first run for a target
  (nothing to compare against yet — no false alert on the baseline).
- `orchestrator.py` — on every `--execute` run (not dry-run — dry-run
  produces no real findings and would corrupt the baseline), fetches the
  previous run, computes the diff, saves the current run, writes
  `reports/<target>-diff.json`, and passes the diff into
  `ReportGenerator`. Exit codes: `0` = success/no new findings/first run,
  `1` = scope/config/argument error (unchanged from before), `3` = success
  but new findings appeared since last run — the hook for alerting.
- `scripts/run-scheduled-scan.sh` — thin wrapper for cron/systemd (no
  built-in scheduler daemon by design): activates venv, runs the
  orchestrator with `--execute`, propagates the exit code.

**Core infrastructure** (unchanged this session):
- `ScopeGuard` (`src/scope_guard.py`) — two independent scope lists:
  `authorized_targets` (network) and `authorized_code_paths` (filesystem).
- `BaseAgent` (`src/agent_base.py`) — allowlisted-tool subprocess
  execution, rate limiting, dry-run mode, uniform `AgentResult`.
- Structured JSON logging (`logs/agent-activity.jsonl`).

### Testing Status
**84/84 tests passing** (`pytest tests/ -v`), no live network, installed
security tools, or live `claude` CLI calls required:
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
| `test_evidence_collector.py` | 5 |
| `test_report_generator.py` | 9 (was 5 — +4 for the diff section) |
| `test_history_store.py` | 6 (new) |
| `test_diff_engine.py` | 6 (new) |

`test_history_store.py` uses a real temp SQLite file (via `tmp_path`), not
mocks — genuinely exercises the DB layer. `test_diff_engine.py` is pure
function tests, no I/O.

### Live Verification (this session — scheduled scanning + diffing)
Ran a 4-run cycle against `local-dvwa` with a fresh `data/history.db`:
1. **Run 1** (`webapp,infra`): `is_first_run: true`, exit code `0`. Baseline
   established (5 findings recorded).
2. **Run 2** (same agents, unchanged target): `0 new, 0 resolved, 5
   unchanged`, exit code `0`.
3. **Run 3** (added `code` agent scanning this project's own `src/`): `3
   new, 0 resolved, 5 unchanged`, **exit code `3`** — correctly detected
   the 3 new bandit/tool-unavailable findings, and the report's "Changes
   Since Last Scan" section correctly listed them.
4. **Run 4** (via `scripts/run-scheduled-scan.sh`, back to `webapp,infra`
   only): `0 new, 3 resolved, 5 unchanged`, exit code `0` — confirmed
   resolved-finding detection (the 3 code findings disappeared since `code`
   wasn't run) and confirmed the wrapper script propagates the
   orchestrator's exit code correctly. Also confirmed resolved-only diffs
   don't trigger exit code 3 (only *new* findings alert, by design).

All four runs' `diff.json` and `report.md` output inspected directly and
matched expectations exactly.

### Key lesson learned (still the platform's standing safety rule)
**Never let an agent default/guess a port, path, or endpoint that could
resolve to something outside the intended target on a shared host.**
`InfraAnalyzer`'s TLS check originally defaulted to port 443; live-tested
against `local-dvwa` on this shared dev host, it silently connected to and
reported the *real* certificate of a completely unrelated service also on
`127.0.0.1:443`. Fixed by requiring `tls_port` to be explicit in
`scope.yaml`. This remains the reference incident for "why we're careful
about defaults" whenever a new agent or feature touches ports/paths.

### Known Issues / Limitations
- `nmap` and `semgrep` are optional/not installed on this dev machine —
  their code paths are tested via mocks but not exercised with real binary
  runs here.
- `LlmSecurityAnalyzer`'s fail-marker matching is a simple substring
  heuristic — use a real canary token for reliable system-prompt-leak
  detection (documented in `config/llm_probes.example.yaml`).
- `EvidenceCollector`'s dedup is exact-content-match only — near-duplicate
  findings phrased slightly differently across agents won't merge.
- **No alerting integration yet** — scheduled scanning ends at "exit code
  3 + a diff file." Wiring that into email/Slack/Jira is deliberately
  deferred (see "What's Next").
- **No web dashboard, no compliance framework mapping, no multi-tenancy**
  — all flagged in the original "what would make this commercially viable"
  discussion as separate, larger pieces of work not started yet.

## Architecture Decisions
- **Scope file as sole authority**; **hard per-agent tool allowlists**; **no
  `shell=True` anywhere**; **dry-run default**; **sequential agent
  execution**; **no default ports/paths that could resolve outside the
  target**; **two independent scope lists** (network vs. filesystem);
  **evidence/report generation generic over `AgentResult.findings`**; **AI-
  generated content is opt-in and never unlabeled** — all established in
  prior sessions, unchanged.
- **History/diffing skipped in dry-run mode**: dry-run agents produce
  placeholder/skip findings, not real data — recording those as a "run"
  would poison the baseline that diffing depends on. History only updates
  on `--execute`.
- **Diff identity strips `seen_by`**: `EvidenceCollector` tracks which
  agent(s) observed each finding, but that's run-specific metadata, not
  part of what makes two findings "the same finding" across time — a
  finding newly co-observed by a second agent shouldn't register as "new."
- **First run never alerts**: `has_new_findings` is hardcoded `False` when
  `is_first_run` is true, even though every finding is technically new —
  there's no baseline yet to meaningfully call something "new," and
  alerting on every target's first-ever scan would be noise, not signal.
- **New findings only, not resolved findings, trigger exit code 3**: a
  finding disappearing is good news, not something to page anyone about.
  Both are recorded in the diff either way — just not both alert-worthy.
- **No scheduler daemon**: the orchestrator stays one-shot; cron/systemd
  own the schedule via `scripts/run-scheduled-scan.sh`. Chosen explicitly
  over building a long-running Python process, to avoid a second thing
  that needs to be kept running/monitored.

## File Structure Status
- `src/scope_guard.py`, `src/agent_base.py`, `src/logging_setup.py`,
  `src/orchestrator.py`, `src/history_store.py`, `src/diff_engine.py` —
  core
- `src/agents/{recon_agent,webapp_analyzer,api_analyzer,infra_analyzer,
  code_analyzer,llm_security_analyzer,evidence_collector,
  report_generator,ai_triage_analyzer}.py` — all 9 implemented, no stubs
- `scripts/run-scheduled-scan.sh` — cron/systemd entry point (new)
- `config/scope.yaml` — `local-dvwa` target → live `llm-cybersec-dvwa`
  container, `web_port: 8080`, `tls_port` unset; `authorized_code_paths` →
  this project's own `src/`
- `config/scope.example.yaml`, `config/llm_probes.example.yaml` — templates
- `tests/` — 84 tests across 12 files, all passing
- `data/` — gitignored; `history.db` created on first `--execute` run
- `reports/` — gitignored; `results.json`/`evidence.json`/`report.md`/
  `diff.json` (+ `ai-triage.md` if requested) per target

### Dependencies
`requirements.txt`: requests, beautifulsoup4, pyyaml, dnspython,
cryptography, bandit, pytest, responses. `sqlite3` is Python stdlib — no
new dependency for history/diffing. `nmap`, `semgrep`, and the `claude` CLI
remain optional system installs, not in `requirements.txt`.

## Notes for Next Session

### Context for a new Claude session
- The platform now covers: scan → aggregate → report → (optional AI
  triage) → (on `--execute`) diff against history → exit-code signal. This
  was step one of a broader "what makes this commercially viable"
  conversation — see the other candidates below.
- If asked to add a new scanning agent: same pattern as always (see
  README's "Adding a new agent"). It automatically gets diffing for free —
  `HistoryStore`/`diff_engine` operate on `evidence["findings"]`, which is
  generic across agents.
- If asked to add alerting (email/Slack/Jira): the natural hook is
  `EXIT_NEW_FINDINGS` (`src/orchestrator.py`) and `reports/<target>-
  diff.json` — build a notifier that reads the diff file when the exit
  code is 3, rather than adding notification logic inside the orchestrator
  itself (keep the one-shot-CLI-plus-external-wiring pattern established
  by the cron/systemd approach).
- **Never let an agent default/guess a port, path, or endpoint that could
  resolve to something other than the intended target on a shared host.**
  Standing rule, established the hard way — see "Key lesson learned."

### Possible next steps
From the original "commercially viable" discussion, roughly in priority
order, with scheduled scanning + diffing (this session) now done:
1. **Compliance framework mapping** — tag findings against OWASP Top
   10/CIS/SOC 2 controls
2. **Alerting integration** (Slack/email/Jira) — natural follow-on to this
   session's exit-code hook
3. **Web dashboard** — trend lines over `HistoryStore`'s data, historical
   reports, multi-target rollup
4. **Deeper findings** — real CVE matching against detected software
   versions, not just banner flags
5. **Auth/attestation trail** — who authorized a scan, when, against what
   scope
6. Install `nmap` and `semgrep` locally to live-verify those code paths
7. `llm-cybersec-dvwa` container still running as the standing lab target;
   `docker stop llm-cybersec-dvwa` when no longer needed

### Warnings/Cautions
- Never add a target to scope.yaml that isn't personally owned/authorized.
- Do not loosen `_run_tool`'s allowlist check or add `shell=True` anywhere.
- Do not let any agent default/guess a port, path, or endpoint that isn't
  explicitly scoped.
- Do not make `AiTriageAnalyzer` (or any AI-powered step) run by default,
  and never let AI-generated output be mistaken for deterministic tool
  output without the AI-GENERATED label.
- Do not let dry-run writes touch `data/history.db` — would corrupt the
  diff baseline for real scans. (Already guarded in `orchestrator.py` —
  keep it that way if refactoring.)
