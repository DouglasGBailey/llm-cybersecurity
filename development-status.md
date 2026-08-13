# Development Status - LLM Cybersecurity Agent Platform

## Last Updated
**Date**: 2026-08-13
**Session Duration**: Multi-session build (6 sessions in one day)
**Claude Code Session**: Platform complete — all 6 scanning agents + Evidence Collector + Report Generator implemented, tested, and live-verified; then added AiTriageAnalyzer (the one genuinely AI-powered, opt-in component) after user asked "in what ways is it AI-powered?"

## Current Project State

### What's Working — the platform is feature-complete
All planned components from the original architecture are implemented,
unit-tested, and live-verified against a real local lab:

- **`ScopeGuard`** (`src/scope_guard.py`) — the safety backbone. Two
  independent scope lists: `authorized_targets` (network, IP/hostname/CIDR,
  with exclusions) and `authorized_code_paths` (local filesystem, for
  `CodeAnalyzer`). Nothing runs against anything not explicitly listed.
- **`BaseAgent`** (`src/agent_base.py`) — allowlisted-tool subprocess
  execution (no `shell=True`, timeout-enforced), rate limiting per
  `scope.yaml`'s `max_scan_rate`, dry-run mode, uniform `AgentResult`.
- **`ReconAgent`** — dig + whois + capped nmap (`-sV --script=default
  --top-ports 100`). Degrades gracefully if `nmap` isn't installed.
- **`WebAppAnalyzer`** — missing security headers, server banner,
  robots.txt disallow list, generator meta tag / page title fingerprinting.
- **`ApiAnalyzer`** — OpenAPI/Swagger spec discovery, missing-security-scheme
  flagging, GraphQL introspection detection, verbose-error-page detection.
- **`InfraAnalyzer`** — TLS cert expiry inspection (via `cryptography`, not
  `openssl` subprocess) + SPF/DMARC/DNSSEC checks via `dig`. TLS check
  **only runs when a target has `tls_port` explicitly set** — never
  guesses a port (see "Key lesson learned" below).
- **`CodeAnalyzer`** — static analysis of a local directory via `bandit`
  (required) + `semgrep` (optional). Path-based, not network-based —
  authorized via `authorized_code_paths`.
- **`LlmSecurityAnalyzer`** — 3 built-in (config-overridable via
  `config/llm_probes.yaml`) harmless prompt-injection/jailbreak probes,
  checked against a canary fail-marker string. For testing your own LLM
  app, not third-party models.
- **`EvidenceCollector`** (`src/agents/evidence_collector.py`) — aggregates
  an orchestrator run's `AgentResult` list into a deduplicated evidence
  bundle (identical findings from different agents merged, `seen_by`
  tracked), with per-type/per-agent summary counts.
- **`ReportGenerator`** (`src/agents/report_generator.py`) — renders the
  evidence bundle as Markdown, findings grouped by a severity heuristic
  (high/medium/low/info — see `SEVERITY_BY_TYPE`), plus a raw JSON
  appendix.
- **`AiTriageAnalyzer`** (`src/agents/ai_triage_analyzer.py`) — the ONE
  genuinely AI-powered component. Shells out to the `claude` CLI with the
  evidence bundle, asking for a prioritized triage narrative (top
  priorities, remediation order, cross-finding patterns, overall
  assessment). Opt-in via `--ai-triage` on the orchestrator (costs Claude
  usage, sends evidence to Anthropic's API). Output always written to its
  own `<target>-ai-triage.md` file with an explicit AI-GENERATED
  disclaimer — never blended into the deterministic `report.md`. See
  "Why AiTriageAnalyzer exists" below for the context that prompted it.
- **`orchestrator.py`** — CLI entry point (`python -m src.orchestrator
  --scope ... --target ... [--agents recon,webapp,api,infra,code,llm]
  [--code-path PATH] [--execute] [--ai-triage]`). Dry-run by default. After
  the agent loop, always writes three files to `reports/`:
  `<target>-results.json`, `<target>-evidence.json`, `<target>-report.md`,
  plus `<target>-ai-triage.md` if `--ai-triage` is passed.
- Structured JSON logging (`logs/agent-activity.jsonl`) via
  `src/logging_setup.py` — every tool/request invocation with timestamps.

### Why AiTriageAnalyzer exists
After the platform was otherwise complete, the user asked "in what ways is
it AI-powered?" — a fair challenge, since every agent up to that point
(including `LlmSecurityAnalyzer`, despite its name) is deterministic
rule-based code with zero LLM calls. The honest answer was: none of the
scanning/aggregation/reporting logic is AI-powered; only the human+Claude-
Code loop driving the CLI from outside counted as "AI." The user chose
option 1 (an LLM-powered triage/summarization step) and specified it
should use Claude Code itself (the `claude` CLI) rather than a raw
Anthropic API key — since this environment already has `claude`
installed/authenticated, that avoids a second credential to manage and
keeps the "Claude Code building Claude Code-adjacent tooling" framing
consistent with the rest of the session.

### Testing Status
**68/68 tests passing** (`pytest tests/ -v`), no live network, installed
security tools, or live `claude` CLI calls required to run the suite:
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
| `test_report_generator.py` | 5 |

Recon/infra tests mock `subprocess.run`; webapp/api/llm tests mock HTTP via
`responses`; infra's TLS check is tested via `patch.object(_fetch_peer_cert)`
with real self-signed certs built via `cryptography`; evidence/report tests
are pure-function, no mocking needed; ai_triage tests mock `subprocess.run`
the same way recon does (the `claude` CLI is just another allowlisted
binary as far as `BaseAgent._run_tool` is concerned).

### Live Verification
A DVWA container (`llm-cybersec-dvwa`, `vulnerables/web-dvwa`, port 8080)
runs as the standing local lab target (`config/scope.yaml`'s `local-dvwa`
entry). Full platform run confirmed end-to-end:
```
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa \
  --agents recon,webapp,api,infra,llm --execute
```
produced real findings (missing security headers, Apache version banner,
DNS resolution, graceful `nmap`/TLS/API-surface absence handling) and all
three output files (`results.json`, `evidence.json`, `report.md`) —
`report.md` correctly grouped findings by severity and deduplicated
nothing spurious. `CodeAnalyzer` was separately run live against this
project's own `src/` (an `authorized_code_paths` self-scan) and found 2
real bandit findings (subprocess-usage flags, expected/mitigated).

Then re-ran with `--ai-triage` added:
```
python -m src.orchestrator --scope config/scope.yaml --target local-dvwa \
  --agents recon,webapp,api,infra,llm --execute --ai-triage
```
This made a real `claude -p` call against the actual evidence bundle. The
narrative it produced was genuinely good: correctly identified DVWA as a
deliberately-vulnerable app that shouldn't be network-reachable outside a
lab, correlated missing-headers + no-TLS + outdated-Apache-banner into one
coherent "under-hardened target" story, flagged the `nmap`-unavailable gap
as reducing recon confidence, and correctly noted the LLM/API checks came
back clean. Written to `reports/local-dvwa-ai-triage.md` with the
AI-GENERATED disclaimer comment at the top.

### Key lesson learned this build (codified as a standing rule)
**Never let an agent default/guess a port, path, or endpoint that could
resolve to something outside the intended target on a shared host.**
`InfraAnalyzer`'s TLS check originally defaulted to port 443; live-tested
against `local-dvwa` (`127.0.0.1`, DVWA is plain HTTP on 8080), it silently
connected to and reported the *real* certificate of a completely unrelated
service also listening on `127.0.0.1:443` on this shared dev host. Fixed
by requiring `tls_port` to be explicit in `scope.yaml` — an unset port
means "skip the check," never "assume a default." A regression test
(`test_no_port_given_skips_tls_check_without_guessing`) guards this. Any
future agent needing a port/path the scope entry doesn't already specify
must require it explicitly or skip with a recorded reason.

### Known Issues / Limitations
- `nmap` is not installed on this dev machine — `ReconAgent`'s port/service
  scan step has not been live-tested with a real nmap run here (only
  `dig`/`whois` have). Install `nmap` before relying on that step live.
- `semgrep` is optional and not installed — `CodeAnalyzer`'s bandit path is
  the one that's been live-verified; semgrep's `tool-unavailable`
  graceful-degradation path is tested but not exercised with a real
  semgrep run.
- `LlmSecurityAnalyzer`'s fail-marker matching is a simple substring
  heuristic (documented limitation) — for real system-prompt-leak testing,
  plant a unique canary token in your app's actual system prompt and use
  that as a `fail_marker` in `config/llm_probes.yaml` rather than relying
  on generic phrasing.
- `EvidenceCollector`'s deduplication is exact-content-match only (same
  `type` + all other fields identical across agents) — near-duplicate
  findings with slightly different detail (e.g. two agents phrasing the
  same fact differently) won't be merged. Acceptable for this build; a
  future improvement could dedupe by `(type, key_fields)` instead of full
  content equality.

## Architecture Decisions
- **Scope file as sole authority**: `ScopeGuard` is the only code path that
  can authorize a target (network) or path (code); agents/orchestrator
  never make their own scope decisions.
- **Hard per-agent tool allowlists**: `BaseAgent._run_tool()` raises
  `DisallowedToolError` for any binary not in that agent's `allowed_tools`.
  Enforced in code, not just convention.
- **No `shell=True` anywhere**: all subprocess calls use list-form args.
- **Dry-run default**: orchestrator requires an explicit `--execute` flag.
- **Sequential agent execution**: not parallel, to keep aggregate request
  rate against lab targets low and predictable.
- **No default ports/paths that could resolve outside the target** — see
  "Key lesson learned" above.
- **Two independent scope lists, matched to two different kinds of claim**:
  `authorized_targets` (network) vs. `authorized_code_paths` (filesystem)
  — "I'm allowed to scan this host" and "I own this codebase" are
  different authorizations and shouldn't be conflatable.
- **Evidence/Report generation is generic over `AgentResult.findings`**:
  `EvidenceCollector`/`ReportGenerator` don't know about specific agents —
  a new agent needs zero changes to either to have its findings show up
  correctly in reports (only an optional `SEVERITY_BY_TYPE` entry if a
  non-default severity is wanted).
- **AI-generated content is opt-in and never unlabeled**: `AiTriageAnalyzer`
  only runs with `--ai-triage`, and its output always goes to a separate
  file (`<target>-ai-triage.md`) with an explicit disclaimer comment at the
  top — it is never merged into the deterministic `report.md` in a way that
  could make AI-generated text look like tool output. Provenance stays
  unambiguous.
- **Use the `claude` CLI, not a raw API key**: `AiTriageAnalyzer` shells out
  to `claude -p` rather than calling the Anthropic API directly. In a
  Claude Code environment `claude` is already installed and authenticated,
  so this avoids managing a second credential and reuses the allowlisted-
  subprocess pattern already established by `ReconAgent`/`CodeAnalyzer`.

## File Structure Status
- `src/scope_guard.py`, `src/agent_base.py`, `src/logging_setup.py`,
  `src/orchestrator.py` — core
- `src/agents/{recon_agent,webapp_analyzer,api_analyzer,infra_analyzer,
  code_analyzer,llm_security_analyzer,evidence_collector,
  report_generator,ai_triage_analyzer}.py` — all 9 implemented, no stubs
  remain
- `config/scope.yaml` — `local-dvwa` target → live `llm-cybersec-dvwa`
  container, `web_port: 8080`, `tls_port` intentionally unset;
  `authorized_code_paths` → this project's own `src/`
- `config/scope.example.yaml`, `config/llm_probes.example.yaml` — templates
- `tests/` — 68 tests across 10 files, all passing, no live network or
  `claude` CLI calls required
- `reports/` — gitignored; populated by orchestrator runs
  (`results.json`/`evidence.json`/`report.md`, plus `ai-triage.md` if
  `--ai-triage` was passed, per target)

### Dependencies
`requirements.txt`: requests, beautifulsoup4, pyyaml, dnspython,
cryptography, bandit, pytest, responses. `nmap` and `semgrep` are optional
system/pip installs, not in `requirements.txt`. `AiTriageAnalyzer` requires
the `claude` CLI to be installed and authenticated (not a pip dependency —
it's the Claude Code CLI itself, confirmed present at
`/home/webadmin/.local/bin/claude` in this environment).

## Notes for Next Session

### Context for a new Claude session
- The platform is feature-complete per the original architecture, plus one
  opt-in AI-powered triage step added after the user asked what was
  actually "AI-powered" about it. Nothing is blocked or half-implemented.
- If asked to add a new agent: follow the `BaseAgent` pattern (see README's
  "Adding a new agent" section), register in `AGENT_REGISTRY`
  (`src/orchestrator.py`), add to `PATH_BASED_AGENTS` if it's filesystem-
  based like `CodeAnalyzer`. `EvidenceCollector`/`ReportGenerator` need no
  changes.
- If asked to add more AI-powered functionality: follow
  `AiTriageAnalyzer`'s pattern (shell out to `claude -p`, keep it opt-in,
  keep output in a clearly-labeled separate file) rather than blending
  LLM-generated content into the deterministic pipeline's output.
- **Never let an agent default/guess a port, path, or endpoint that could
  resolve to something other than the intended target on a shared host.**
  This dev machine runs many unrelated Docker services on the same
  loopback IP — see "Key lesson learned" above for the incident that
  established this rule.

### Possible next steps (none blocking, all optional)
1. Install `nmap` and `semgrep` locally to live-verify their code paths
2. Add an HTML report renderer alongside Markdown if a shareable
   non-Markdown format is wanted
3. Consider whether `AiTriageAnalyzer`'s prompt should be user-customizable
   (like `config/llm_probes.yaml` is for `LlmSecurityAnalyzer`) if different
   triage framing is wanted per use case
4. `llm-cybersec-dvwa` container is left running; `docker stop
   llm-cybersec-dvwa` when no longer needed, or keep it as the standing
   lab target

### Warnings/Cautions
- Never add a target to scope.yaml that isn't personally owned/authorized —
  hard ethical/legal boundary for the whole project, not a style preference.
- Do not loosen `_run_tool`'s allowlist check or add `shell=True` anywhere.
- Do not let any agent default/guess a port, path, or endpoint that isn't
  explicitly scoped.
- Do not make `AiTriageAnalyzer` (or any future AI-powered step) run by
  default, and do not let its output be written anywhere that could be
  mistaken for deterministic tool output without the AI-GENERATED label.

### Possible next steps (none blocking, all optional)
1. Install `nmap` and `semgrep` locally to live-verify their code paths
   (currently only tested via mocks + graceful-degradation)
2. Add an HTML report renderer alongside the Markdown one in
   `ReportGenerator` if a shareable non-Markdown format is wanted
3. Wire `EvidenceCollector` to also attach the relevant slice of
   `logs/agent-activity.jsonl` for a given run (mentioned in the original
   design, deferred as non-essential — evidence.json already has full
   findings + raw agent output)
4. `llm-cybersec-dvwa` container is left running; `docker stop
   llm-cybersec-dvwa` when no longer needed, or keep it as the standing
   lab target

### Warnings/Cautions
- Never add a target to scope.yaml that isn't personally owned/authorized —
  hard ethical/legal boundary for the whole project, not a style preference.
- Do not loosen `_run_tool`'s allowlist check or add `shell=True` anywhere.
- Do not let any agent default/guess a port, path, or endpoint that isn't
  explicitly scoped.
