# Development Status - LLM Cybersecurity Agent Platform

## Last Updated
**Date**: 2026-08-13
**Session Duration**: Multi-session build (10 sessions in one day)
**Claude Code Session**: Full recon/hygiene platform built and hardened
across prior sessions (6 scanning agents, evidence/report/AI-triage,
scheduled scanning + diffing, alerting, compliance mapping, dashboard,
containerization + REST API). This session: added real, config-driven
exploitation (`ExploitAgent`) after the user asked to add penetration-
testing/exploit capability — a genuine policy shift from the platform's
prior "no agent performs exploitation" stance, handled deliberately with
its own safety design rather than bolted onto the existing agent pattern.

## Current Project State

### What's Working — full recon/hygiene platform + real exploitation
All components implemented, unit-tested, live-verified against the real
DVWA lab (including, this session, actual working exploitation).

**Scanning agents** (`ReconAgent`, `WebAppAnalyzer`, `ApiAnalyzer`,
`InfraAnalyzer`, `CodeAnalyzer`, `LlmSecurityAnalyzer`) and supporting
modules (`EvidenceCollector`, `ReportGenerator`, `AiTriageAnalyzer`,
`HistoryStore`, `diff_engine`, `alerting`, `compliance_mapping`,
`dashboard`, `api`) — unchanged this session, see prior entries/README.

**This session — `ExploitAgent` (`src/agents/exploit_agent.py`):**

The user explicitly asked for penetration-testing/exploit capability. This
directly contradicted a written design principle (README's Ethics section
said "No agent performs exploitation"), so rather than silently reversing
it, I asked clarifying questions before building: exploitation depth (user
chose full — real data extraction, real command execution — specifically
because the target is *resettable*, a disposable container), vuln classes
(SQLi, XSS, command injection, auth/credential weaknesses), and scope
model (a separate `authorized_exploit_targets` list, not reuse of
`authorized_targets` — user confirmed this explicitly).

**Scope model** (`src/scope_guard.py`):
- New `ExploitTarget` dataclass: `name`, `host`, `resettable: bool`,
  `known_vulnerabilities: dict`, `notes`, `web_port`.
- `Scope.authorized_exploit_targets: list[ExploitTarget]`.
- **Load-time enforcement**: `ScopeGuard._load` raises `ScopeConfigError`
  immediately if any `authorized_exploit_targets` entry is missing
  `resettable: true` — the platform refuses to even load a scope file
  that tries to authorize full exploitation against a non-resettable
  target. Not just documented — enforced in code, matching every other
  safety rule in this codebase (the `tls_port`-must-be-explicit rule, the
  `authorized_code_paths` separation, etc.).
- New `resolve_exploit_target(name)` / `authorize_exploit(host)` methods,
  mirroring the recon-side `resolve_target`/`authorize` exactly.
- **Recon authorization does not imply exploit authorization**: a host in
  `authorized_targets` but not `authorized_exploit_targets` will scan fine
  but `ExploitAgent` will refuse it. Verified both in unit tests and live.

**Config schema — declared, not discovered**: `ExploitAgent` does NOT
auto-discover injectable parameters. `known_vulnerabilities` in a
target's scope entry declares exactly what to test (paths, params,
payload shape) — generic enough in code to fit any similarly-structured
app, with all DVWA-specific knowledge living in config, not code. This
was a deliberate design choice to avoid drifting toward "autonomous
hacking tool," the opposite of this project's founding principle
(literally the user's own framing at the very start of this whole
project: "you don't want to become dependent on 'ChatGPT, hack this
server' — build controlled security agents").

**Four exploitation modules, all pure `requests`/`BeautifulSoup` (no
subprocess, `allowed_tools: []`):**
- `_setup_auth` — optional login + follow-up requests (e.g. DVWA's
  security-level cookie) before other modules run. Scrapes a CSRF token
  from a hidden form field if configured.
- `_run_sqli` — UNION-based extraction (`union_select`/`from_table` in
  config build the payload). Confirms exploitation by comparing extracted
  `<pre>` blocks against a baseline (non-injected) request — not just
  "got a response."
- `_run_xss` — confirms exploitation by checking a `<script>` payload is
  reflected **unescaped** in the response HTML (the standard automated-
  tool bar for confirmed XSS; no headless browser in this pass, documented
  limitation — no live cookie-theft demo).
- `_run_command_injection` — **found and fixed a real bug during live
  testing** (see below). Confirms exploitation via baseline diff, same
  pattern as SQLi.
- `_run_credentials` — tries a small configured `candidates` list, stops
  at first success.

**Hard lines held regardless of configured "full" depth — not config-
overridable, enforced in code:**
- SQLi payloads are `SELECT`/`UNION` only — the agent never constructs
  `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`.
- Command injection only ever runs a command from a hardcoded
  `ALLOWED_COMMANDS` set (`whoami`, `id`, `hostname`, `uname -a`, `pwd`).
  A command in a target's config `allowed_commands` that isn't in that
  hardcoded set is rejected and never sent — config can *select from* what
  this agent will attempt, never *expand* it. Verified live: `rm -rf /`
  in config was rejected and logged as an `error` finding, never executed.
- Credential testing is a small curated list, not a wordlist/brute-force
  — stops at first success rather than continuing to enumerate.

**Orchestrator/API wiring**: `AGENT_REGISTRY["exploit"] = ExploitAgent`,
new `EXPLOIT_AGENTS = {"exploit"}` set. Both `main()` (CLI) and
`create_scan()` (`src/api.py`) resolve `guard.resolve_exploit_target(...)`
**before running any agent** when `"exploit"` is requested, failing fast
(CLI: `EXIT_CONFIG_ERROR`; API: `403`) if the target isn't separately
exploit-authorized. `run_scan()` gained an `exploit_target` parameter.

**Findings/severity/compliance**: `sqli-exploited`, `xss-exploited`,
`command-injection-exploited` → `HIGH` severity, OWASP Top 10 2021 A03
(Injection). `weak-credentials-exploited` → `HIGH`, OWASP A07
(Identification and Authentication Failures). Zero changes needed to
`EvidenceCollector`/`dashboard.py`/`diff_engine` — the "new agent needs
no downstream changes" design decision held even for this much larger
agent.

### Testing Status
**140/140 tests passing** (`pytest tests/ -v`), no live network required:
| File | Count |
|---|---|
| `test_scope_guard.py` | 18 (was 12 — +6 for exploit-target/resettable enforcement) |
| `test_exploit_agent.py` | 10 (new) |
| (all other files) | unchanged from prior session, 112 total |

`test_exploit_agent.py` mocks HTTP via `responses`, same pattern as
`WebAppAnalyzer`/`ApiAnalyzer` — no real exploitation happens in CI.
Notably includes a regression test
(`test_command_injection_not_flagged_when_output_matches_baseline`) for
the real bug found during live verification (see below) — this test
would have caught it before it ever reached a live run.

### Live Verification (this session) — the real payoff
Manually verified DVWA's actual page structure first (login form fields,
CSRF token field name, SQLi/XSS/exec page HTML) via raw `curl` before
writing the scope config, to ground the config in real target behavior
rather than guessing. Discovered DVWA's database had never been
initialized on this container — ran its own one-time setup wizard
(`setup.php`'s "Create / Reset Database") to fix that, a legitimate lab
setup step, not a workaround of anything.

**Found and fixed a real bug live**: the initial command-injection module
considered *any non-empty response* as proof of successful injection. But
DVWA's exec page always echoes a ping result whether or not the injected
command actually ran — so the original heuristic would have flagged
**every** attempt as "exploited," including ones that weren't. Manually
confirmed this by comparing baseline (`ip=127.0.0.1`, no injection) vs.
would-be-injected output — both looked "non-empty and successful" under
the old logic. Fixed by applying the same baseline-diff technique the
SQLi module already used: only a response that *differs* from the
baseline proves the injected command actually ran. Added a regression
test for this exact failure mode before re-running live.

**Full live exploitation run against `local-dvwa`** (`--agents exploit
--execute`), all four vulnerability classes confirmed with real data:
- **SQLi**: extracted all 5 real DVWA user rows (admin, gordonb, 1337,
  pablo, smithy) with real MD5 password hashes via UNION injection
- **XSS**: confirmed unescaped `<script>` reflection
- **Command injection**: captured real `whoami` output (`www-data`) and
  real `hostname` output (the actual container ID, `69a82652eded`) — and
  confirmed the disallowed `rm -rf /` command in config was rejected and
  never sent (0 requests for it, verified via call count)
- **Weak credentials**: confirmed `admin`/`password` (DVWA's real default)
  logs in successfully

Exit code `3` returned correctly (new findings). Report/compliance
rendering verified: all four finding types correctly grouped under
`### HIGH`, correct OWASP A03/A07 tags shown inline. Verified the
fail-fast safety check live too: requesting `--agents exploit` against
`local-juiceshop` (in `authorized_targets` but not
`authorized_exploit_targets`) failed immediately with a clear error and
`EXIT_CONFIG_ERROR`, before any request was sent.

### Known Issues / Limitations
- Carried forward from prior sessions (nmap/semgrep optional, LLM probe
  heuristic, exact-content dedup, compliance mapping intentionally
  partial, email-only alerting, static dashboard, opt-in API auth,
  synchronous scan execution, unvalidated K8s manifests).
- **XSS confirmation has no headless browser** — proves unescaped
  reflection (the standard automated-tool bar), not actual JS execution
  or session/cookie theft. Documented limitation, not a bug.
- **`ExploitAgent` is only live-verified against DVWA** — the config
  schema is generic in code, but no other target has been tested against
  it. A differently-structured app (different CSRF field name, different
  result-container HTML, etc.) would need its own `known_vulnerabilities`
  config and likely some real-world debugging the same way DVWA needed
  (the command-injection baseline-diff fix came directly from live
  testing, not from reading DVWA's source ahead of time).
- **Command injection / SQLi confirmation logic is baseline-diff, not
  semantic** — it detects "the response changed," not "the response
  changed *because of my payload specifically*." For DVWA this is
  reliable (the only variable between requests is the injected payload),
  but a target with any non-deterministic page content (timestamps,
  request IDs, ads) could produce false positives. Not hit here; worth
  keeping in mind if `ExploitAgent` is pointed at a less controlled target.

## Architecture Decisions
Carried forward unchanged from prior sessions (scope file as sole
authority, hard per-agent tool allowlists, no `shell=True`, dry-run
default, sequential execution, no default ports/paths, evidence/report
generic over findings, AI content opt-in and labeled, history/diffing
skipped in dry-run, diff identity strips derived metadata, first run never
alerts, only new findings trigger exit 3, no scheduler daemon, alerting
opt-in with swallowed failures, env-var credential indirection, static
dashboard, API auth opt-in with localhost-default bind, container
`0.0.0.0` vs. host `127.0.0.1` distinction, K8s deliberately minimal).

**New this session:**
- **A genuine policy change gets a genuine safety redesign, not a bolt-on
  flag.** Adding exploitation wasn't "extend `BaseAgent` and call it a
  day" — it got its own authorization list, its own load-time-enforced
  precondition (`resettable: true`), and hardcoded (not configurable)
  limits on the most dangerous primitives (arbitrary SQL, arbitrary
  commands, credential brute-forcing). When a request meaningfully changes
  what the system is allowed to do, the safety design should change with
  it, proportionally — not just "add the feature, keep the same guardrails
  that were sized for a different risk level."
- **`resettable: true` is the load-bearing justification, not a
  checkbox.** "Full exploitation is OK because you can reset the target"
  is a real, specific safety argument (mistakes have no lasting
  consequence), and the code reflects that argument directly — enforced
  at load time, not just mentioned in a docstring. If the reasoning
  changes (e.g. someone wants to point this at a non-resettable target),
  the code should force that conversation to happen explicitly, not
  silently go along with it.
- **Declared vulnerabilities, not discovered ones.** `ExploitAgent`
  reading a config-declared list of known endpoints/params, rather than
  probing/fuzzing to find injectable parameters itself, is a direct
  continuation of the project's original founding constraint (restricted,
  auditable sub-agents, not an LLM improvising its own attack). This was
  a deliberate design choice made while planning, before the user asked
  for it either way — worth preserving as precedent for any future
  "should this agent be smarter/more autonomous" question.
- **Hardcoded allowlists that config cannot expand.** The
  `ALLOWED_COMMANDS` set lives in Python code, not YAML — a target's
  config can select a subset of it, never add to it. This is a stronger
  guarantee than "the default config only has safe commands": even a
  compromised or careless scope.yaml edit can't turn this into an
  arbitrary-command-execution tool.
- **Live testing is what actually validates a heuristic like this** — the
  command-injection baseline-diff fix would not have been caught by
  writing tests against imagined behavior; it took running against the
  real, slightly-quirky real target (DVWA's exec page always pinging) to
  find. Reinforces the established pattern in this project of always
  live-verifying against DVWA before calling a feature done, not just
  trusting mocked tests.

## File Structure Status
- Core: unchanged file list from prior session, plus `src/scope_guard.py`
  modified (ExploitTarget, resettable enforcement, resolve_exploit_target/
  authorize_exploit), `src/orchestrator.py` modified (EXPLOIT_AGENTS,
  exploit_target param/resolution), `src/api.py` modified (same,
  `create_scan`), `src/agents/report_generator.py` modified
  (SEVERITY_BY_TYPE entries), `src/compliance_mapping.py` modified
  (COMPLIANCE_MAP entries)
- **`src/agents/exploit_agent.py`** (new) — the only new agent file
- `config/scope.yaml` — now has a working `authorized_exploit_targets`
  entry for `local-dvwa` with all four vuln classes configured and
  live-verified
- `tests/test_exploit_agent.py` (new, 10 tests); `tests/test_scope_guard.py`
  extended (+6 tests)
- `tests/` — 140 tests across 17 files, all passing

### Dependencies
No new dependencies this session — `ExploitAgent` uses `requests` and
`bs4`, both already present.

## Notes for Next Session

### Context for a new Claude session
- The platform now does real exploitation, gated far more tightly than
  everything else. If asked to extend `ExploitAgent` to a new vuln class
  or a new target: follow the existing module pattern
  (`_run_<class>(base_url, configs, result)`), keep any dangerous
  primitive (new command types, destructive SQL, etc.) as a hardcoded,
  non-config-expandable allowlist if it could cause real damage, and
  live-verify against a real (resettable!) target before considering it
  done — mocked tests alone did not catch the command-injection baseline
  bug this session; only live testing did.
- If asked to point `ExploitAgent` at a target other than DVWA: expect to
  need real reconnaissance of that target's actual HTML/form structure
  first (field names, CSRF token names, result-container markup) the same
  way this session did for DVWA via raw `curl` — don't assume the generic
  config schema will "just work" without checking.
- If asked to relax any of the hard lines (destructive SQL, arbitrary
  commands, credential brute-forcing, or the `resettable: true`
  requirement): treat this the same way the original exploitation request
  was treated — ask clarifying questions and confirm scope explicitly
  before changing code, don't silently comply. These lines were held even
  when the user's answers left room to interpret them more loosely.
- **Never let an agent default/guess a port, path, endpoint, or bind
  address that could resolve to something outside the intended target.**
  Standing rule, now also applies to command-injection command selection
  (never expand `ALLOWED_COMMANDS` via config) and SQLi payload
  construction (never allow non-SELECT statements via config).

### Possible next steps
1. Point `ExploitAgent` at additional lab targets (Juice Shop, etc.) —
   will need real per-target config work, not just a config entry
2. Slack/Jira alerting; real CVE matching; auth/attestation trail; actual
   multi-tenancy — all still open from earlier "commercially viable"/
   "enterprise-grade" discussions
3. `llm-cybersec-dvwa` container still running as the standing lab target
   — its database is now initialized and security level set to low, so a
   fresh `docker rm` + re-run will need that setup redone (that's the
   whole point of `resettable: true` — it's expected to be redone)

### Warnings/Cautions
Carried forward (never add an unauthorized target; don't loosen
`_run_tool`'s allowlist or add `shell=True`; don't let any agent default/
guess ports/paths/bind addresses; keep AI-generated content opt-in and
labeled; don't let dry-run touch `data/history.db`; no literal credentials
in committed files; don't let derived metadata affect dedup/diff identity;
don't default `src/api.py` to `0.0.0.0`).

**New this session:**
- Do not let `ExploitAgent`'s command-injection module accept a command
  outside the hardcoded `ALLOWED_COMMANDS` set, regardless of what a
  target's config requests — this is enforced in code
  (`src/agents/exploit_agent.py`) and must stay that way.
- Do not let the SQLi module construct anything beyond a `SELECT`/`UNION`
  payload — no write/delete capability, ever.
- Do not let credential testing grow into a real brute-force (large
  wordlists, no stop-at-first-success) — it's default-credential
  confirmation, not a credential-stuffing tool.
- Do not remove or weaken `ScopeGuard`'s load-time rejection of
  `authorized_exploit_targets` entries missing `resettable: true` — this
  is the load-bearing justification for the entire feature existing.
