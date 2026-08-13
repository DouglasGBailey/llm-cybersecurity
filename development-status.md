# Development Status - LLM Cybersecurity Agent Platform

## Last Updated
**Date**: 2026-08-13
**Session Duration**: Multi-session build (12+ sessions in one day)
**Claude Code Session**: Full recon/hygiene platform + real, config-driven
exploitation (`ExploitAgent`) built across prior sessions (see git log for
the ExploitAgent design session's full detail — 6 scanning agents,
evidence/report/AI-triage, scheduled scanning + diffing, alerting,
compliance mapping, dashboard, containerization + REST API, then
exploitation as a deliberate, separately-authorized policy shift). Three
more sessions since: (1) wrote `FUNCTIONAL_SPEC.md`/`TECHNICAL_SPEC.md`
and a full hands-on tutorial site (`tutorial/index.html`), committed as
`ee0eac0`/`859e699`; (2) ran a 9-agent parallel `total-code-intelligence`
full-codebase audit, implemented fixes for every finding (6 critical, 4
important, 5 suggestion-tier), then caught and fixed a real credential-leak
bug the audit itself missed during live DVWA re-verification; (3) added a
seventh scanning agent, `KubernetesAnalyzer`, in response to an explicit
request to add k8s cluster scanning (minimum 1-node support), with its own
separately-authorized scope model (`authorized_k8s_clusters`) mirroring
the `ExploitAgent`/`CodeAnalyzer` precedent of a dedicated authorization
list per resource type, live-verified against a disposable `kind` cluster
seeded with hand-written misconfigs; (4) stood up a second, standing k8s
lab target by deploying the third-party "Kubernetes Goat"
(madhuakula/kubernetes-goat) intentionally-vulnerable project on a
persistent local `kind` cluster, the k8s equivalent of DVWA, confirming
`KubernetesAnalyzer` generalizes correctly beyond self-authored test
manifests, plus a new tutorial module covering it; (5) **this session** —
added `start-system.sh`, a single terminal entrypoint (interactive menu +
scriptable subcommands) covering every feature: scanning, reports,
dashboard, REST API, tests, and lab-target management.

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
**154/154 tests passing** (`pytest tests/ -v`), no live network required.
As of this session: `test_scope_guard.py` and `test_exploit_agent.py`
each gained several tests for the audit fixes above (malformed-config
handling, SQLi/credentials validation, redaction, IPv4/IPv6 edge case);
`test_infra_analyzer.py` gained the zero-TXT-record regression test;
`test_report_generator.py` gained a `format_finding_detail` test; new
`tests/test_orchestrator.py` (previously had zero dedicated test file)
covers `run_scan()`'s precondition validation.

`test_exploit_agent.py` mocks HTTP via `responses`, same pattern as
`WebAppAnalyzer`/`ApiAnalyzer` — no real exploitation happens in CI.
Notably includes a regression test
(`test_command_injection_not_flagged_when_output_matches_baseline`) for
a real bug found during live verification in the exploitation-design
session — this test would have caught it before it ever reached a live
run.

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

### This session — full code-intelligence audit + fix pass

Ran the `total-code-intelligence` skill (FULL mode, 9 parallel review
agents: bug-hunter, security-auditor, error-handler-auditor,
test-coverage-analyst, comment-quality, type-design-analyzer,
code-simplifier, compliance-checker, git-context) against the entire
codebase (no pending diff — reviewed `master`, commit `859e699`, as it
stood). 7 of 9 agents hit a Claude session usage limit partway through and
were resumed via `SendMessage` to their original `agentId`s with context
on where they'd been cut off; all completed successfully on retry.

**Most significant finding**: `ExploitAgent`'s documented "hard lines" (the
safety design the entire exploitation feature was built around — see the
prior session's entry above) were in several places *claimed but not
structurally enforced*. Two independent agents (test-coverage-analyst and
security-auditor) converged on the same SQLi validation gap independently,
which is what made this the top-priority fix.

**Fixed — critical (6)**:
1. `_run_sqli`'s `union_select`/`from_table` config values were
   interpolated into the payload with zero validation, so a malicious/
   careless `scope.yaml` edit could smuggle non-SELECT SQL past the
   "read-only" hard line. Fixed with `_validate_sqli_config` — a strict
   allowlist regex (`[A-Za-z0-9_.,\s]+` for columns, `[A-Za-z0-9_.]+` for
   the table) rejects anything containing `;`, `--`, `/*`, or a keyword
   outside SELECT/UNION/column syntax, raising before any HTTP request is
   built. Tests: `test_sqli_rejects_malicious_union_select_...`,
   `test_sqli_rejects_malicious_from_table_...`.
2. `ExploitTarget`'s `resettable: true` requirement was only checked in
   `ScopeGuard._load`, not in the dataclass itself — any other
   construction path (a test, future code) could bypass it. Added
   `ExploitTarget.__post_init__` as a backstop that raises
   `ScopeConfigError` directly. Test:
   `test_exploit_target_direct_construction_with_resettable_false_rejected`.
3. The exploit/webapp/api/llm-security agents' step loops only caught
   `requests.RequestException`, so any other failure (e.g. the new
   `SqliConfigError`, a `KeyError` from a malformed config) would crash
   the whole scan instead of being recorded as a finding. Broadened to
   `except Exception` in all four (matching the pattern already correct in
   `recon_agent.py`/`infra_analyzer.py`/`code_analyzer.py`).
4. `ExploitAgent._get`/`_post` logged full request bodies via
   `log_with_fields`, which persists verbatim to `logs/agent-activity.jsonl`
   — including plaintext passwords during credential testing. Added
   `_redact()`, masking `password`/`passwd`/`pwd`/`pass` fields before
   logging (never before sending). Test: `test_redact_masks_password_...`.
5. `_run_credentials` defaulted `success_indicator` to `""`, and an empty
   string is a substring of everything — every login attempt, successful
   or not, would be flagged `weak-credentials-exploited`. Changed to
   `cfg["success_indicator"]` (required, `KeyError` if absent, caught by
   fix #3's broadened exception handling and recorded as a finding rather
   than silently matching). Test:
   `test_credentials_missing_success_indicator_is_rejected`.
6. `src/api.py`'s `require_api_key` compared the bearer token with `!=`,
   a timing side-channel. Switched to `hmac.compare_digest`.

**Fixed — important (4 remaining; 2 comment-quality ones were already
fixed inline before this pass)**:
7. `ai_triage_analyzer.py`'s non-zero-`claude`-exit branch set
   `result.error` but never called `log_with_fields` (its sibling
   `except Exception` branch did) — added the missing log call.
   `orchestrator.py`'s "AI triage did not produce a narrative" print now
   surfaces `triage_result.error` (falling back to `.findings`) instead of
   always printing the findings list, which was empty/uninformative on a
   real failure.
8. `ScopeGuard._load` let a malformed `scope.yaml` (bad YAML syntax, a
   target missing `name`/`host`) raise a raw `yaml.YAMLError`/`KeyError`
   instead of the documented `ScopeConfigError`. Wrapped in try/except,
   re-raising as `ScopeConfigError` with the offending path. Tests:
   `test_malformed_yaml_raises_scope_config_error`,
   `test_authorized_target_missing_host_raises_scope_config_error`,
   `test_exploit_target_missing_name_raises_scope_config_error`.
9. `run_scan()` relied on its *callers* (`main()`, `create_scan()`) to
   validate `code_path`/`exploit_target` were provided before calling it
   — calling it directly (as a library, or from a future caller) with
   `"code"`/`"exploit"` in `agent_keys` but the matching value `None`
   would fail deep inside the agent loop instead of failing fast. Added
   the same precondition check *inside* `run_scan()` itself
   (`ValueError`). New `tests/test_orchestrator.py` (previously had zero
   dedicated test file — flagged separately by the coverage agent).
12. This `development-status.md` update — it had gone two full sessions
    (spec docs, tutorial site) without being updated, against this
    project's own documented convention.

**Fixed — suggestions (5, lower confidence but real)**:
14. `infra_analyzer.py`'s SPF/DMARC checks only flagged `*-record-missing`
    when `dig` returned *some* non-matching TXT output — a domain with
    zero TXT records at all produced no finding either way. Now flags
    missing in both cases. Test:
    `test_missing_spf_dmarc_flagged_when_no_txt_records_at_all`.
15. `ScopeGuard._matches` could raise `TypeError` (uncaught) when a host
    resolved to a mix of IPv4/IPv6 addresses and was checked against a
    single-family CIDR scope entry. Now catches `TypeError` alongside
    `ValueError` per-IP — a family mismatch is just "not a match," not an
    error. Test: `test_ipv4_cidr_scope_does_not_crash_on_ipv6_resolved_...`.
16. `ai_triage_analyzer.py`'s prompt embeds scraped target content
    (page titles, server banners, reflected XSS payloads) verbatim.
    Added an explicit instruction telling Claude to treat those fields as
    inert data, never as commands — a low-cost prompt-injection mitigation
    for a low-severity surface (this is a local triage tool reading the
    operator's own evidence, not a remotely-exploitable path).
17. `AgentResult.status` was typed as bare `str`; narrowed to
    `Literal["ok", "error", "skipped"]` to match what the docstring
    already claimed.
18. Dedup cleanup: `_host_from_target` (was duplicated in `webapp_analyzer`/
    `api_analyzer`/`llm_security_analyzer`) moved to `BaseAgent`. The
    rate-limit/log/dry-run-guard prelude every agent's `_get`/`_post`
    reimplemented is now `BaseAgent._prepare_request` (raises
    `RuntimeError`, translated to `requests.RequestException` at each
    call site — kept HTTP-library-agnostic since `AiTriageAnalyzer` isn't
    an HTTP agent at all). `report_generator.py`'s `_severity_for` renamed
    to public `severity_for` (updated `dashboard.py`'s import and both
    test files) since it's used cross-module. New
    `report_generator.format_finding_detail()` replaces three duplicated
    `k=v, k=v` finding-formatting blocks (two in `report_generator.py`,
    one in `alerting.py`). `_render_diff_section`'s duplicated New/
    Resolved blocks collapsed into one loop over
    `[("New", ...), ("Resolved", ...)]`.

**Deliberately deferred — not fixed this session**: the type-design
agent's Liskov-substitution finding (`BaseAgent.run(self, target: str)`'s
abstract signature doesn't match `ExploitAgent.run(exploit_target:
ExploitTarget)` / `AiTriageAnalyzer.run(evidence: dict)`'s actual
parameter types) was reported at confidence 82, under "Important Issues."
Not fixed here: fixing it properly means either a generic `BaseAgent[T]`
or splitting the abstract method per agent-shape, either of which is a
real refactor touching every agent file for a type-checker-visibility
issue, not a runtime bug — fixes #3 and #9 above already close the actual
behavioral gaps this mismatch could cause (a wrong-type target now fails
fast with a clear error instead of misbehaving deep in an agent). If a
type checker (mypy/pyright) is added to CI later, revisit this then.

**Verification**: all fixes have accompanying tests; `pytest tests/ -v`
green throughout the fix pass (140 → 154 tests as fixes were added). No
live DVWA re-verification was needed for the audit-fix pass itself — every
fix is either pure validation/logging logic covered by mocked-HTTP tests
(matching the existing `test_exploit_agent.py` pattern) or a
non-behavioral rename/dedup.

**Live DVWA re-verification (separate follow-up)**: restarted
`llm-cybersec-dvwa` (had been stopped) to run a real `--agents exploit
--execute` scan and confirm the fixes above didn't regress live behavior.
Apache inside the container hadn't come back up on `docker start` — its
init script saw a stale PID file from before the earlier `docker stop` and
skipped starting it; fixed with `docker exec ... service apache2 start`
(a container quirk, not a platform bug). All four vuln classes confirmed
again with real data (5 DVWA user rows via SQLi, XSS reflection,
`whoami`/`hostname` output, `admin`/`password` login) — the SQLi/
credentials fixes don't reject legitimate config.

This live pass caught a **real bug the audit missed**: fix #4 redacted
credentials inside `ExploitAgent._get`/`_post`'s own logging, but
`orchestrator.py`'s per-agent `logger.info(f"Running {agent.name} against
{agent_target}")` line logs `agent_target` directly, and for exploit
agents that's the raw `ExploitTarget` object — whose `str()`/repr includes
`known_vulnerabilities`, i.e. the plaintext `auth_setup`/`credentials`
passwords, unredacted. Confirmed the leak by grepping
`logs/agent-activity.jsonl` for the real DVWA password after a live run —
found it, twice. Fixed by computing a safe `target_label` (agent name +
host only, never the full object) once per agent iteration, used for both
the log line and — this closes a **second**, more serious latent bug —
the `except Exception` branch's `AgentResult(target=...)`. That branch
previously stored the raw `ExploitTarget` object as `target` whenever
`ExploitAgent.run()` raised before returning (e.g. an unauthorized exploit
target), which would have crashed `json.dumps()` when `results.json` was
written — turning any exploit-agent startup failure into an unhandled
crash of the whole scan instead of a clean per-agent error. Both bugs
share one fix and one root cause: never let a raw `ExploitTarget` reach a
log line, a `print`, or a serialized field. Two new regression tests in
`tests/test_orchestrator.py`:
`test_run_scan_never_logs_exploit_target_credentials` and
`test_run_scan_handles_exploit_agent_exception_without_crashing` (the
latter caught the JSON-serialization crash directly — it failed before
the fix). 156/156 tests passing after this fix.

### This session — KubernetesAnalyzer (seventh scanning agent)

User asked: "can we add functionality to scan a k8s cluster for issues,
min 1 node". Before building, asked two clarifying questions (mirroring
the `ExploitAgent` precedent of confirming scope model + depth before a
new capability, since this needed its own authorization-list decision):
connection method (kubeconfig context vs. explicit API server + stored
credentials — user chose kubeconfig context) and check depth (core
hygiene checks vs. CIS Kubernetes Benchmark-style depth requiring
control-plane/node access `kubectl` alone can't see — user chose core
hygiene).

**Scope model** (`src/scope_guard.py`): new `K8sCluster` dataclass (`name`,
`context`, `notes`) and `Scope.authorized_k8s_clusters`. Identified by a
kubeconfig **context name**, never a host/IP or stored credential — the
ambient kubeconfig (`KUBECONFIG` env var or `~/.kube/config`) is the sole
credential source, same "config references, never stores, credentials"
pattern `alerting.py` already uses for SMTP. `resolve_k8s_cluster(name)` /
`authorize_k8s_context(context)` mirror the existing
`resolve_exploit_target`/`authorize_exploit` pair. Independent of
`authorized_targets` — same "different claim" reasoning as
`authorized_code_paths`.

**`src/agents/k8s_analyzer.py` (new)**: `KubernetesAnalyzer(BaseAgent)`,
`allowed_tools = ["kubectl"]`, six checks via `kubectl get ... -o json`
(list/read only — never `apply`/`create`/`delete`/`exec`):
`k8s-privileged-container`, `k8s-container-runs-as-root`,
`k8s-host-namespace-shared` (hostNetwork/PID/IPC), `k8s-missing-resource-
limits` (aggregated per namespace to avoid finding-spam),
`k8s-overly-permissive-clusterrolebinding` (User/ServiceAccount bound to
`cluster-admin` — the default Group:system:masters binding is correctly
excluded as expected control-plane wiring),
`k8s-wildcard-clusterrole` (built-in roles `cluster-admin`/`admin`/`edit`/
`view`/`system:*` excluded as by-design), `k8s-service-publicly-exposed`
(NodePort/LoadBalancer), `k8s-namespace-missing-network-policy`,
`k8s-default-serviceaccount-automounts-token`, and an informational
`k8s-node-info` (node count + kubelet version — the piece confirming
single-node support: nothing here assumes multi-node topology, everything
is namespace/resource scoped). `kube-system`/`kube-public`/
`kube-node-lease` are excluded from the network-policy and default-SA
checks (cluster-managed, not operator-configured) but deliberately **not**
from the pod-security checks — a genuinely privileged/hostNetwork
control-plane pod is still reported, just expected to be there.

**Design choice that avoided a whole bug class**: `KubernetesAnalyzer.run()`
takes a plain `context: str`, not a `K8sCluster` object — unlike
`ExploitAgent.run(exploit_target: ExploitTarget)`. Since no credentials
live in `authorized_k8s_clusters` (unlike `ExploitTarget`'s
`known_vulnerabilities`), there's nothing sensitive to accidentally
log/serialize, sidestepping the exact leak-and-crash bug class fixed
earlier this session for `ExploitTarget`. `orchestrator.py`'s agent loop
passes `k8s_cluster.context` as `agent_target` for `"k8s"` in
`K8S_AGENTS`, so the existing safe-logging code path (`target_label`)
handles it with zero special-casing.

**Orchestrator/API wiring**: `AGENT_REGISTRY["k8s"] = KubernetesAnalyzer`,
new `K8S_AGENTS = {"k8s"}` set, `run_scan()` gained a `k8s_cluster`
parameter with the same precondition validation pattern as `code_path`/
`exploit_target` (`ValueError` if `"k8s"` requested without a resolved
cluster). Both `main()` (CLI) and `create_scan()` (`src/api.py`) resolve
`guard.resolve_k8s_cluster(target_name)` before running any agent when
`"k8s"` is requested, failing fast (CLI: `EXIT_CONFIG_ERROR`; API: `403`)
if the context isn't separately authorized — same fail-fast pattern as
`ExploitAgent`. Note: like `CodeAnalyzer`/`ExploitAgent`, a k8s-only scan
still needs a same-named `authorized_targets` entry too, since `run_scan()`
is always keyed by that for report naming/history — documented in both
`config/scope.example.yaml` and the README.

**Findings/severity/compliance**: `k8s-privileged-container`,
`k8s-host-namespace-shared`, `k8s-overly-permissive-clusterrolebinding`,
`k8s-wildcard-clusterrole` → `HIGH`; `k8s-container-runs-as-root`,
`k8s-service-publicly-exposed` → `MEDIUM`; the rest → `LOW`/informational.
Mapped to OWASP A05 (Security Misconfiguration), A01 (Broken Access
Control), and CIS Controls v8 4.1/4.8/6.8 where a clear mapping exists —
zero changes needed to `EvidenceCollector`/`dashboard.py`/`diff_engine`,
the "new agent needs no downstream changes" design decision holding again.

**Testing**: 17 new tests in `tests/test_k8s_analyzer.py` mocking
`subprocess.run` with canned `kubectl -o json` output per resource type
(same pattern as `test_infra_analyzer.py`'s `fake_dig`), covering every
check plus dry-run, tool-unavailable, and kubectl-failure paths. Plus new
`ScopeGuard`/`orchestrator`/`api` tests for the k8s wiring. 179/179 tests
passing.

**Live verification**: installed `kubectl` + `kind` (needed `sudo`,
confirmed passwordless access first), created a disposable single-node
`kind` cluster (`llm-cybersec-k8s-lab`), deployed manifests with one pod
combining `hostNetwork`/`hostPID`/`privileged: true`/`runAsUser: 0`, a
`NodePort` Service, a wildcard `ClusterRole`, and a `ClusterRoleBinding`
granting `cluster-admin` to a `ServiceAccount` — then ran a real
`--agents k8s --execute` scan. Every intended finding fired correctly,
including the "expected" ones on real `kube-system` control-plane pods
(`kube-proxy` is genuinely privileged/hostNetwork by design — correctly
reported as true, not suppressed) and correct exclusion of `kube-system`
from the network-policy/default-SA checks. Confirmed single-node support
directly: `k8s-node-info` reported `node_count: 1`. Verified report
rendering (severity grouping, compliance tags) against the real evidence
bundle. Cluster torn down afterward (`kind delete cluster`), no lingering
state (`kind get clusters` → none).

### This session — Kubernetes Goat as a standing k8s lab target

User asked to "point KubernetesAnalyzer at additional lab targets" —
the direct k8s analog of an earlier next-step ("Point ExploitAgent at
additional lab targets (Juice Shop, etc.)"). Asked one clarifying
question first (matching this project's pattern of confirming before
building extra infrastructure): a simple standing `kind` cluster seeded
with more hand-written misconfigs, the third-party "Kubernetes Goat"
project, or both. User chose **Kubernetes Goat**
(`madhuakula/kubernetes-goat` — the k8s equivalent of DVWA: a
purpose-built, intentionally-vulnerable cluster with named scenarios
rather than ad-hoc misconfigured YAML).

**Setup**: created a new persistent single-node `kind` cluster
(`k8s-goat-lab`, kubeconfig context `kind-k8s-goat-lab` — deliberately
separate from the disposable cluster used for initial live verification,
which was already torn down). Cloned `kubernetes-goat` to `/tmp` (not
vendored into the repo — 199MB third-party clone, same reasoning DVWA's
Docker image isn't vendored either). Confirmed `helm` was already
installed, ran `setup-kubernetes-goat.sh` against the new context, which
deploys ~10 vulnerable scenarios across 5 namespaces (`default`,
`big-monolith`, `secure-middleware`, plus `kube-system`/
`local-path-storage`) including its own `insecure-rbac` scenario (a
`superadmin` ServiceAccount bound to `cluster-admin`).

**Config**: added `local-k8s-goat` to both `authorized_targets` (a
placeholder host, since k8s scanning doesn't use it — documented inline
why the entry still needs to exist) and `authorized_k8s_clusters`
(context `kind-k8s-goat-lab`) in `config/scope.yaml` (gitignored, not
committed — confirmed via `git check-ignore` before editing). Recreate
instructions written into the entry's `notes` field.

**Live verification — confirms generalization, not just the original
design**: ran `--agents k8s --execute` against the real, third-party
cluster (not self-authored test manifests this time). Every check fired
correctly on genuinely different infrastructure: `k8s-privileged-container`
(Kubernetes Goat's `health-check`/`system-monitor` containers),
`k8s-host-namespace-shared` (hostPID+hostIPC on `system-monitor`, plus the
expected real `hostNetwork` control-plane pods), `k8s-overly-permissive-
clusterrolebinding` (caught the `superadmin` binding — Kubernetes Goat's
own `insecure-rbac` scenario, a genuine third-party finding, not something
built to match this agent's checks), `k8s-service-publicly-exposed`
(`internal-proxy-info-app-service` as `NodePort`), missing resource
limits/network policies/SA-automount across the deployed namespaces, and
`k8s-node-info` confirming `node_count: 1`. Manually cross-checked for a
false negative on `k8s-wildcard-clusterrole` (queried `clusterroles`
directly with a one-off script) — confirmed there genuinely are no
custom wildcard roles in this deployment (Kubernetes Goat grants
`cluster-admin` directly rather than via a custom wildcard role), so the
absence of that finding is correct, not a miss.

**Diffing confirmed working on a second run**: re-ran the same scan —
`0 new, 0 resolved, 26 unchanged since last run`, exit code `0` (vs. `3`
on the first/baseline run) — `HistoryStore`/`diff_engine` work correctly
for this agent's finding shapes with no special-casing needed, same as
every prior agent.

`local-k8s-goat` is now a **standing** lab target (left running, unlike
the disposable cluster from the original live-verification pass) —
`local-dvwa`'s Docker container and `local-k8s-goat`'s `kind` cluster are
now both persistent, reusable lab infrastructure for this project.

**Tutorial site updated** (mid-session, per a follow-up request): added a
new Module 10, "Kubernetes Cluster Hygiene," to `tutorial/index.html`,
between the existing "Hands-On Ethical Exploitation" (now still Module 9)
and "Compliance Frameworks and Reporting" (renumbered 10→11). Covers the
kubeconfig-context authorization model, all nine `k8s-*` finding types,
the deliberate "report kube-system truthfully but exclude it from the
network-policy/default-SA checks" design choice, and a hands-on lab using
the newly-deployed `local-k8s-goat` target — including the "run it twice,
see 0 new/0 resolved" diffing exercise. Renumbered all downstream
in-module cross-references (`ops`'s SMTP mention was Module 11, now 12;
etc.) and the "Where to Go Next" module's practice-target list and
surface-area count (five → six). Verified the module array's JS syntax
(`node --check`) and structural validity (every module has required
fields, every quiz question has valid `correct`/`options`/`explain`)
before considering this done — no browser tools available in this
environment to screenshot-verify visually, so this is unverified beyond
static/structural checks; worth an actual browser look next session.

### This session — `start-system.sh` terminal entrypoint

User asked for a single terminal entrypoint to access every feature.
Built `start-system.sh` at the project root: an interactive menu (run a
scan, view a report, regenerate the dashboard, start the REST API, run
the test suite, manage lab targets) that also works non-interactively via
subcommands (`scan`, `dashboard`, `api`, `test`, `lab status|up|down`) for
scripting. Deliberately does not loosen any underlying safety default —
still defaults to dry-run for scans, still requires an explicit `y`
confirmation (defaulting to no-op) before anything destructive (stopping
DVWA, deleting the k8s-goat cluster).

**Found and fixed a real bug while testing it**: the initial
`choose_from` helper printed a numbered list by piping candidates into it
(`list_targets | choose_from ...`) and read the user's choice with `read`
*inside* that same function. Since `choose_from`'s stdin was the pipe from
`list_targets`, and `mapfile` had already drained that pipe to build the
list, the subsequent `read` saw an already-closed/empty stdin instead of
the terminal — every menu selection that went through `choose_from`
(target picker, report picker) silently failed with "Invalid choice."
regardless of what the user typed. Caught this by testing the interactive
menu with piped input rather than assuming the happy path worked. Fixed
by passing candidates as function arguments instead of via a pipe, so
`read` keeps using the real stdin — the general lesson (documented inline
in the script): never prompt with `read` from inside a function whose own
stdin has been repurposed by a pipe.

**Lab-target automation encapsulates a known quirk**: `lab up dvwa`
automatically detects and repairs `llm-cybersec-dvwa`'s Apache-not-
restarting-after-stop issue (documented in an earlier session's entry
above) via a status check + conditional restart, so a future `docker
start` + scan doesn't need the manual `docker exec ... service apache2
start` step this project discovered by hand. `lab up k8s-goat` similarly
encapsulates the full `kind create cluster` + clone + `setup-kubernetes-
goat.sh` sequence from the prior session, idempotently (skips creation if
the cluster/clone already exist).

**Verified**: every menu path (scan → target/agent selection → dry-run
prompt → AI-triage prompt, view report, dashboard, lab submenu, exit) and
every non-interactive subcommand, using piped `printf` input for the
interactive paths (matching the technique that caught the bug above).
`./start-system.sh lab up dvwa` re-tested against a freshly-stopped
container to confirm the auto-repair path is reachable, not just
theoretically correct. Full `pytest tests/` suite (179/179) re-run
afterward as a sanity check — this script doesn't touch Python code, but
confirming nothing else drifted costs nothing.

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
- **This session — `src/agents/k8s_analyzer.py`** (new, `KubernetesAnalyzer`),
  `src/scope_guard.py` modified (`K8sCluster`, `authorized_k8s_clusters`,
  `resolve_k8s_cluster`/`authorize_k8s_context`/`is_k8s_context_authorized`),
  `src/orchestrator.py` modified (`K8S_AGENTS`, `k8s_cluster` param/
  resolution in both `run_scan()` and `main()`), `src/api.py` modified
  (same, `create_scan`), `src/agents/report_generator.py` modified
  (`SEVERITY_BY_TYPE` entries), `src/compliance_mapping.py` modified
  (`COMPLIANCE_MAP` entries), `config/scope.example.yaml` modified
  (`authorized_k8s_clusters` documented), `README.md` modified (new
  "Kubernetes Cluster Scanning" section, agent table/counts updated)
- `tests/test_k8s_analyzer.py` (new, 17 tests); `tests/test_scope_guard.py`,
  `tests/test_orchestrator.py`, `tests/test_api.py` each gained k8s-wiring
  tests
- `tests/` — 179 tests across 19 files, all passing
- `FUNCTIONAL_SPEC.md`/`TECHNICAL_SPEC.md` (prior sessions) — not updated
  for `KubernetesAnalyzer`; both predate it and would need a new capability
  entry (§5-style table row) to stay accurate if relied on again
- `tutorial/index.html` — updated this session with a new Module 10
  covering `KubernetesAnalyzer` (13 modules total now); still predates the
  code-intelligence audit fixes, which have no dedicated module (those
  were internal hardening, not a new user-facing capability, so arguably
  don't need one)
- **This session — `start-system.sh`** (new, project root, executable) —
  interactive menu + non-interactive subcommands wrapping
  `src.orchestrator`/`src.dashboard`/`src.api`/`pytest`/`docker`/`kind`.
  `README.md` modified (new "Quick start: start-system.sh" section, minor
  agent-count/list corrections elsewhere)

### Dependencies
No new dependencies this session for the Python package itself —
`KubernetesAnalyzer` shells out to `kubectl` (like `nmap`/`dig`/`bandit`/
`semgrep` before it) rather than adding a Kubernetes client library.
`kubectl` and `kind` were installed system-wide (`/usr/local/bin`, via
`sudo`) for live verification only — not a project dependency, since the
agent only requires `kubectl` to be present on whatever machine runs a
scan, same as any other external-tool-backed agent.

No new dependencies from the exploitation-design session — `ExploitAgent` uses `requests` and
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
- `KubernetesAnalyzer` is read-only by design (`kubectl get` only) — if
  asked to extend it toward remediation/mutation (auto-patching a
  privileged pod, deleting a wildcard ClusterRole, etc.), treat that the
  same way exploitation and code-scanning scope changes were treated: ask
  before building, since "flag the issue" and "change the cluster" are
  very different claims, same reasoning as `ExploitAgent`'s hard lines.
- No k8s client library was added — `KubernetesAnalyzer` shells out to
  `kubectl` like every other tool-backed agent. If ever tempted to switch
  to the `kubernetes` Python client for richer typing, weigh it against
  this project's consistent "external tool via subprocess, not a new SDK
  dependency" pattern (`nmap`, `dig`, `whois`, `bandit`, `semgrep`, now
  `kubectl`) before doing so.

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
4. ~~`KubernetesAnalyzer` has only been live-verified against a disposable
   `kind` cluster~~ — done: `local-k8s-goat` (Kubernetes Goat on a
   persistent `kind` cluster, context `kind-k8s-goat-lab`) is now a
   standing k8s lab target, mirroring `local-dvwa`.
5. `FUNCTIONAL_SPEC.md`/`TECHNICAL_SPEC.md` predate `KubernetesAnalyzer` —
   worth a pass adding it if either doc is relied on again
6. ~~`tutorial/index.html` predates `KubernetesAnalyzer`~~ — done: new
   Module 10 added. A browser-based visual check of the new module still
   hasn't happened (no browser tools available this session) — worth
   doing next session before calling it fully verified.
   if the tutorial site is revisited

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
- There are now **two** standing, persistent lab targets consuming local
  resources: `llm-cybersec-dvwa` (Docker container) and the `kind`
  cluster backing `local-k8s-goat` (context `kind-k8s-goat-lab`, ~10 pods
  across 5 namespaces). Neither should be torn down without checking
  first — same caution as always applied to `llm-cybersec-dvwa`. The
  `/tmp/kubernetes-goat` clone used to deploy it is disposable (manifests
  are already applied to the live cluster) and won't survive a `/tmp`
  clear, but the recreate command is in `config/scope.yaml`'s
  `local-k8s-goat` entry notes if it's ever needed again.
