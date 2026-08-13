# Functional Specification — LLM Cybersecurity Agent Platform

## 1. Purpose

A controlled, multi-agent security assessment platform for a personal
pentesting-skills learning path. It assesses infrastructure the operator
owns or is explicitly authorized to test, and separately, can prove real
exploitability against a disposable lab target. The platform's guiding
principle, set at the start of the project: build restricted, auditable
sub-agents with narrow roles, not a general-purpose "LLM with a shell."

**Primary user**: a single operator (developer/security learner) running
scans against their own lab infrastructure (a local DVWA container is the
reference target used throughout development) or infrastructure they
have documented authorization to assess.

## 2. Non-goals

- **Not** an autonomous "point an LLM at a target and let it figure out
  how to hack it" tool. Every action any agent can take is declared in
  advance (allowlisted tools, declared vulnerability endpoints) — nothing
  is discovered/improvised at runtime.
- **Not** a vulnerability *discovery*/fuzzing engine. `ExploitAgent`
  proves impact against endpoints the operator already knows are
  vulnerable and has declared in config; it does not scan for unknown
  injectable parameters.
- **Not** multi-tenant. Single operator, single scope file, no user
  accounts, no per-user authorization model.
- **Not** a continuously-running service by default. The scanning core is
  a one-shot CLI/library call; scheduling is delegated to cron/systemd,
  and the REST API executes scans synchronously on request rather than
  managing a job queue.
- **Not** a replacement for commercial vulnerability scanners (Nessus,
  Qualys, etc.) — coverage is intentionally narrow (six hygiene checks +
  four exploitation techniques) rather than an exhaustive CVE database.

## 3. Actors

| Actor | Description |
|---|---|
| **Operator** | The human running scans, configuring scope, reading reports. Sole user of the system. |
| **CLI** | `python -m src.orchestrator` — the primary interface. |
| **REST API client** | Anything driving the platform programmatically (CI job, future dashboard, a K8s Job) via `src/api.py`. |
| **Scheduler** | cron or systemd, external to the platform, invoking `scripts/run-scheduled-scan.sh` on a cadence. |
| **Alert recipient** | Whoever receives the email alert when new findings appear. |

## 4. Core capability: scoped target authorization

Before any capability below can act on a target, that target must be
explicitly listed in a scope configuration file. There is no capability
in this system that can act on a target that is not named in advance.

- **Recon/hygiene scope** (`authorized_targets`): host/IP or CIDR range,
  optional `web_port`/`tls_port`, optional `notes`. Governs the six
  scanning agents (§5).
- **Code-scan scope** (`authorized_code_paths`): local filesystem
  directories `CodeAnalyzer` may statically analyze. Independent of
  network scope — "I own this code" is a different claim than "I may
  scan this host."
- **Exploitation scope** (`authorized_exploit_targets`): a *separate*,
  stricter list. A host listed in `authorized_targets` is **not**
  automatically exploitable — it must have its own entry here, which
  must additionally declare `resettable: true` (the target can be torn
  down and recreated) before the system will even load the configuration.
  Each entry also declares exactly which vulnerability endpoints/
  parameters are known-vulnerable and testable (§6).
- **Exclusions**: hosts/ranges that must never be touched even if they'd
  otherwise match an authorized range (e.g. a shared gateway on a lab
  subnet).
- **Rate limit**: a single requests-per-second ceiling every agent must
  respect against any target.

**Functional requirement**: attempting to run any capability against an
unlisted target, or an exploitation capability against a target not
separately exploit-authorized, must fail with a clear error before any
network/tool action is taken — not silently skip, not warn-and-continue.

## 5. Capability: security hygiene scanning (six agents)

Each agent is independently selectable per run; an operator chooses which
subset to run for a given scan.

| Agent | What it checks | Example findings |
|---|---|---|
| **Recon** | DNS resolution, WHOIS, network port/service enumeration | open ports, service banners, DNS records |
| **Web App Analyzer** | HTTP security posture | missing security headers, server version disclosure, robots.txt content, page/generator fingerprinting |
| **API Analyzer** | REST/GraphQL API hygiene | exposed OpenAPI specs, missing declared auth schemes, GraphQL introspection left enabled, verbose error pages |
| **Infrastructure Analyzer** | TLS and DNS-based email security hygiene | expiring/expired TLS certs, missing SPF/DMARC/DNSSEC records |
| **Code Analyzer** | Static analysis of local source | bandit (Python) and semgrep (multi-language) findings |
| **LLM Security Analyzer** | Prompt-injection/jailbreak resistance of the operator's own LLM-backed app | probe failures (app complied with an injected instruction it should have refused) |

All six are **read-only enumeration** — no agent in this group writes,
deletes, brute-forces, or exploits anything. This is the platform's
default, low-risk assessment mode.

**Functional requirement — TLS port safety**: the Infrastructure Analyzer
must never assume a default TLS port (e.g. 443) when checking
certificates. If a target has no explicit `tls_port` configured, the TLS
check is skipped and reported as skipped, never silently defaulted — a
shared host may run unrelated services on other ports of the same address,
and an authorized IP does not authorize probing every port on it.

## 6. Capability: proof-of-impact exploitation (opt-in, separately scoped)

For a target the operator has both recon-authorized *and*
exploit-authorized (§4) with `resettable: true`, the platform can prove
real exploitability rather than only flag a weakness:

| Vulnerability class | What is proven |
|---|---|
| **SQL injection** | Real data extraction via UNION-based injection (read-only — SELECT only) |
| **Cross-site scripting (XSS)** | A script payload is reflected unescaped in the response (confirmed injectable) |
| **Command injection** | A real, non-destructive command executes on the target and its output is captured |
| **Weak/default credentials** | A login succeeds using a small set of common default credentials |

**Functional requirements (non-negotiable, not configurable by the
operator):**
- SQL injection may only ever read data (no write/update/delete/schema
  changes), regardless of configuration.
- Command injection may only ever execute from a small fixed set of
  read-only, informational commands (e.g. `whoami`, `hostname`) —
  configuration may select a subset of this set, but cannot add to it.
- Credential testing attempts a small, curated list of common defaults
  and stops immediately upon the first success — it is not a
  brute-force/wordlist attack.
- The system does not discover which endpoints are vulnerable; the
  operator declares them in advance (endpoint path, parameter, and
  technique-specific detail like which SQL columns to extract).
- An optional authentication step (login, plus any follow-up requests
  such as setting a security level) may run before exploitation modules,
  since many vulnerable lab apps require an authenticated session.

## 7. Capability: evidence aggregation and reporting

After any scan, regardless of which agents ran:

- **Deduplication**: identical findings observed by multiple agents are
  merged into one record, tracking which agent(s) observed it.
- **Compliance tagging**: each finding is tagged (where a clear, honest
  mapping exists) against the compliance framework control it relates to
  — OWASP Top 10 2021, CIS Controls v8, PCI DSS 4.0, or the OWASP Top 10
  for LLM Applications for LLM-specific findings. Not every finding type
  is tagged; purely informational findings are left untagged rather than
  forcing a spurious mapping.
- **Severity classification**: every finding is placed into one of four
  tiers (high/medium/low/info) for triage purposes.
- **Human-readable report**: a Markdown report is produced per scan,
  containing an executive summary, findings grouped by severity with
  their compliance tags, a compliance-coverage summary, and (see §8) a
  changes-since-last-run section when history exists.
- **Optional AI-written narrative**: on request, a natural-language
  triage narrative (priority ranking, suggested remediation order,
  cross-finding patterns) can be generated from the evidence and written
  to its own clearly-labeled file — this is the one place in the system
  where an LLM's judgment (rather than deterministic rule-matching)
  produces output, and it is always visually distinguishable from the
  deterministic report.

## 8. Capability: scheduled scanning and change detection

- Every live (non-dry-run) scan is recorded to a persistent history,
  keyed by target.
- Each scan is automatically compared to that target's most recent prior
  scan, producing: which findings are new, which have been resolved
  since last time, and which are unchanged.
- The very first scan of a target has nothing to compare against and is
  treated as a baseline — it is never itself treated as "new findings" to
  alert on.
- The scan process signals via its exit status whether new findings
  appeared, so it can be run unattended (via cron/systemd) and an
  external scheduler can decide whether to alert a human, without the
  platform needing its own scheduler process.

## 9. Capability: alerting

- Optional email notification when a scan detects new findings.
- Disabled by default; enabling it requires explicit configuration
  (mail server details and recipient).
- Credentials for sending mail are never stored directly in
  configuration — only references to where the real credential can be
  found at run time (an environment variable).
- A failure to send an alert (bad mail server, network issue, etc.) must
  never cause the scan itself to be considered failed — alerting is a
  side effect of a successful scan, not a precondition for one.

## 10. Capability: dashboard

- A single-page overview, generated on demand, showing every configured
  target: its finding-count trend over recent scans, current severity
  breakdown, most recent change summary, and compliance coverage.
- Targets never scanned are shown as such, not as an error or empty
  chart.
- Not a live, auto-refreshing service — it is regenerated by request
  (CLI command or REST API call) and reflects the state of history at
  that moment.

## 11. Capability: programmatic access (REST API)

Everything the CLI can do is also available over HTTP, for integration
with other systems (CI pipelines, a future UI, orchestration platforms):

- List currently authorized (recon) targets.
- Trigger a scan against a named target with a chosen set of agents, and
  receive a summary of the outcome plus links to the full report/evidence/
  diff.
- Retrieve a previously generated report, evidence bundle, or diff for a
  target.
- Retrieve the dashboard.
- A basic health-check endpoint for use by process supervisors.

**Functional requirements:**
- A scan request blocks until the scan completes and returns its result
  — there is no "start a scan, poll for completion" flow in this version.
- Authentication is optional but supportable: if a shared secret is
  configured, every endpoint except the health check requires it; if not
  configured, the endpoints are open, but the service must clearly signal
  (at startup) that it is running without authentication, and must not
  listen beyond the local machine unless the operator explicitly says to.

## 12. Capability: containerized/orchestrated deployment

- The platform can be packaged as a container image, with the operator's
  configuration and data mounted in at run time rather than baked into
  the image.
- Reference deployment patterns exist for running a single scan as a
  scheduled batch job, and for running the API as a long-lived service,
  in a container-orchestration environment — provided as a starting
  point for an operator who wants that, not a validated production
  deployment.

## 13. Outputs

Every scan produces, per target, on disk:
1. Raw per-agent results
2. The deduplicated, compliance-tagged evidence bundle
3. The human-readable Markdown report
4. The diff against the prior scan (live scans only)
5. Optionally, the AI-written triage narrative (clearly labeled as
   AI-generated)

Plus, on request: the dashboard (all targets, generated fresh each time)
and, if alerting is configured and new findings exist, an email
notification.

## 14. Success criteria

- An operator can point the platform at their own lab target, run a
  hygiene scan, and receive an accurate, evidence-backed report within
  seconds to low minutes depending on which agents ran.
- An operator can, separately and deliberately, authorize live
  exploitation against a disposable lab target and receive genuine proof
  of impact (real extracted data, real command output, real successful
  login) rather than only a "this looks vulnerable" flag.
- Running the same scan twice with no change to the target produces a
  report showing zero new/resolved findings.
- Attempting to scan or exploit anything not explicitly authorized fails
  immediately and clearly, with no partial action taken.
- The platform can run unattended on a schedule and signal, via its exit
  status, whether a human needs to look at the results.
