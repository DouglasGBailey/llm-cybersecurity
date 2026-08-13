#!/usr/bin/env bash
# start-system.sh -- single terminal entrypoint for this platform.
#
# Interactive menu covering every feature (run a scan, view/regenerate
# reports and the dashboard, start the REST API, run the test suite, and
# manage local lab targets), or drive it directly with a subcommand for
# scripting -- run `start-system.sh --help` for the non-interactive form.
#
# Defaults to --dry-run for anything that touches a target, same as
# src/orchestrator.py itself -- this script adds a menu on top of the
# existing CLI, it does not loosen any of its safety defaults.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SCOPE_PATH="${SCOPE_PATH:-config/scope.yaml}"
VENV_DIR="venv"
KNOWN_AGENTS=(recon webapp api infra code llm exploit k8s)

# ---------------------------------------------------------------- setup

ensure_venv() {
  if [ ! -d "$VENV_DIR" ]; then
    echo "No virtual environment found at ./$VENV_DIR." >&2
    echo "Create one first:" >&2
    echo "  python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt" >&2
    exit 1
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

ensure_scope() {
  if [ ! -f "$SCOPE_PATH" ]; then
    echo "No scope file at $SCOPE_PATH."
    read -rp "Copy config/scope.example.yaml to $SCOPE_PATH now? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      cp config/scope.example.yaml "$SCOPE_PATH"
      echo "Copied. Edit $SCOPE_PATH to add your own authorized targets before scanning anything for real."
    else
      echo "Cannot continue without a scope file." >&2
      exit 1
    fi
  fi
}

# ---------------------------------------------------------------- scope introspection (via PyYAML, already a dependency)

list_yaml_names() {
  # $1 = top-level scope.yaml key, $2 = field to print per entry
  python -c "
import sys, yaml
with open('$SCOPE_PATH') as f:
    data = yaml.safe_load(f) or {}
for entry in (data.get('$1') or []):
    print(entry.get('$2', ''))
"
}

list_targets() { list_yaml_names authorized_targets name; }
list_exploit_targets() { list_yaml_names authorized_exploit_targets name; }
list_k8s_clusters() { list_yaml_names authorized_k8s_clusters name; }

# ---------------------------------------------------------------- prompts

choose_from() {
  # Prints a numbered list of the given options, prompts for a choice,
  # echoes the chosen one to stdout. Returns non-zero if the list was
  # empty or the user picked invalid. Takes options as arguments (not
  # piped stdin) so the prompt's own `read` still sees the real terminal.
  local prompt="$1"; shift
  local options=("$@")
  if [ "${#options[@]}" -eq 0 ]; then
    echo "(none configured)" >&2
    return 1
  fi
  local i
  for i in "${!options[@]}"; do
    printf '  %d) %s\n' "$((i + 1))" "${options[$i]}" >&2
  done
  local choice
  read -rp "$prompt " choice
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#options[@]}" ]; then
    echo "Invalid choice." >&2
    return 1
  fi
  echo "${options[$((choice - 1))]}"
}

confirm() {
  local prompt="$1"
  local ans
  read -rp "$prompt [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------- feature: scan

do_scan() {
  local target="${1:-}" agents="${2:-}" execute="${3:-}" ai_triage="${4:-}"

  if [ -z "$target" ]; then
    echo
    echo "Authorized targets in $SCOPE_PATH:"
    local targets=()
    mapfile -t targets < <(list_targets)
    target="$(choose_from "Target #:" "${targets[@]}")" || return 1
  fi

  if [ -z "$agents" ]; then
    echo
    echo "Available agents: ${KNOWN_AGENTS[*]}"
    echo "(exploit and k8s each need their own separate scope.yaml authorization --"
    echo " see README.md's Exploitation / Kubernetes sections)"
    read -rp "Comma-separated agents [recon,webapp]: " agents
    agents="${agents:-recon,webapp}"
  fi

  if [ -z "$execute" ]; then
    if confirm "Actually execute (live actions)? Answering N runs --dry-run only."; then
      execute="yes"
    else
      execute="no"
    fi
  fi

  if [ -z "$ai_triage" ]; then
    if confirm "Also generate an AI triage narrative (--ai-triage, uses Claude usage)?"; then
      ai_triage="yes"
    else
      ai_triage="no"
    fi
  fi

  local args=(--scope "$SCOPE_PATH" --target "$target" --agents "$agents")
  [ "$execute" = "yes" ] && args+=(--execute)
  [ "$ai_triage" = "yes" ] && args+=(--ai-triage)

  if [[ ",$agents," == *",code,"* ]]; then
    read -rp "Local code path to scan [src]: " code_path
    args+=(--code-path "${code_path:-src}")
  fi

  echo
  echo "+ python -m src.orchestrator ${args[*]}"
  python -m src.orchestrator "${args[@]}"
  local exit_code=$?
  echo
  echo "orchestrator exited $exit_code (0=no new findings, 1=config error, 3=new findings)"
  return "$exit_code"
}

# ---------------------------------------------------------------- feature: reports / dashboard

do_view_reports() {
  echo
  if [ ! -d reports ] || [ -z "$(ls -A reports 2>/dev/null)" ]; then
    echo "No reports yet -- run a scan first."
    return
  fi
  echo "Reports on disk:"
  local reports_list=()
  mapfile -t reports_list < <(ls -1 reports/*-report.md 2>/dev/null)
  local report
  report="$(choose_from "Open #:" "${reports_list[@]}")" || return
  ${PAGER:-less} "$report"
}

do_dashboard() {
  echo
  python -m src.dashboard --scope "$SCOPE_PATH"
  local out="reports/dashboard.html"
  if [ -t 0 ] && command -v xdg-open >/dev/null 2>&1; then
    confirm "Open it now (xdg-open)?" && xdg-open "$out" >/dev/null 2>&1 &
  fi
}

# ---------------------------------------------------------------- feature: REST API

do_api() {
  echo
  local host="${API_HOST:-127.0.0.1}"
  local port="${API_PORT:-8000}"
  if [ -z "${API_KEY:-}" ]; then
    echo "API_KEY is not set -- the API will run UNAUTHENTICATED. This is fine bound"
    echo "to 127.0.0.1 for local use; do not expose this beyond localhost as-is."
  fi
  echo "Starting REST API on $host:$port (Ctrl-C to stop) ..."
  SCOPE_PATH="$SCOPE_PATH" python -m src.api --host "$host" --port "$port"
}

# ---------------------------------------------------------------- feature: tests

do_tests() {
  echo
  python -m pytest tests/ -v
}

# ---------------------------------------------------------------- feature: lab targets

lab_status() {
  echo
  echo "-- DVWA (local-dvwa) --"
  if docker inspect llm-cybersec-dvwa >/dev/null 2>&1; then
    docker ps -a --filter "name=llm-cybersec-dvwa" --format "  {{.Names}}: {{.Status}}"
  else
    echo "  container not found (never created, or removed)"
  fi
  echo
  echo "-- Kubernetes Goat (local-k8s-goat, kind cluster) --"
  if kind get clusters 2>/dev/null | grep -qx "k8s-goat-lab"; then
    echo "  cluster 'k8s-goat-lab' exists (context kind-k8s-goat-lab)"
    kubectl --context kind-k8s-goat-lab get nodes --no-headers 2>/dev/null | sed 's/^/  /'
  else
    echo "  cluster not found"
  fi
}

lab_up_dvwa() {
  if ! docker inspect llm-cybersec-dvwa >/dev/null 2>&1; then
    echo "No llm-cybersec-dvwa container exists yet. Create one, e.g.:"
    echo "  docker run -d --name llm-cybersec-dvwa -p 8080:80 vulnerables/web-dvwa"
    return 1
  fi
  docker start llm-cybersec-dvwa
  sleep 2
  # This container's apache2 sometimes doesn't come back up after a stop
  # (stale PID file) -- known quirk, see development-status.md. Detect and
  # fix it here so this script always leaves DVWA actually reachable.
  if ! docker exec llm-cybersec-dvwa service apache2 status >/dev/null 2>&1; then
    echo "apache2 didn't come back up automatically (known container quirk) -- restarting it."
    docker exec llm-cybersec-dvwa service apache2 start
  fi
  echo "DVWA up at http://127.0.0.1:8080"
}

lab_down_dvwa() {
  confirm "Stop llm-cybersec-dvwa? (data/state persists until 'docker rm')" && docker stop llm-cybersec-dvwa
}

lab_up_k8s_goat() {
  if ! kind get clusters 2>/dev/null | grep -qx "k8s-goat-lab"; then
    echo "Creating kind cluster 'k8s-goat-lab' ..."
    kind create cluster --name k8s-goat-lab
    local goat_dir="/tmp/kubernetes-goat"
    if [ ! -d "$goat_dir" ]; then
      git clone --depth 1 https://github.com/madhuakula/kubernetes-goat.git "$goat_dir"
    fi
    (cd "$goat_dir" && kubectl config use-context kind-k8s-goat-lab && bash setup-kubernetes-goat.sh)
  else
    echo "kind cluster 'k8s-goat-lab' already exists."
  fi
  echo "Context: kind-k8s-goat-lab"
}

lab_down_k8s_goat() {
  confirm "DELETE the kind cluster 'k8s-goat-lab'? This is destructive and cannot be undone." \
    && kind delete cluster --name k8s-goat-lab
}

lab_menu() {
  while true; do
    echo
    lab_status
    echo
    echo "Lab targets:"
    echo "  1) Start/repair DVWA"
    echo "  2) Stop DVWA"
    echo "  3) Create/deploy Kubernetes Goat"
    echo "  4) Delete Kubernetes Goat cluster"
    echo "  5) Back"
    read -rp "Choice: " choice
    case "$choice" in
      1) lab_up_dvwa ;;
      2) lab_down_dvwa ;;
      3) lab_up_k8s_goat ;;
      4) lab_down_k8s_goat ;;
      5) return ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

# ---------------------------------------------------------------- menu

main_menu() {
  while true; do
    echo
    echo "=== LLM Cybersecurity Agent Platform ==="
    echo "  1) Run a scan"
    echo "  2) View a report"
    echo "  3) Regenerate dashboard"
    echo "  4) Start REST API server"
    echo "  5) Run test suite"
    echo "  6) Manage lab targets (DVWA / Kubernetes Goat)"
    echo "  7) Exit"
    read -rp "Choice: " choice
    case "$choice" in
      1) do_scan ;;
      2) do_view_reports ;;
      3) do_dashboard ;;
      4) do_api ;;
      5) do_tests ;;
      6) lab_menu ;;
      7) exit 0 ;;
      *) echo "Invalid choice." ;;
    esac
  done
}

# ---------------------------------------------------------------- non-interactive subcommands

usage() {
  cat <<EOF
Usage: $0 [command] [args...]

With no command: interactive menu covering every feature.

Commands (non-interactive, for scripting):
  scan --target NAME --agents a,b,c [--execute] [--ai-triage] [--code-path DIR]
                              Run a scan directly (all flags forwarded to
                              src.orchestrator, plus this script's --execute/
                              --ai-triage passthroughs)
  dashboard                  Regenerate reports/dashboard.html
  api [--host H] [--port P]  Start the REST API server in the foreground
  test                       Run the pytest suite
  lab status                 Show DVWA + Kubernetes Goat status
  lab up dvwa|k8s-goat       Start/create a lab target
  lab down dvwa|k8s-goat     Stop/delete a lab target
  -h, --help                 This message
EOF
}

main() {
  ensure_venv
  ensure_scope

  if [ $# -eq 0 ]; then
    main_menu
    return
  fi

  case "$1" in
    -h|--help) usage ;;
    scan)
      shift
      # Pass everything straight through to orchestrator except the two
      # flags this script also understands as yes/no toggles.
      local target="" agents="" execute="no" ai_triage="no" extra=()
      while [ $# -gt 0 ]; do
        case "$1" in
          --target) target="$2"; shift 2 ;;
          --agents) agents="$2"; shift 2 ;;
          --execute) execute="yes"; shift ;;
          --ai-triage) ai_triage="yes"; shift ;;
          *) extra+=("$1"); shift ;;
        esac
      done
      [ -z "$target" ] && { echo "scan requires --target NAME" >&2; exit 1; }
      [ -z "$agents" ] && { echo "scan requires --agents a,b,c" >&2; exit 1; }
      python -m src.orchestrator --scope "$SCOPE_PATH" --target "$target" --agents "$agents" \
        $([ "$execute" = "yes" ] && echo --execute) \
        $([ "$ai_triage" = "yes" ] && echo --ai-triage) \
        "${extra[@]}"
      ;;
    dashboard) do_dashboard ;;
    api)
      shift
      local host="${API_HOST:-127.0.0.1}" port="${API_PORT:-8000}"
      while [ $# -gt 0 ]; do
        case "$1" in
          --host) host="$2"; shift 2 ;;
          --port) port="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      SCOPE_PATH="$SCOPE_PATH" python -m src.api --host "$host" --port "$port"
      ;;
    test) do_tests ;;
    lab)
      shift
      case "${1:-}" in
        status) lab_status ;;
        up)
          case "${2:-}" in
            dvwa) lab_up_dvwa ;;
            k8s-goat) lab_up_k8s_goat ;;
            *) echo "usage: $0 lab up dvwa|k8s-goat" >&2; exit 1 ;;
          esac
          ;;
        down)
          case "${2:-}" in
            dvwa) lab_down_dvwa ;;
            k8s-goat) lab_down_k8s_goat ;;
            *) echo "usage: $0 lab down dvwa|k8s-goat" >&2; exit 1 ;;
          esac
          ;;
        *) echo "usage: $0 lab status|up|down ..." >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "Unknown command: $1" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
