#!/usr/bin/env bash
# Wrapper for cron/systemd: run one scan against a named target and
# propagate the orchestrator's exit code, so the scheduler can alert on it.
#
# Usage: run-scheduled-scan.sh <target-name> [extra orchestrator args...]
#   e.g. run-scheduled-scan.sh local-dvwa --agents recon,webapp,api,infra,llm
#
# Exit codes (see src/orchestrator.py):
#   0 - success, no new findings since last run (or first run for this target)
#   1 - scope/config/argument error
#   3 - success, but new findings appeared since the last run (alert-worthy)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <target-name> [extra orchestrator args...]" >&2
  exit 1
fi

TARGET="$1"
shift

cd "$PROJECT_ROOT"
source venv/bin/activate

python -m src.orchestrator --scope config/scope.yaml --target "$TARGET" --execute "$@"
