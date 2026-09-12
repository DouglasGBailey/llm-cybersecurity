#!/usr/bin/env bash
#
# start-system.sh - Serve the tutorial's index.html over HTTP and print
# both the local and network (LAN) URLs so it can be opened from other
# devices on the same network.

set -euo pipefail

PORT="${1:-8123}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$DIR/index.html" ]; then
    echo "Error: index.html not found in $DIR" >&2
    exit 1
fi

# Find a network-reachable IP (skip loopback). Falls back gracefully if
# no tool below is available.
get_lan_ip() {
    if command -v hostname >/dev/null 2>&1; then
        hostname -I 2>/dev/null | awk '{print $1}' && return 0
    fi
    if command -v ip >/dev/null 2>&1; then
        ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' && return 0
    fi
    if command -v ifconfig >/dev/null 2>&1; then
        ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -n1 && return 0
    fi
    return 1
}

LAN_IP="$(get_lan_ip || true)"

# If ufw is installed and active, make sure the port is allowed through so
# the network URL is actually reachable from other devices.
ensure_fw_allows_port() {
    command -v ufw >/dev/null 2>&1 || return 0

    local status
    status="$(sudo -n ufw status 2>/dev/null || true)"
    [ -z "$status" ] && status="$(ufw status 2>/dev/null || true)"

    case "$status" in
        *"Status: active"*) ;;
        *) return 0 ;;  # ufw not active (or status unreadable) - nothing to do
    esac

    if echo "$status" | grep -qE "^${PORT}/tcp[[:space:]]+ALLOW"; then
        return 0
    fi

    echo "ufw is active and ${PORT}/tcp is not allowed - opening it..."
    if sudo -n ufw allow "${PORT}/tcp" comment 'llm-cybersecurity tutorial preview' >/dev/null 2>&1; then
        echo "  Added ufw rule for ${PORT}/tcp."
    elif sudo ufw allow "${PORT}/tcp" comment 'llm-cybersecurity tutorial preview' >/dev/null 2>&1; then
        echo "  Added ufw rule for ${PORT}/tcp."
    else
        echo "  Warning: could not add ufw rule for ${PORT}/tcp (no sudo access)." >&2
        echo "  Network URL may be unreachable until this port is allowed." >&2
    fi
}

ensure_fw_allows_port

echo "Serving $DIR"
echo ""
echo "  Local:    http://localhost:${PORT}/index.html"
if [ -n "${LAN_IP:-}" ]; then
    echo "  Network:  http://${LAN_IP}:${PORT}/index.html"
else
    echo "  Network:  (could not determine LAN IP)"
fi
echo ""
echo "Press Ctrl+C to stop."

cd "$DIR"

if command -v python3 >/dev/null 2>&1; then
    exec python3 -m http.server "$PORT" --bind 0.0.0.0
elif command -v python >/dev/null 2>&1; then
    exec python -m SimpleHTTPServer "$PORT"
else
    echo "Error: python3 or python is required to serve files." >&2
    exit 1
fi
