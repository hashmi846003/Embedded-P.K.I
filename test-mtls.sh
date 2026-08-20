#!/usr/bin/env bash
# Run an mTLS curl test from a device over SSH.
#
# Usage:
#   ./test-mtls.sh <device-ip> <ssh-user> [device-id] [options]
#
# Example:
#   ./test-mtls.sh 192.168.7.2 debian bbb-a3f291
#   ./test-mtls.sh 192.168.7.2 debian          # auto-detects device-id from DB
#
# Options:
#   --server-ip IP   backend IP (default: 192.168.7.1)
#   --port PORT      backend port (default: 4433)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/pki-common.sh
source "$SCRIPT_DIR/scripts/lib/pki-common.sh"

pki_init_paths

SERVER_IP="192.168.7.1"
PORT="4433"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
	case "$1" in
		--server-ip) SERVER_IP="${2:?}"; shift 2 ;;
		--port)      PORT="${2:?}"; shift 2 ;;
		-h|--help)
			sed -n '2,14p' "$0" | sed 's/^# \?//'
			exit 0
			;;
		-*)
			pki_die "Unknown option: $1"
			;;
		*)
			POSITIONAL+=("$1")
			shift
			;;
	esac
done

if ((${#POSITIONAL[@]} < 2)); then
	pki_die "Usage: $0 <device-ip> <ssh-user> [device-id] [--server-ip IP] [--port PORT]"
fi

DEVICE_IP="${POSITIONAL[0]}"
SSH_USER="${POSITIONAL[1]}"
DEVICE_ID="${POSITIONAL[2]:-}"

if [[ -z "$DEVICE_ID" ]]; then
	# Pick the most recently scanned device at this IP
	DEVICE_ID="$(sqlite3 "$PKI_DB" \
		"SELECT device_id FROM devices WHERE ip_address='$DEVICE_IP' ORDER BY last_seen DESC LIMIT 1;" 2>/dev/null || true)"
	[[ -n "$DEVICE_ID" ]] || pki_die "Could not find device-id — pass it explicitly or run onboard-device.sh first."
	pki_log "Using device ID from database: $DEVICE_ID"
fi

pki_test_mtls_from_device "$DEVICE_IP" "$SSH_USER" "$DEVICE_ID" "$SERVER_IP" "$PORT"
