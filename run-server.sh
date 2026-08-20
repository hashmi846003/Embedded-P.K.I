#!/usr/bin/env bash
# Start or stop the mTLS backend.
#
# Usage:
#   ./run-server.sh [listen-addr]          # foreground (default)
#   ./run-server.sh --background [addr]    # background daemon
#   ./run-server.sh --stop
#
# Example:
#   ./run-server.sh 192.168.7.1:4433
#   ./run-server.sh --background
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/pki-common.sh
source "$SCRIPT_DIR/scripts/lib/pki-common.sh"

pki_init_paths

LISTEN_ADDR="192.168.7.1:4433"
MODE="foreground"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--background|-b)
			MODE="background"
			shift
			;;
		--stop)
			pki_stop_server
			exit 0
			;;
		--status)
			pid_file="$(pki_server_pid_file)"
			if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
				echo "Server running (pid $(cat "$pid_file"))"
				exit 0
			fi
			echo "Server not running"
			exit 1
			;;
		-h|--help)
			sed -n '2,12p' "$0" | sed 's/^# \?//'
			exit 0
			;;
		-*)
			pki_die "Unknown option: $1"
			;;
		*)
			LISTEN_ADDR="$1"
			shift
			;;
	esac
done

if [[ "$MODE" == "background" ]]; then
	pki_start_server "$LISTEN_ADDR"
	exit 0
fi

if [[ ! -f "$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.crt" ]]; then
	pki_die "No backend-server certificate. Run ./onboard-device.sh or ./setup-pki.sh first."
fi

echo "[run-server] Listening on $LISTEN_ADDR, database: $PKI_ROOT_DIR/data/pki.db"
cd "$PKI_SERVER_DIR"
CA_CERT="$PKI_ROOT_DIR/certs/ca/ca.crt" \
SERVER_CERT="$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.crt" \
SERVER_KEY="$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.key" \
PKI_DB="$PKI_ROOT_DIR/data/pki.db" \
LISTEN_ADDR="$LISTEN_ADDR" \
exec ./server
