#!/usr/bin/env bash
# End-to-end setup: build, CA, onboard device, start server, run mTLS test.
#
# Usage:
#   ./setup-pki.sh <device-ip> <device-type> <ssh-user> [options]
#
# Example:
#   ./setup-pki.sh 192.168.7.2 bbb debian
#   ./setup-pki.sh 192.168.7.2 bbb debian --yes --fresh
#
# Options:
#   --fresh              wipe certs/ and data/ first
#   --yes                auto-approve pending devices (no prompt)
#   --force              force issue for suspicious devices
#   --server-ip IP       IP for backend-server cert SAN (default: 192.168.7.1)
#   --listen ADDR        server listen address (default: 192.168.7.1:4433)
#   --skip-test          skip the curl test from the device
#   --skip-server        onboard only, do not start the server
#   --stop-server        stop the server when the script exits (default: keep running)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/pki-common.sh
source "$SCRIPT_DIR/scripts/lib/pki-common.sh"

pki_init_paths
pki_require_tools

FRESH=false
AUTO_YES=false
FORCE_ISSUE=false
SKIP_TEST=false
SKIP_SERVER=false
KEEP_SERVER=true
SERVER_IP="192.168.7.1"
LISTEN_ADDR="192.168.7.1:4433"

POSITIONAL=()
while [[ $# -gt 0 ]]; do
	case "$1" in
		--fresh)       FRESH=true; shift ;;
		--yes|-y)      AUTO_YES=true; shift ;;
		--force)       FORCE_ISSUE=true; shift ;;
		--skip-test)   SKIP_TEST=true; shift ;;
		--skip-server) SKIP_SERVER=true; shift ;;
		--stop-server) KEEP_SERVER=false; shift ;;
		--server-ip)   SERVER_IP="${2:?}"; shift 2 ;;
		--listen)      LISTEN_ADDR="${2:?}"; shift 2 ;;
		-h|--help)
			sed -n '2,20p' "$0" | sed 's/^# \?//'
			exit 0
			;;
		-*)
			pki_die "Unknown option: $1 (try --help)"
			;;
		*)
			POSITIONAL+=("$1")
			shift
			;;
	esac
done

if ((${#POSITIONAL[@]} < 3)); then
	pki_die "Usage: $0 <device-ip> <device-type> <ssh-user> [options]"
fi

DEVICE_IP="${POSITIONAL[0]}"
DEVICE_TYPE="${POSITIONAL[1]}"
SSH_USER="${POSITIONAL[2]}"

ONBOARD_ARGS=(--server-ip "$SERVER_IP")
$FRESH       && ONBOARD_ARGS+=(--fresh)
$AUTO_YES    && ONBOARD_ARGS+=(--yes)
$FORCE_ISSUE  && ONBOARD_ARGS+=(--force)

pki_log "Step 1/3 — Onboarding device at $DEVICE_IP ..."
DEVICE_ID="$("$SCRIPT_DIR/onboard-device.sh" "${ONBOARD_ARGS[@]}" "$DEVICE_IP" "$DEVICE_TYPE" "$SSH_USER")"

if ! $SKIP_SERVER; then
	pki_log "Step 2/3 — Starting server ..."
	pki_start_server "$LISTEN_ADDR"
fi

if ! $SKIP_TEST; then
	pki_log "Step 3/3 — Verifying mTLS ..."
	LISTEN_PORT="${LISTEN_ADDR##*:}"
	pki_test_mtls_from_device "$DEVICE_IP" "$SSH_USER" "$DEVICE_ID" "$SERVER_IP" "$LISTEN_PORT"
fi

# shellcheck disable=SC2329
cleanup() {
	if ! $KEEP_SERVER && ! $SKIP_SERVER; then
		pki_stop_server
	fi
}

if ! $KEEP_SERVER && ! $SKIP_SERVER; then
	trap cleanup EXIT INT TERM
fi

pki_log "All done."
echo
echo "  Device ID:  $DEVICE_ID"
echo "  Server:     $LISTEN_ADDR"
echo "  Certs on device: ~/$SSH_USER/certs/"
echo
echo "  Start server again:  ./run-server.sh $LISTEN_ADDR"
echo "  Stop background server: ./run-server.sh --stop"
echo "  Test again:          ./test-mtls.sh $DEVICE_IP $SSH_USER $DEVICE_ID"
