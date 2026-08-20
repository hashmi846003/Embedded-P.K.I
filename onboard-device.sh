#!/usr/bin/env bash
# Onboard a device: scan, trust check, issue cert, copy over SSH.
#
# Usage:
#   ./onboard-device.sh <device-ip> <device-type> <ssh-user> [options]
#
# Example:
#   ./onboard-device.sh 192.168.7.2 bbb debian
#   ./onboard-device.sh 192.168.7.2 bbb debian --yes --server-ip 192.168.7.1
#
# Options:
#   --fresh       wipe certs/ and data/ first
#   --yes         auto-approve pending devices (no prompt)
#   --force       force issue for suspicious devices
#   --server-ip   IP for backend-server cert SAN (default: 192.168.7.1)
#   --skip-scp    issue cert but do not copy to device
#
# Prints the device ID on stdout (logs go to stderr).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/pki-common.sh
source "$SCRIPT_DIR/scripts/lib/pki-common.sh"

pki_init_paths
pki_require_tools

FRESH=false
AUTO_YES=false
FORCE_ISSUE=false
SKIP_SCP=false
SERVER_IP="192.168.7.1"
POSITIONAL=()

while [[ $# -gt 0 ]]; do
	case "$1" in
		--fresh)     FRESH=true; shift ;;
		--yes|-y)    AUTO_YES=true; shift ;;
		--force)     FORCE_ISSUE=true; shift ;;
		--skip-scp)  SKIP_SCP=true; shift ;;
		--server-ip) SERVER_IP="${2:?}"; shift 2 ;;
		-h|--help)
			sed -n '2,18p' "$0" | sed 's/^# \?//'
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

if ((${#POSITIONAL[@]} < 3)); then
	pki_die "Usage: $0 <device-ip> <device-type> <ssh-user> [options]"
fi

DEVICE_IP="${POSITIONAL[0]}"
DEVICE_TYPE="${POSITIONAL[1]}"
SSH_USER="${POSITIONAL[2]}"

log()  { pki_log "$*" >&2; }
warn() { pki_warn "$*" >&2; }
die()  { pki_die "$*" >&2; }

$FRESH && pki_wipe_state

log "Building certctl and server..."
pki_build

pki_ensure_ca
pki_ensure_backend_cert "$SERVER_IP"

log "Scanning $DEVICE_IP as '$DEVICE_TYPE' (sudo required for nmap)..."
SCAN_OUTPUT=$(sudo pki_certctl scan "$DEVICE_IP" "$DEVICE_TYPE")
echo "$SCAN_OUTPUT" >&2

DEVICE_ID=$(echo "$SCAN_OUTPUT" | grep "^Device ID:" | awk '{print $3}')
[[ -n "$DEVICE_ID" ]] || die "Could not parse device ID from scan output."
log "Device ID: $DEVICE_ID"

STATUS=$(echo "$SCAN_OUTPUT" | grep "Trust score:" | awk -F'-> ' '{print $2}' | tr -d ' ')
FORCE_FLAG=""

case "$STATUS" in
	trusted)
		log "Device is trusted — issuing certificate."
		;;
	pending)
		if $AUTO_YES; then
			pki_certctl trust "$DEVICE_ID" trusted "approved via onboard-device.sh"
		else
			warn "Device scored 'pending' — needs approval."
			read -r -p "Approve '$DEVICE_ID'? [y/N] " REPLY >&2
			if [[ "$REPLY" =~ ^[Yy]$ ]]; then
				pki_certctl trust "$DEVICE_ID" trusted "approved via onboard-device.sh"
			else
				die "Not approved."
			fi
		fi
		;;
	suspicious)
		if $FORCE_ISSUE; then
			warn "Forcing issuance for suspicious device (--force)."
			FORCE_FLAG="--force"
		else
			warn "Device scored 'suspicious'. Review ports above."
			read -r -p "Force issue? Type 'yes' exactly: " REPLY >&2
			if [[ "$REPLY" == "yes" ]]; then
				FORCE_FLAG="--force"
			else
				die "Not forced."
			fi
		fi
		;;
	*)
		die "Could not parse trust status."
		;;
esac

log "Issuing client certificate for '$DEVICE_ID'..."
pki_certctl issue "$DEVICE_ID" client ${FORCE_FLAG:-}

if ! $SKIP_SCP; then
	log "Copying certs to $SSH_USER@$DEVICE_IP:~/certs/ ..."
	ssh "$SSH_USER@$DEVICE_IP" "mkdir -p ~/certs && rm -f ~/certs/*.crt ~/certs/*.key" \
		|| die "SSH failed — is the device reachable at $DEVICE_IP?"

	scp "$PKI_ROOT_DIR/certs/issued/$DEVICE_ID/$DEVICE_ID.crt" \
	    "$PKI_ROOT_DIR/certs/issued/$DEVICE_ID/$DEVICE_ID.key" \
	    "$PKI_ROOT_DIR/certs/ca/ca.crt" \
	    "$SSH_USER@$DEVICE_IP:~/certs/"

	log "Certs copied. Test with:"
	echo "  ./test-mtls.sh $DEVICE_IP $SSH_USER $DEVICE_ID --server-ip $SERVER_IP" >&2
fi

# stdout: device id for callers (setup-pki.sh)
echo "$DEVICE_ID"
