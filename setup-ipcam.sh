#!/usr/bin/env bash
# Onboard an IP camera (or any device without native TLS) and generate stunnel config.
#
# Usage:
#   ./setup-ipcam.sh <camera-ip> [options]
#
# Example:
#   ./setup-ipcam.sh 192.168.1.50 --backend-ip 192.168.7.1 --yes
#
# Options:
#   --yes              auto-approve pending devices
#   --force            force issue for suspicious devices
#   --backend-ip IP    mTLS backend address (default: 192.168.7.1)
#   --backend-port P   mTLS backend port (default: 4433)
#   --local-port P     stunnel accept port on proxy host (default: 8554)
#   --output FILE      write stunnel config here (default: ./stunnel-ipcam.conf)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/pki-common.sh
source "$SCRIPT_DIR/scripts/lib/pki-common.sh"

pki_init_paths
pki_require_tools

CAMERA_IP=""
AUTO_YES=false
FORCE_ISSUE=false
BACKEND_IP="192.168.7.1"
BACKEND_PORT="4433"
LOCAL_PORT="8554"
OUTPUT="$SCRIPT_DIR/stunnel-ipcam.conf"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--yes|-y)        AUTO_YES=true; shift ;;
		--force)         FORCE_ISSUE=true; shift ;;
		--backend-ip)    BACKEND_IP="${2:?}"; shift 2 ;;
		--backend-port)  BACKEND_PORT="${2:?}"; shift 2 ;;
		--local-port)    LOCAL_PORT="${2:?}"; shift 2 ;;
		--output)        OUTPUT="${2:?}"; shift 2 ;;
		-h|--help)
			sed -n '2,16p' "$0" | sed 's/^# \?//'
			exit 0
			;;
		-*)
			pki_die "Unknown option: $1"
			;;
		*)
			[[ -z "$CAMERA_IP" ]] && CAMERA_IP="$1" || pki_die "Unexpected argument: $1"
			shift
			;;
	esac
done

[[ -n "$CAMERA_IP" ]] || pki_die "Usage: $0 <camera-ip> [options]"

pki_build
pki_ensure_ca
pki_ensure_backend_cert "$BACKEND_IP"

pki_log "Scanning camera at $CAMERA_IP ..."
SCAN_OUTPUT=$(sudo pki_certctl scan "$CAMERA_IP" ipcam)
echo "$SCAN_OUTPUT"

DEVICE_ID=$(echo "$SCAN_OUTPUT" | grep "^Device ID:" | awk '{print $3}')
[[ -n "$DEVICE_ID" ]] || pki_die "Could not parse device ID from scan."

STATUS=$(echo "$SCAN_OUTPUT" | grep "Trust score:" | awk -F'-> ' '{print $2}' | tr -d ' ')
FORCE_FLAG=""

case "$STATUS" in
	trusted) ;;
	pending)
		if $AUTO_YES; then
			pki_certctl trust "$DEVICE_ID" trusted "approved via setup-ipcam.sh"
		else
			read -r -p "Approve '$DEVICE_ID'? [y/N] " REPLY
			[[ "$REPLY" =~ ^[Yy]$ ]] || pki_die "Not approved."
			pki_certctl trust "$DEVICE_ID" trusted "approved via setup-ipcam.sh"
		fi
		;;
	suspicious)
		if $FORCE_ISSUE; then
			FORCE_FLAG="--force"
		else
			pki_die "Device scored suspicious — re-run with --force after reviewing ports."
		fi
		;;
	*)
		pki_die "Could not parse trust status."
		;;
esac

pki_log "Issuing certificate for $DEVICE_ID ..."
pki_certctl issue "$DEVICE_ID" client ${FORCE_FLAG:-}

CERT_DIR="$PKI_ROOT_DIR/certs/issued/$DEVICE_ID"
CA_CRT="$PKI_ROOT_DIR/certs/ca/ca.crt"

cat >"$OUTPUT" <<EOF
; stunnel config for IP camera identity: $DEVICE_ID
; Install: sudo apt install stunnel4
; Run:     sudo stunnel $OUTPUT

[ipcam-client]
client = yes
cert = $CERT_DIR/$DEVICE_ID.crt
key  = $CERT_DIR/$DEVICE_ID.key
CAfile = $CA_CRT
verifyChain = yes
connect = $BACKEND_IP:$BACKEND_PORT
accept = 127.0.0.1:$LOCAL_PORT
EOF

pki_log "Wrote stunnel config to $OUTPUT"
echo
echo "  Certificate: $CERT_DIR/$DEVICE_ID.crt"
echo "  Local proxy: 127.0.0.1:$LOCAL_PORT -> $BACKEND_IP:$BACKEND_PORT (mTLS)"
echo
echo "  Next:"
echo "    sudo apt install stunnel4"
echo "    sudo stunnel $OUTPUT"
echo "    curl http://127.0.0.1:$LOCAL_PORT/   # or point your RTSP client at the proxy"
