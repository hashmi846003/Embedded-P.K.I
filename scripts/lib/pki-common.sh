#!/usr/bin/env bash
# Shared helpers for PKI bash scripts.

pki_init_paths() {
	local caller="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
	local dir
	dir="$(cd "$(dirname "$caller")" && pwd)"

	# scripts/lib -> project root; project root scripts stay at root
	if [[ "$(basename "$dir")" == "lib" && "$(basename "$(dirname "$dir")")" == "scripts" ]]; then
		PKI_ROOT_DIR="$(cd "$dir/../.." && pwd)"
	else
		PKI_ROOT_DIR="$dir"
	fi

	PKI_SERVER_DIR="$PKI_ROOT_DIR/server"
	export PKI_ROOT="$PKI_ROOT_DIR"
	export PKI_DB="$PKI_ROOT_DIR/data/pki.db"
}

pki_log()  { echo -e "\n\033[1;36m[pki]\033[0m $*"; }
pki_warn() { echo -e "\033[1;33m[pki][!]\033[0m $*"; }
pki_die()  { echo -e "\033[1;31m[pki][x]\033[0m $*"; exit 1; }

pki_require_tools() {
	local missing=()
	for tool in go openssl nmap ssh scp curl; do
		command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
	done
	if ((${#missing[@]})); then
		pki_die "Missing required tools: ${missing[*]}"
	fi
}

pki_build() {
	pki_log "Building certctl and server..."
	cd "$PKI_SERVER_DIR"
	CGO_ENABLED=1 go build -o certctl ./cmd/certctl
	CGO_ENABLED=1 go build -o server  ./cmd/server
	pki_log "Build OK."
}

pki_certctl() {
	cd "$PKI_SERVER_DIR"
	./certctl "$@"
}

pki_ensure_ca() {
	if [[ ! -f "$PKI_ROOT_DIR/certs/ca/ca.key" ]]; then
		pki_log "Creating CA..."
		pki_certctl init-ca
	else
		pki_log "CA already exists — skipping."
	fi
}

pki_ensure_backend_cert() {
	local server_ip="${1:?server IP required}"
	local cert_path="$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.crt"

	if [[ ! -f "$cert_path" ]]; then
		pki_log "Issuing backend-server certificate (SAN=$server_ip)..."
		pki_certctl issue backend-server server "IP:$server_ip"
	else
		pki_log "backend-server cert already issued — skipping."
	fi
}

pki_wipe_state() {
	pki_warn "Wiping certs/ and data/ for a fresh start."
	rm -rf "$PKI_ROOT_DIR/certs" "$PKI_ROOT_DIR/data"
}

pki_server_pid_file() {
	echo "$PKI_ROOT_DIR/data/server.pid"
}

pki_start_server() {
	local listen_addr="${1:-192.168.7.1:4433}"
	local pid_file log_file
	pid_file="$(pki_server_pid_file)"
	log_file="$PKI_ROOT_DIR/data/server.log"

	mkdir -p "$PKI_ROOT_DIR/data"

	if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
		pki_log "Server already running (pid $(cat "$pid_file"))."
		return 0
	fi

	if [[ ! -f "$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.crt" ]]; then
		pki_die "No backend-server certificate. Run onboarding first."
	fi

	pki_log "Starting mTLS server on $listen_addr (background)..."
	cd "$PKI_SERVER_DIR"
	CA_CERT="$PKI_ROOT_DIR/certs/ca/ca.crt" \
	SERVER_CERT="$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.crt" \
	SERVER_KEY="$PKI_ROOT_DIR/certs/issued/backend-server/backend-server.key" \
	PKI_DB="$PKI_ROOT_DIR/data/pki.db" \
	LISTEN_ADDR="$listen_addr" \
	nohup ./server >"$log_file" 2>&1 &
	echo $! >"$pid_file"

	# Wait for the server to bind
	local i
	for i in $(seq 1 20); do
		if curl -sk --connect-timeout 1 "https://${listen_addr}/api/device/data" >/dev/null 2>&1 \
		   || grep -qi "listening" "$log_file" 2>/dev/null; then
			pki_log "Server started (pid $(cat "$pid_file"), log: $log_file)."
			return 0
		fi
		sleep 0.5
	done

	pki_warn "Server process started but health check did not confirm readiness yet."
	pki_warn "Check $log_file if the test step fails."
}

pki_stop_server() {
	local pid_file
	pid_file="$(pki_server_pid_file)"
	if [[ -f "$pid_file" ]]; then
		local pid
		pid="$(cat "$pid_file")"
		if kill -0 "$pid" 2>/dev/null; then
			kill "$pid" 2>/dev/null || true
			pki_log "Stopped server (pid $pid)."
		fi
		rm -f "$pid_file"
	fi
}

pki_test_mtls_from_device() {
	local device_ip="$1"
	local ssh_user="$2"
	local device_id="$3"
	local server_ip="$4"
	local listen_port="${5:-4433}"

	pki_log "Testing mTLS from $ssh_user@$device_ip ..."
	local url="https://${server_ip}:${listen_port}/api/device/data"
	local cmd
	cmd="curl -sf --cert ~/certs/${device_id}.crt --key ~/certs/${device_id}.key --cacert ~/certs/ca.crt '$url'"

	if ssh "$ssh_user@$device_ip" "$cmd"; then
		pki_log "mTLS test passed."
		return 0
	fi

	pki_die "mTLS test failed. Check server log at $PKI_ROOT_DIR/data/server.log"
}
