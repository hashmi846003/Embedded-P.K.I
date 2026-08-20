# Embedded Device PKI

Certificate-based authentication for IoT devices using mutual TLS (mTLS). Handles issuance, revocation, blacklisting, expiry tracking, and an audit log — all backed by SQLite.

Tested with a BeagleBone Black over USB Ethernet. The CLI and server are split so the same setup works for other device types (e.g. an IP camera via stunnel).

---

## Quick start

**Prerequisites:** Go, OpenSSL, nmap, SSH access to your device.

One command does the full setup — build, CA, scan, issue, copy certs, start server, and test mTLS:

```bash
chmod +x setup-pki.sh onboard-device.sh run-server.sh test-mtls.sh
./setup-pki.sh 192.168.7.2 bbb debian --yes
```

Or step by step:

```bash
./onboard-device.sh 192.168.7.2 bbb debian --yes
./run-server.sh --background
./test-mtls.sh 192.168.7.2 debian
```

Use `--fresh` to wipe `certs/` and `data/` and start over. The server keeps running after setup unless you pass `--stop-server`.

### Scripts

| Script | What it does |
|--------|----------------|
| `setup-pki.sh` | Full pipeline: onboard + server + mTLS test |
| `onboard-device.sh` | Build, CA, scan, trust, issue, SCP to device |
| `run-server.sh` | Start/stop the mTLS backend (`--background`, `--stop`) |
| `test-mtls.sh` | curl test from the device over SSH |
| `setup-ipcam.sh` | Scan/issue for IP cameras + write stunnel config |

---

## Manual setup

```bash
cd server
go build -o certctl ./cmd/certctl
go build -o server  ./cmd/server

export PKI_ROOT=..   # parent dir — where certs/ and data/ live

# Create the CA (once)
./certctl init-ca

# Issue certs — server SAN must match how devices reach the server
./certctl issue backend-server server "IP:192.168.7.1"
./certctl issue bbb-device-01  client

# Copy device cert + key + CA to the device
scp ../certs/issued/bbb-device-01/{bbb-device-01.crt,bbb-device-01.key,ca.crt} \
    debian@192.168.7.2:~/certs/

# Run the backend
cp .env.example .env   # adjust paths / LISTEN_ADDR if needed
export $(grep -v '^#' .env | xargs)
./server
```

From the device:

```bash
curl --cert bbb-device-01.crt --key bbb-device-01.key --cacert ca.crt \
     https://192.168.7.1:4433/api/device/data
```

---

## Onboarding a new device (trust gate)

Client certificates require a scan and a trust score above the threshold:

```bash
./certctl scan 192.168.7.2 bbb
./certctl devices
./certctl trust bbb-a3f291 trusted "reviewed manually"
./certctl issue bbb-a3f291 client
```

Devices with risky open ports (telnet, TR-069, etc.) are marked `suspicious`. Issuance is blocked unless you pass `--force`, which is logged. See [docs/trust-scoring.md](docs/trust-scoring.md).

---

## Day-to-day operations

```bash
./certctl list
./certctl expiring
./certctl revoke bbb-device-01 "lost device"
./certctl blacklist ipcam-01 "compromised"
./certctl unblacklist ipcam-01
./certctl log
```

Revocation and blacklisting apply on the next connection — no server restart.

---

## How it fits together

Most IoT demos stop at server-side TLS — the device trusts the server, but the server accepts anything that connects. Here the server verifies the device too, using a certificate it issued, and can revoke or blacklist that device at any time.

```
                    Root CA (self-signed)
                    certs/ca/ca.key (secret)
                    certs/ca/ca.crt (shared)
                              │ signs
              ┌────────────────┴────────────────┐
              ▼                                  ▼
     backend-server                      Device certificates
     (Go mTLS server)  <──mTLS handshake──>  bbb-device-01, ipcam-01, ...
              │
              │ every request checked & logged against
              ▼
     data/pki.db  (SQLite)
     tables: certificates | blacklist | events | devices
              ▲
              │ issue / revoke / blacklist / list / expiring
     certctl (CLI)
```

Public certificates live in the database (`cert_pem` column). Private keys stay on disk — only a path is stored in `key_path`. Every issuance, revocation, auth attempt, and scan goes into the `events` table.

---

## Project layout

```
pki-project/
├── server/          # Go binaries: server + certctl
├── certs/           # Generated at runtime (gitignored)
├── data/            # pki.db (gitignored)
├── onboard-device.sh
├── setup-pki.sh
├── setup-ipcam.sh
├── test-mtls.sh
├── run-server.sh
├── scripts/lib/pki-common.sh
└── docs/
```

`certs/` and `data/` contain private keys and device identities. Regenerate with `init-ca` and `issue`.

---

## Further reading

| Doc | Contents |
|-----|----------|
| [test-log.md](docs/test-log.md) | Verification output from building and testing |
| [trust-scoring.md](docs/trust-scoring.md) | Scan + trust model |
| [certificate-storage.md](docs/certificate-storage.md) | DB vs filesystem, key handling |
| [database-migration.md](docs/database-migration.md) | Flat files → SQLite, bugs found along the way |
| [ip-camera-stunnel.md](docs/ip-camera-stunnel.md) | Devices without native TLS |
| [linkedin/LINKEDIN-DOCUMENTATION.md](docs/linkedin/LINKEDIN-DOCUMENTATION.md) | LinkedIn post text, diagrams, project overview |
