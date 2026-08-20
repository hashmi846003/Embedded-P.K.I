# Verification Test Log

Output from building and testing this project. Three rounds: the original flat-file version, the database-backed rebuild, and trust-gated onboarding.

## Round 1 — Flat-File Version (superseded)

Initial build used bash scripts + a `revoked.txt` flat file. Two issues found:

**SAN missing from server cert:**
```
* SSL: certificate subject name 'backend-server' does not match target host name '127.0.0.1'
curl: (60) SSL: certificate subject name 'backend-server' does not match target host name '127.0.0.1'
```
Fixed by adding `subjectAltName` to the server cert's extensions.

**Hex vs. decimal serial mismatch broke revocation silently** — see [database-migration.md](database-migration.md). That bug is what pushed the move to SQLite.

## Round 2 — Database-Backed Version, Full Lifecycle Test

Fresh CA, four certificates issued via `certctl` (including one with 5-day validity to test expiry detection), server built from `cmd/server` against the shared SQLite store.

| # | Test | Expected | Actual |
|---|---|---|---|
| 1 | Valid device (`bbb-device-01`) connects | `200` + identity JSON | ✅ `200` |
| 2 | No client certificate | Rejected at TLS handshake | ✅ Rejected |
| 3 | `certctl revoke bbb-device-01` | Recorded in DB, no restart | ✅ `[+] Revoked ... serial ...` |
| 4 | Revoked device retries | `403 certificate revoked` | ✅ `403` |
| 5 | `certctl blacklist ipcam-01` | Recorded, blocks by identity | ✅ `[+] Blacklisted device 'ipcam-01'` |
| 6 | Blacklisted device connects | `403 device is blacklisted` | ✅ `403` |
| 7 | `certctl list` | Shows bbb=revoked, ipcam=BLACKLISTED | ✅ Confirmed in table output |
| 8 | `certctl log` | Every action + auth attempt, newest first | ✅ 8 events, correctly ordered |
| 9 | `certctl issue soon-to-expire-sensor client ... 5` | 5-day validity cert | ✅ expires date = issue date + 5 days |
| 10 | `certctl expiring` (default 30-day window) | Only the 5-day cert listed | ✅ Only `soon-to-expire-sensor` shown |
| 11 | `certctl unblacklist ipcam-01` then retry | `200` again | ✅ `200` + identity JSON |

Sample event log (`certctl log`):

```
2026-08-19 23:55:38  auth_denied      cn=ipcam-01      serial=...  blacklisted: suspected compromised
2026-08-19 23:55:38  blacklisted      cn=ipcam-01      serial=     suspected compromised
2026-08-19 23:55:38  auth_denied      cn=bbb-device-01 serial=...  revoked
2026-08-19 23:55:38  revoked          cn=bbb-device-01 serial=...  test revocation
2026-08-19 23:55:38  auth_success     cn=bbb-device-01 serial=...
2026-08-19 23:55:23  issued           cn=ipcam-01      serial=...  issued client cert, expires 2028-11-21
```

## Bug Found During Round 2 Testing (test tooling, not the product)

While chaining test commands as `cd /project && ./server > log 2>&1 & ...`, subsequent `curl` calls failed with `could not load PEM client certificate ... No such file or directory` even though the files existed.

Root cause: bash backgrounds the entire `cd && command` list as one job, so the `cd` never affected the script's working directory. Later commands ran from the wrong place. Because `certctl`'s `PKI_DB` was also a relative path, an `unblacklist` call silently created a second `pki.db` elsewhere — the CLI reported success, but the real database still showed the device blocked. Found via `find / -name "pki.db*"` turning up two files. Full writeup in [database-migration.md](database-migration.md).

## Round 3 — Trust-Gated Device Onboarding

Added `certctl scan`/`devices`/`trust`, and gated `certctl issue` for client certs behind a trust score from a real `nmap` scan. Tested against `127.0.0.1` as a stand-in (same code path runs against any LAN device, e.g. the BBB at `192.168.7.2`).

| # | Test | Expected | Actual |
|---|---|---|---|
| 1 | `certctl issue bbb-device-01 client` with no prior scan | Refused | ✅ `[!] REFUSED: device 'bbb-device-01' has never been scanned` |
| 2 | `certctl scan 127.0.0.1 test-device` (no risky ports, MAC unknown) | Scored `pending` (below 70) | ✅ `65/100 -> pending` |
| 3 | `certctl trust test-device-... trusted "..."` then issue | Issuance succeeds | ✅ `[+] Issued 'test-device-127-0-0-1' (client)` |
| 4 | Simulated device with telnet (port 23) open, scanned | Scored `suspicious` | ✅ `15/100 -> suspicious` (+15 port count, -50 telnet, from base 50) |
| 5 | `certctl issue` against the suspicious device | Refused | ✅ `[!] REFUSED: ... 'suspicious' (trust score 15)` |
| 6 | Same, with `--force` | Issued, logged as explicit override | ✅ Issued + `trust_override` event |
| 7 | `certctl devices` | Shows both devices, correct scores/status | ✅ Confirmed in table output |
| 8 | `certctl log` | All event types present and ordered | ✅ All 9 events present, newest first |

Event log excerpt — blocked attempt and forced override are separate event types:

```
issued           cn=risky-cam-127-0-0-1  issued client cert, expires 2028-11-22
trust_override   cn=risky-cam-127-0-0-1  FORCED ISSUANCE despite: device 'risky-cam-127-0-0-1' is 'suspicious' (trust score 15)
issue_blocked    cn=risky-cam-127-0-0-1  device 'risky-cam-127-0-0-1' is 'suspicious' (trust score 15)
device_scanned   cn=risky-cam-127-0-0-1  trust_score=15 status=suspicious ports=[23]
```

## Round 4 — Certificate Content in the Database

Added `cert_pem`, `key_path`, `algorithm` columns to `certificates`, and `certctl export`, which reads the public certificate from SQLite.

| # | Test | Expected | Actual |
|---|---|---|---|
| 1 | `certctl issue backend-server server ...` | Reports algorithm | ✅ `Algorithm: RSA-2048 / SHA256-RSA` |
| 2 | `certctl list` | Shows algorithm column | ✅ `RSA-2048 / SHA256-RSA` in table output |
| 3 | `certctl export backend-server` vs. the `.crt` file on disk | Byte-identical | ✅ `diff` produced no output |
| 4 | `openssl x509` on the DB-exported cert | Parses as valid X.509 | ✅ correct subject, serial, validity dates |
| 5 | Grep all `cert_pem` and `key_path` column content for `BEGIN ... PRIVATE KEY` | Zero matches | ✅ `0` |
