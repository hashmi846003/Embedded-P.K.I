# Device Discovery & Trust-Based Certificate Issuance

This is the gate before a device gets a certificate — scan the network, score the device, approve or block issuance.

## The Flow

```
certctl scan <ip> [type]
        │
        │  nmap -sV --open <ip>   → open ports + service banners
        │  ip neigh show <ip>     → MAC address (if on local subnet)
        ▼
   trust.Calculate(scan)
        │
        │  weighted scoring (see below)
        ▼
   devices table: trust_score, onboarding_status
        │
        ▼
certctl issue <device-id> client
        │
        │  st.CheckIssuanceAllowed(device-id)
        │  — refuses unless onboarding_status == "trusted"
        │  — --force bypasses it, logs a "trust_override" event
        ▼
   certificate issued, recorded in certificates
```

## What a Scan Collects

| Field | Source | Why it's used |
|---|---|---|
| Open TCP ports + service | `nmap -sV --open` | Port count and which ports are open are the strongest network-only signals |
| MAC address | `ip neigh show <ip>` | Only on the same local subnet — expected for BBB/camera-style deployments |
| MAC vendor (OUI prefix) | Local lookup table (`trust.knownVendorOUIs`) | Quick check for known embedded/IoT hardware |
| Locally-administered bit | Computed from the MAC's first octet | IEEE signal that a MAC was set in software — common in spoofing |

## Device Identity

The device ID is derived from the scan, not typed by hand: `<type>-<last 6 hex of MAC>` (e.g. `bbb-a3f291`), falling back to the IP if no MAC is available. Ties the identity to something on the wire instead of a label someone might reuse by mistake.

## Trust Score

Starts at 50, then:

| Signal | Effect |
|---|---|
| MAC vendor is a known embedded/IoT vendor | **+20** |
| MAC has the locally-administered bit set | **-30** |
| MAC not found (off-subnet or hidden) | **+0** (neutral) |
| 3 or fewer open ports | **+15** |
| Risky port open (telnet 23, FTP 21, RDP 3389, VNC 5900, TR-069 7547) | **-50 per port** |

Thresholds:

```
score >= 70  → trusted     (certctl issue proceeds)
40-69        → pending     (needs certctl trust <id> trusted "<reason>")
< 40         → suspicious  (issue refuses unless --force)
```

Every point gained or lost is printed by `certctl scan` with the reason. Deliberately simple and explainable rather than a black-box score.

## Storage

Two tables (full schema in `internal/store/store.go`):

```sql
devices (device_id PK, ip_address, mac_address, mac_vendor_known,
         device_type, open_ports, risky_ports_found, trust_score,
         onboarding_status, first_seen, last_seen, scan_count)

events  (... event_type IN ('device_scanned', 'trust_override',
                             'issue_blocked', ...))
```

`devices` is current state; `events` is the history. `certctl devices` reads the former; `certctl log` reads the latter.

## Verified Behavior

See `test-log.md` for raw output. Summary:

- No prior scan → `certctl issue` refuses.
- Clean scan, unknown MAC → `pending` (65/100 in testing), needs manual approval.
- `certctl trust <id> trusted "<reason>"` then allows issuance.
- Telnet open → `suspicious` (15/100), issue refuses.
- `--force` overrides but logs as `trust_override` with "FORCED ISSUANCE despite: ..." — distinct from normal approval.

## Limits

This is a working demo, not production IDS:

- The vendor OUI list is a small illustrative set, not the full IEEE registry.
- Port/banner fingerprinting can be spoofed — useful against casual threats, not a cryptographic guarantee.
- MAC addresses only visible on the same local subnet.
- The trust score decides *whether* to issue; the certificate (backed by the device's keypair) still does the cryptographic authentication.
