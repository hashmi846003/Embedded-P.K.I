# Why This Moved From Flat Files to SQLite

The first version tracked revocation in a flat file (`revoked.txt`, one serial per line). That worked until you need more than one kind of status:

- No way to distinguish "revoke this cert" from "block this device even if reissued" (blacklist vs. revocation).
- No queryable history — "when was this issued, when revoked, and why" meant grepping files.
- No expiry tracking.
- Every new status would mean another flat file, each able to drift out of sync.

## What Changed

Everything now lives in one SQLite database (`data/pki.db`):

```sql
certificates  -- one row per issued cert: serial, name, type, issued_at,
              -- expires_at, status (issued/revoked), status_reason
blacklist     -- one row per blocked device identity (by common name),
              -- independent of any specific certificate serial
events        -- append-only log: every issue, revoke, blacklist action,
              -- and every authentication attempt (accepted or rejected)
```

The mTLS server (`cmd/server`) and admin CLI (`cmd/certctl`) both open this same file — revocation state can't drift between tools the way two flat files could.

## Why Blacklist Is Separate From Revocation

`certctl revoke <name>` invalidates one specific certificate serial. If that device gets a new certificate later, the new cert is valid again — correct for routine rotation.

`certctl blacklist <common-name>` blocks the device identity regardless of which certificate it's holding. Right tool for "we think this physical device is compromised." Reissuing a cert should not restore access until someone runs `unblacklist`.

The server checks both on every request (`store.CheckAuth`).

## Two Bugs Found While Building This

**1. Hex vs. decimal serial mismatch (flat-file version).** OpenSSL's `-serial` output is hex; Go's `x509.Certificate.SerialNumber.String()` is decimal. The bash revocation script stored hex, the server compared decimal — revocation silently did nothing. The SQLite version reads the serial back out of the signed cert via Go's `x509.ParseCertificate`, so issuance and auth-check always use the same decimal string.

**2. `cd dir && command &` doesn't do what it looks like.** A test one-liner ran `cd /project && ./server &`. Bash backgrounds the entire `cd && command` pair as one job — the `cd` only applies inside that subshell. Later `curl` calls ran from the wrong directory; relative cert paths broke. Worse, because `PKI_DB` was also relative, an `unblacklist` call created a second `pki.db` in the wrong place while the real DB still showed the device blocked. Fixed by never combining `cd` with `&` in the same statement. Easy mistake — every individual command looks correct in isolation.
