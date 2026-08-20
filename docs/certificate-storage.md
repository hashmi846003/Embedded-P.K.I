# What's in the Database, What's on Disk

Certificate data is split across SQLite and the filesystem on purpose. Public material goes in the DB; private keys stay on disk.

## Signing Algorithm

Every certificate — CA, server, and device — uses:

- **Key type**: RSA. CA key is 4096-bit; server/device keys are 2048-bit.
- **Signature**: SHA-256 hash, RSA signature (`sha256WithRSAEncryption`, reported as `SHA256-RSA` in Go).

Example:

```
$ certctl issue backend-server server "IP:127.0.0.1"
[+] Issued 'backend-server' (server), serial ..., expires 2028-11-22
    Algorithm: RSA-2048 / SHA256-RSA
```

RSA-2048 is supported everywhere you'll test against (`curl`, `openssl s_client`, Go's `crypto/tls`). For a constrained microcontroller doing its own TLS handshake, ECDSA (P-256) would be a better fit — smaller keys, cheaper math. The BBB has a full Linux TLS stack, so RSA is fine here.

## What's Stored in the Database

```sql
cert_pem   TEXT   -- full PEM-encoded public certificate
key_path   TEXT   -- filesystem path to the private key (string only)
algorithm  TEXT   -- e.g. "RSA-2048 / SHA256-RSA"
```

Verified byte-identical to disk:

```bash
$ certctl export backend-server > from-db.crt
$ diff from-db.crt certs/issued/backend-server/backend-server.crt
# (no output)
$ openssl x509 -in from-db.crt -noout -subject -dates
subject=CN = backend-server
notBefore=Aug 20 19:29:07 2026 GMT
notAfter=Nov 22 19:29:07 2028 GMT
```

`certctl export <name>` reads only from SQLite — no filesystem access — and returns a valid X.509 certificate.

## Private Keys Are Not in the Database

Only a path string is stored in `key_path`, never the key itself:

```bash
$ sqlite3 data/pki.db "SELECT cert_pem FROM certificates;" > /tmp/check.txt
$ sqlite3 data/pki.db "SELECT key_path FROM certificates;" >> /tmp/check.txt
$ grep -c "BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY" /tmp/check.txt
0
```

Why keep keys off the DB? Databases get backed up, replicated, exported, copied to laptops for debugging. One leaked backup with every device's private key means total fleet compromise. Filesystem-only keys with restricted permissions (`chmod 400` on the CA key) limit the blast radius to one file.

**Next step if this project continues:** device keys are currently generated on the PC and copied via `scp`. In a hardened design, the device generates its own keypair locally and only sends a CSR — the private key never leaves the device.

## Summary

| Data | Where | Why |
|---|---|---|
| Public certificate (PEM) | Database (`cert_pem`) and filesystem | Safe to duplicate |
| Private key | Filesystem only (`certs/issued/<name>/<name>.key`) | Never centralize in a queryable store |
| Path to private key | Database (`key_path`) | Convenience pointer, not the secret |
| Signature algorithm | Database (`algorithm`) | Inventory / audit |
