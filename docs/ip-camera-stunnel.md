# Onboarding a Device With No Native Certificate Support (IP Camera Example)

Most consumer IP cameras speak plain RTSP/HTTP and have no way to install a client certificate. You can still give the camera its own PKI identity by putting a small TLS-terminating proxy in front of it that holds the certificate on the camera's behalf.

## 1. Issue the camera a certificate

Same flow as any other device — or use the helper script:

```bash
./setup-ipcam.sh 192.168.1.50 --yes
```

Manual steps:

## 2. Check the camera's admin UI first

Some IP cameras support uploading a client cert (for ONVIF-over-TLS or cloud-push features) under a "Certificates" / "HTTPS" security menu. If yours does, upload `ipcam-01.crt`, `ipcam-01.key`, and `ca.crt` there directly and skip the proxy below.

## 3. If not — front it with stunnel

Install:

```bash
sudo apt install stunnel4
```

Config (`/etc/stunnel/ipcam.conf`), run on the machine that has network access to both the camera and your mTLS backend:

```ini
[ipcam-client]
client = yes
cert = /path/to/certs/issued/ipcam-01/ipcam-01.crt
key = /path/to/certs/issued/ipcam-01/ipcam-01.key
CAfile = /path/to/certs/ca/ca.crt
verifyChain = yes
connect = <backend-server-ip>:4433
accept = 127.0.0.1:8554
```

Anything that talks to the camera locally connects to `127.0.0.1:8554` instead of the camera directly. stunnel forwards it out over mTLS using the camera's issued identity. The camera's own plain RTSP/HTTP traffic stays on the local segment — only the tunnel's mTLS connection crosses the network boundary.

## Why bother with a proxy

Not every device in a real fleet can run your protocol stack natively. Issuing an identity and enforcing it at the network boundary — even when the device itself can't do TLS — is a common pattern in IoT deployments (trusted proxy / identity gateway).
