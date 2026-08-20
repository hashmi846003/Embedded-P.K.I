// Command certctl is the admin tool for the certificate fleet: it wraps
// OpenSSL for the actual cryptographic operations (key generation, CSR,
// signing) and records every lifecycle action in the shared SQLite store,
// so the mTLS server and this CLI are always looking at the same source
// of truth for issued/revoked/blacklisted/expiring certificates.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mtls-server/internal/store"
	"mtls-server/internal/trust"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	rootDir := envOr("PKI_ROOT", "..")
	dbPath := envOr("PKI_DB", filepath.Join(rootDir, "data", "pki.db"))
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	st, err := store.Open(dbPath)
	must(err)
	defer st.Close()

	switch os.Args[1] {
	case "init-ca":
		cn := "Embedded-IoT-Fleet-RootCA"
		if len(os.Args) > 2 {
			cn = os.Args[2]
		}
		cmdInitCA(rootDir, cn)
	case "issue":
		if len(os.Args) < 4 {
			fmt.Println("usage: certctl issue <name> <server|client> [san] [validity-days] [--force]")
			os.Exit(1)
		}
		san := "IP:127.0.0.1"
		if len(os.Args) > 4 && os.Args[4] != "--force" {
			san = os.Args[4]
		}
		days := 825
		if len(os.Args) > 5 {
			fmt.Sscanf(os.Args[5], "%d", &days)
		}
		force := false
		for _, a := range os.Args {
			if a == "--force" {
				force = true
			}
		}
		cmdIssue(st, rootDir, os.Args[2], os.Args[3], san, days, force)
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("usage: certctl scan <ip-address> [device-type-hint]")
			os.Exit(1)
		}
		deviceType := "unknown"
		if len(os.Args) > 3 {
			deviceType = os.Args[3]
		}
		cmdScan(st, os.Args[2], deviceType)
	case "devices":
		cmdDevices(st)
	case "trust":
		if len(os.Args) < 4 {
			fmt.Println("usage: certctl trust <device-id> <trusted|pending|suspicious> [reason]")
			os.Exit(1)
		}
		reason := "manual override"
		if len(os.Args) > 4 {
			reason = os.Args[4]
		}
		must(st.SetOnboardingStatus(os.Args[2], store.OnboardingStatus(os.Args[3]), reason))
		fmt.Printf("[+] '%s' onboarding status manually set to '%s'.\n", os.Args[2], os.Args[3])
	case "revoke":
		if len(os.Args) < 3 {
			fmt.Println("usage: certctl revoke <name> [reason]")
			os.Exit(1)
		}
		reason := "manual revocation"
		if len(os.Args) > 3 {
			reason = os.Args[3]
		}
		cmdRevoke(st, rootDir, os.Args[2], reason)
	case "blacklist":
		if len(os.Args) < 3 {
			fmt.Println("usage: certctl blacklist <common-name> [reason]")
			os.Exit(1)
		}
		reason := "manual blacklist"
		if len(os.Args) > 3 {
			reason = os.Args[3]
		}
		must(st.Blacklist(os.Args[2], reason))
		fmt.Printf("[+] Blacklisted device '%s' — blocked even if reissued a new cert.\n", os.Args[2])
	case "unblacklist":
		if len(os.Args) < 3 {
			fmt.Println("usage: certctl unblacklist <common-name>")
			os.Exit(1)
		}
		must(st.Unblacklist(os.Args[2]))
		fmt.Printf("[+] Removed '%s' from blacklist.\n", os.Args[2])
	case "list":
		cmdList(st)
	case "export":
		if len(os.Args) < 3 {
			fmt.Println("usage: certctl export <name>   -- prints the public cert PEM, read entirely from the database")
			os.Exit(1)
		}
		cmdExport(st, os.Args[2])
	case "expiring":
		days := 30
		cmdExpiring(st, time.Duration(days)*24*time.Hour)
	case "log":
		cmdLog(st)
	default:
		usage()
		os.Exit(1)
	}
}

func cmdInitCA(rootDir, cn string) {
	caDir := filepath.Join(rootDir, "certs", "ca")
	os.MkdirAll(caDir, 0755)
	keyPath := filepath.Join(caDir, "ca.key")
	if _, err := os.Stat(keyPath); err == nil {
		fmt.Println("CA already exists — refusing to overwrite.")
		os.Exit(1)
	}

	run("openssl", "genrsa", "-out", keyPath, "4096")
	os.Chmod(keyPath, 0400)
	run("openssl", "req", "-x509", "-new", "-nodes", "-key", keyPath, "-sha256", "-days", "3650",
		"-out", filepath.Join(caDir, "ca.crt"), "-subj", "/CN="+cn)

	fmt.Println("[+] CA ready:")
	fmt.Println("    Private key (secret):", keyPath)
	fmt.Println("    Root cert (shared):  ", filepath.Join(caDir, "ca.crt"))
}

func cmdIssue(st *store.Store, rootDir, name, certType, san string, days int, force bool) {
	if certType != "server" && certType != "client" {
		fmt.Println("type must be 'server' or 'client'")
		os.Exit(1)
	}

	// The trust gate only applies to client (device) certs — the backend
	// server itself isn't a network-scanned "device" in this model.
	if certType == "client" {
		allowed, reason := st.CheckIssuanceAllowed(name)
		if !allowed && !force {
			fmt.Println("[!] REFUSED:", reason)
			fmt.Println("    Run `certctl scan <ip> " + name + "` first, or override with --force (logged as an explicit exception).")
			st.LogIssueBlocked(name, reason)
			os.Exit(1)
		}
		if !allowed && force {
			fmt.Println("[!] Trust gate failed (" + reason + ") but --force was set — issuing anyway.")
			st.LogTrustForceOverride(name, reason)
		}
	}

	caDir := filepath.Join(rootDir, "certs", "ca")
	outDir := filepath.Join(rootDir, "certs", "issued", name)
	os.MkdirAll(outDir, 0755)

	keyPath := filepath.Join(outDir, name+".key")
	csrPath := filepath.Join(outDir, name+".csr")
	crtPath := filepath.Join(outDir, name+".crt")

	run("openssl", "genrsa", "-out", keyPath, "2048")
	run("openssl", "req", "-new", "-key", keyPath, "-out", csrPath, "-subj", "/CN="+name)

	extFile, _ := os.CreateTemp("", "ext-*.cnf")
	if certType == "server" {
		fmt.Fprintf(extFile, "extendedKeyUsage = serverAuth\nsubjectAltName = %s\n", san)
	} else {
		fmt.Fprint(extFile, "extendedKeyUsage = clientAuth\n")
	}
	extFile.Close()
	defer os.Remove(extFile.Name())

	run("openssl", "x509", "-req", "-in", csrPath,
		"-CA", filepath.Join(caDir, "ca.crt"), "-CAkey", filepath.Join(caDir, "ca.key"),
		"-CAcreateserial", "-out", crtPath, "-days", fmt.Sprint(days), "-sha256",
		"-extfile", extFile.Name())
	os.Remove(csrPath)

	exec.Command("cp", filepath.Join(caDir, "ca.crt"), filepath.Join(outDir, "ca.crt")).Run()

	// Read back the cert we just made so the DB record's serial and expiry
	// are exactly what's cryptographically true — never re-derived or guessed.
	// This also reads the PEM content and signature algorithm, so the
	// database ends up with the full public certificate, not just metadata
	// pointing at a file — see the note in store.go about why the private
	// key at keyPath is deliberately NOT included in what gets stored.
	serial, expiresAt, algorithm := readCertMeta(crtPath)
	pemBytes, err := os.ReadFile(crtPath)
	must(err)
	issuedAt := time.Now()

	must(st.RecordIssued(store.Certificate{
		Serial:     serial,
		Name:       name,
		Type:       certType,
		CommonName: name,
		IssuedAt:   issuedAt,
		ExpiresAt:  expiresAt,
		CertPEM:    string(pemBytes),
		KeyPath:    keyPath, // pointer only -- the key file itself, never its contents
		Algorithm:  algorithm,
	}))

	fmt.Printf("[+] Issued '%s' (%s), serial %s, expires %s\n", name, certType, serial, expiresAt.Format("2006-01-02"))
	fmt.Printf("    Algorithm: %s\n", algorithm)
	fmt.Printf("    Private key (never stored in DB): %s\n", keyPath)
	fmt.Printf("    Public cert stored in database:    %s\n", envOr("PKI_DB", filepath.Join(rootDir, "data", "pki.db")))
}

func cmdRevoke(st *store.Store, rootDir, name, reason string) {
	crtPath := filepath.Join(rootDir, "certs", "issued", name, name+".crt")
	serial, _, _ := readCertMeta(crtPath)
	must(st.Revoke(serial, reason))
	fmt.Printf("[+] Revoked '%s' (serial %s): %s\n", name, serial, reason)
	fmt.Println("    Takes effect on the device's next connection — no server restart needed.")
}

func cmdScan(st *store.Store, ip, deviceType string) {
	fmt.Printf("[*] Scanning %s ...\n", ip)
	result, err := trust.Scan(ip)
	must(err)

	score := trust.Calculate(result)
	deviceID := deviceIDFor(deviceType, result)

	must(st.RecordScan(store.Device{
		DeviceID:         deviceID,
		IPAddress:        result.IPAddress,
		MACAddress:       result.MACAddress,
		MACVendorKnown:   score.MACVendorKnown,
		DeviceType:       deviceType,
		OpenPorts:        result.PortsJSON(),
		RiskyPortsFound:  trust.RiskyPortsCSV(score.RiskyPortsFound),
		TrustScore:       score.Value,
		OnboardingStatus: store.OnboardingStatus(score.Status),
	}))

	fmt.Printf("\nDevice ID:    %s\n", deviceID)
	fmt.Printf("IP:           %s\n", result.IPAddress)
	if result.MACAddress != "" {
		fmt.Printf("MAC:          %s\n", result.MACAddress)
	} else {
		fmt.Printf("MAC:          (not found in local neighbor table)\n")
	}
	fmt.Printf("Open ports:   %s\n", result.PortsJSON())
	fmt.Printf("\nTrust score:  %d/100  ->  %s\n", score.Value, score.Status)
	fmt.Println("Score breakdown:")
	for _, f := range score.Factors {
		fmt.Println("  " + f)
	}

	switch score.Status {
	case "trusted":
		fmt.Printf("\n[+] '%s' is eligible for certificate issuance: certctl issue %s client\n", deviceID, deviceID)
	case "pending":
		fmt.Printf("\n[!] '%s' scored borderline -- needs manual review: certctl trust %s trusted \"<reason>\"\n", deviceID, deviceID)
	default:
		fmt.Printf("\n[!] '%s' scored suspicious -- issuance is blocked unless manually overridden.\n", deviceID)
	}
}

func cmdDevices(st *store.Store) {
	devices, err := st.ListDevices()
	must(err)
	if len(devices) == 0 {
		fmt.Println("No devices scanned yet. Run: certctl scan <ip> [device-type]")
		return
	}
	fmt.Printf("%-20s %-15s %-19s %-6s %-11s %-8s %s\n", "DEVICE_ID", "IP", "MAC", "SCORE", "STATUS", "SCANS", "OPEN_PORTS")
	for _, d := range devices {
		fmt.Printf("%-20s %-15s %-19s %-6d %-11s %-8d %s\n",
			d.DeviceID, d.IPAddress, d.MACAddress, d.TrustScore, d.OnboardingStatus, d.ScanCount, d.OpenPorts)
	}
}

// deviceIDFor derives a stable identity from the scan itself, preferring
// the MAC address (harder to casually collide or spoof than an operator-
// typed name) over the raw IP, which can be reassigned by DHCP between scans.
func deviceIDFor(deviceType string, r trust.ScanResult) string {
	if r.MACAddress != "" {
		suffix := strings.ReplaceAll(r.MACAddress, ":", "")
		if len(suffix) > 6 {
			suffix = suffix[len(suffix)-6:]
		}
		return fmt.Sprintf("%s-%s", deviceType, strings.ToLower(suffix))
	}
	return fmt.Sprintf("%s-%s", deviceType, strings.ReplaceAll(r.IPAddress, ".", "-"))
}

func cmdExport(st *store.Store, name string) {
	pem, err := st.GetCertificatePEM(name)
	must(err)
	fmt.Print(pem)
	fmt.Fprintf(os.Stderr, "\n[note: read entirely from the database — no filesystem access — private key was never queried, it isn't stored here]\n")
}

func cmdList(st *store.Store) {
	certs, err := st.ListCertificates()
	must(err)
	if len(certs) == 0 {
		fmt.Println("No certificates issued yet.")
		return
	}
	fmt.Printf("%-18s %-8s %-10s %-12s %-24s %-12s %s\n", "NAME", "TYPE", "STATUS", "EXPIRES", "ALGORITHM", "BLACKLIST", "REASON")
	for _, c := range certs {
		bl := ""
		if c.Blacklisted {
			bl = "BLACKLISTED"
		}
		fmt.Printf("%-18s %-8s %-10s %-20s %-24s %-12s %s\n",
			c.Name, c.Type, c.Status, c.ExpiresAt.Format("2006-01-02"), c.Algorithm, bl, c.StatusReason)
	}
}

func cmdExpiring(st *store.Store, within time.Duration) {
	certs, err := st.ExpiringSoon(within)
	must(err)
	if len(certs) == 0 {
		fmt.Printf("No certificates expiring within %d days.\n", int(within.Hours()/24))
		return
	}
	fmt.Printf("Certificates expiring within %d days:\n", int(within.Hours()/24))
	for _, c := range certs {
		fmt.Printf("  %-18s expires %s (serial %s)\n", c.Name, c.ExpiresAt.Format("2006-01-02"), c.Serial)
	}
}

func cmdLog(st *store.Store) {
	events, err := st.RecentEvents(50)
	must(err)
	for _, e := range events {
		fmt.Printf("%s  %-16s cn=%-18s serial=%-8s %s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"), e.Type, e.CommonName, e.Serial, e.Detail)
	}
}

// readCertMeta extracts the serial (in the SAME decimal form Go's TLS stack
// reports at connection time), expiry, and human-readable algorithm string
// directly from the signed cert file, via Go's own x509 parser — not by
// re-running openssl and converting hex, which is exactly the class of bug
// that bit the flat-file version of this project (hex vs. decimal serial
// mismatch broke revocation silently).
func readCertMeta(path string) (serial string, expiresAt time.Time, algorithm string) {
	data, err := os.ReadFile(path)
	must(err)
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Println("could not decode PEM cert:", path)
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	must(err)

	keySize := ""
	if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		keySize = fmt.Sprintf("RSA-%d", rsaKey.N.BitLen())
	} else {
		keySize = fmt.Sprintf("%T", cert.PublicKey)
	}
	algorithm = fmt.Sprintf("%s / %s", keySize, cert.SignatureAlgorithm.String())

	return cert.SerialNumber.String(), cert.NotAfter, algorithm
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("command failed: %s %v: %v\n", name, args, err)
		os.Exit(1)
	}
}

func must(err error) {
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func usage() {
	fmt.Println(`certctl — embedded device PKI admin CLI

Usage:
  certctl init-ca [common-name]
  certctl scan <ip-address> [device-type-hint]
  certctl devices
  certctl trust <device-id> <trusted|pending|suspicious> [reason]
  certctl issue <name> <server|client> [san] [validity-days] [--force]
  certctl revoke <name> [reason]
  certctl blacklist <common-name> [reason]
  certctl unblacklist <common-name>
  certctl list
  certctl export <name>                             -- print public cert PEM straight from the database
  certctl expiring
  certctl log

Client (device) certs require a prior 'certctl scan' that scored the
device as trusted -- issue refuses otherwise unless --force is passed
(logged as an explicit exception, never silent).`)
}

var _ = big.NewInt // (kept for clarity that serials are big.Int-backed; not directly used)
