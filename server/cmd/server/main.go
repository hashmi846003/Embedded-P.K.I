// Command server is the mTLS backend for the embedded device PKI project.
//
// Every connecting device must present a certificate signed by the
// project's CA. On top of that, every authenticated request is checked
// against the shared SQLite store (internal/store) for revocation and
// blacklist status, and every attempt -- accepted or rejected -- is logged
// there too. This replaced an earlier flat-file (revoked.txt) design; see
// docs/database-migration.md for why.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"mtls-server/internal/store"
)

type deviceInfo struct {
	CommonName string    `json:"common_name"`
	Serial     string    `json:"serial"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"cert_expires"`
	SeenAt     time.Time `json:"authenticated_at"`
}

func main() {
	rootDir := envOr("PKI_ROOT", "..")
	caCertPath := envOr("CA_CERT", filepath.Join(rootDir, "certs", "ca", "ca.crt"))
	serverCertPath := envOr("SERVER_CERT", filepath.Join(rootDir, "certs", "issued", "backend-server", "backend-server.crt"))
	serverKeyPath := envOr("SERVER_KEY", filepath.Join(rootDir, "certs", "issued", "backend-server", "backend-server.key"))
	dbPath := envOr("PKI_DB", filepath.Join(rootDir, "data", "pki.db"))
	listenAddr := envOr("LISTEN_ADDR", ":4433")

	os.MkdirAll(filepath.Dir(dbPath), 0755)
	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("opening database: %v", err)
	}
	defer st.Close()

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("reading CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("failed to parse CA cert at %s", caCertPath)
	}

	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
		MinVersion: tls.VersionTLS12,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/device/data", func(w http.ResponseWriter, req *http.Request) {
		handleDeviceRequest(w, req, st)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	server := &http.Server{Addr: listenAddr, Handler: mux, TLSConfig: tlsConfig}

	log.Printf("mTLS backend listening on %s (database: %s)", listenAddr, dbPath)
	log.Fatal(server.ListenAndServeTLS(serverCertPath, serverKeyPath))
}

func handleDeviceRequest(w http.ResponseWriter, req *http.Request, st *store.Store) {
	if len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "no client certificate presented", http.StatusUnauthorized)
		return
	}
	cert := req.TLS.PeerCertificates[0]
	serial := cert.SerialNumber.String()
	cn := cert.Subject.CommonName

	allowed, reason := st.CheckAuth(serial, cn)
	if !allowed {
		log.Printf("REJECTED: CN=%s serial=%s reason=%s", cn, serial, reason)
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	info := deviceInfo{
		CommonName: cn,
		Serial:     serial,
		Issuer:     cert.Issuer.CommonName,
		NotAfter:   cert.NotAfter,
		SeenAt:     time.Now().UTC(),
	}
	log.Printf("AUTHENTICATED: CN=%s serial=%s", cn, serial)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
