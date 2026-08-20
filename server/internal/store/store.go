// Package store is the single source of truth for the certificate fleet:
// every issued certificate (including its public PEM content), its current
// status (issued/revoked/expired), a separate device-level blacklist
// (blocks a device even across reissue), the network-discovered device
// inventory with trust scores gating issuance, and an append-only event
// log for every lifecycle action and authentication attempt.
//
// A note on what does and doesn't live here: certificates.cert_pem stores
// the actual public certificate — that's safe, a certificate is meant to
// be shared. Private keys are NEVER stored here, in any column, in any
// form. certificates.key_path is only a filesystem pointer to where the
// key lives on disk, kept for operator convenience — the key material
// itself stays out of the database on purpose. A database is backed up,
// replicated, and sometimes exported; a database holding every device's
// private key turns one leaked backup into a total fleet compromise. Keys
// stay on disk with restricted permissions (or, better, are generated on
// the device itself and never transit the PC at all — see docs/).
//
// Both cmd/certctl (the admin CLI) and cmd/server (the mTLS backend) open
// the same SQLite file, so "issue a cert" and "check if it's revoked"
// always agree — there's no separate flat file that can drift out of sync.
package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Status string

const (
	StatusIssued  Status = "issued"
	StatusRevoked Status = "revoked"
	StatusExpired Status = "expired"
)

type EventType string

const (
	EventIssued        EventType = "issued"
	EventRevoked       EventType = "revoked"
	EventBlacklisted   EventType = "blacklisted"
	EventUnblacklisted EventType = "unblacklisted"
	EventAuthSuccess   EventType = "auth_success"
	EventAuthDenied    EventType = "auth_denied"
	EventExpiryWarning EventType = "expiry_warning"
	EventDeviceScanned EventType = "device_scanned"
	EventTrustOverride EventType = "trust_override"
	EventIssueBlocked  EventType = "issue_blocked"
)

// OnboardingStatus reflects whether a scanned device is currently allowed
// to be issued a certificate. It is derived from TrustScore by default but
// can be set directly via SetOnboardingStatus for a manual override
// (e.g. an operator approving a device that scored borderline).
type OnboardingStatus string

const (
	StatusTrusted    OnboardingStatus = "trusted"
	StatusPending    OnboardingStatus = "pending"
	StatusSuspicious OnboardingStatus = "suspicious"
)

// Device is a network-discovered identity, independent of whether it has
// ever been issued a certificate. A device can exist here — and be scanned
// repeatedly — before certctl issue is ever allowed to run against it.
type Device struct {
	DeviceID         string
	IPAddress        string
	MACAddress       string
	MACVendorKnown   bool
	DeviceType       string
	OpenPorts        string // JSON array, e.g. "[22,80,443]"
	RiskyPortsFound  string // comma-separated list of ports that hurt the score
	TrustScore       int
	OnboardingStatus OnboardingStatus
	FirstSeen        time.Time
	LastSeen         time.Time
	ScanCount        int
}

type Certificate struct {
	Serial       string
	Name         string
	Type         string // "server" or "client"
	CommonName   string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Status       Status
	StatusReason string
	Blacklisted  bool   // set by ListCertificates by joining the blacklist table
	CertPEM      string // the public certificate itself (safe to store — it's not secret)
	KeyPath      string // where the PRIVATE key lives on disk — a pointer only, never the key material itself (see store.go doc comment)
	Algorithm    string // e.g. "RSA-2048 / sha256WithRSAEncryption", read back from the signed cert
}

type Store struct {
	db *sql.DB
}

// Open creates (if needed) and connects to the SQLite database at path,
// applying the schema idempotently.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS certificates (
		serial         TEXT PRIMARY KEY,
		name           TEXT NOT NULL,
		type           TEXT NOT NULL,
		common_name    TEXT NOT NULL,
		issued_at      DATETIME NOT NULL,
		expires_at     DATETIME NOT NULL,
		status         TEXT NOT NULL DEFAULT 'issued',
		status_reason  TEXT,
		status_changed DATETIME,
		cert_pem       TEXT,
		key_path       TEXT,
		algorithm      TEXT
	);

	CREATE TABLE IF NOT EXISTS blacklist (
		common_name TEXT PRIMARY KEY,
		reason      TEXT,
		blacklisted_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS events (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ts          DATETIME NOT NULL,
		event_type  TEXT NOT NULL,
		serial      TEXT,
		common_name TEXT,
		detail      TEXT
	);

	CREATE TABLE IF NOT EXISTS devices (
		device_id         TEXT PRIMARY KEY,
		ip_address         TEXT,
		mac_address         TEXT,
		mac_vendor_known     INTEGER NOT NULL DEFAULT 0,
		device_type           TEXT,
		open_ports             TEXT,
		risky_ports_found       TEXT,
		trust_score               INTEGER NOT NULL DEFAULT 0,
		onboarding_status          TEXT NOT NULL DEFAULT 'pending',
		first_seen                  DATETIME NOT NULL,
		last_seen                    DATETIME NOT NULL,
		scan_count                    INTEGER NOT NULL DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
	CREATE INDEX IF NOT EXISTS idx_certs_expires ON certificates(expires_at);
	`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	// Defensive migration for a database created before cert_pem/key_path/
	// algorithm existed: CREATE TABLE IF NOT EXISTS won't add columns to an
	// already-existing table, so add them explicitly and ignore the
	// "duplicate column" error on a database that already has them.
	for _, stmt := range []string{
		`ALTER TABLE certificates ADD COLUMN cert_pem TEXT`,
		`ALTER TABLE certificates ADD COLUMN key_path TEXT`,
		`ALTER TABLE certificates ADD COLUMN algorithm TEXT`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	return nil
}

// RecordIssued inserts a newly issued certificate — including its public
// PEM content, the signature algorithm, and a pointer to where the
// private key lives on disk (not the key itself) — and logs the event.
func (s *Store) RecordIssued(c Certificate) error {
	_, err := s.db.Exec(
		`INSERT INTO certificates (serial, name, type, common_name, issued_at, expires_at, status, status_changed, cert_pem, key_path, algorithm)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Serial, c.Name, c.Type, c.CommonName, c.IssuedAt, c.ExpiresAt, StatusIssued, time.Now(), c.CertPEM, c.KeyPath, c.Algorithm,
	)
	if err != nil {
		return err
	}
	return s.logEvent(EventIssued, c.Serial, c.CommonName, fmt.Sprintf("issued %s cert (%s), expires %s", c.Type, c.Algorithm, c.ExpiresAt.Format("2006-01-02")))
}

// Revoke marks a specific certificate (by serial) revoked. A reissued
// certificate for the same device gets a new serial and is unaffected —
// use Blacklist below to block a device identity regardless of serial.
func (s *Store) Revoke(serial, reason string) error {
	res, err := s.db.Exec(
		`UPDATE certificates SET status = ?, status_reason = ?, status_changed = ? WHERE serial = ?`,
		StatusRevoked, reason, time.Now(), serial,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no certificate found with serial %s", serial)
	}
	cn, _ := s.commonNameForSerial(serial)
	return s.logEvent(EventRevoked, serial, cn, reason)
}

// Blacklist blocks a device by common name — even if it's issued a brand
// new certificate later, it stays blocked until explicitly removed. This
// is the right tool for "this device is known compromised", vs Revoke
// which just invalidates one specific certificate.
func (s *Store) Blacklist(commonName, reason string) error {
	_, err := s.db.Exec(
		`INSERT INTO blacklist (common_name, reason, blacklisted_at) VALUES (?, ?, ?)
		 ON CONFLICT(common_name) DO UPDATE SET reason = excluded.reason, blacklisted_at = excluded.blacklisted_at`,
		commonName, reason, time.Now(),
	)
	if err != nil {
		return err
	}
	return s.logEvent(EventBlacklisted, "", commonName, reason)
}

func (s *Store) Unblacklist(commonName string) error {
	_, err := s.db.Exec(`DELETE FROM blacklist WHERE common_name = ?`, commonName)
	if err != nil {
		return err
	}
	return s.logEvent(EventUnblacklisted, "", commonName, "")
}

// CheckAuth is the single call the mTLS server makes per connection: it
// answers "is this serial/CN currently allowed?" and logs the outcome
// either way, so every authentication attempt — accepted or rejected —
// is in the event log, not just the rejections.
func (s *Store) CheckAuth(serial, commonName string) (allowed bool, reason string) {
	var blReason string
	err := s.db.QueryRow(`SELECT reason FROM blacklist WHERE common_name = ?`, commonName).Scan(&blReason)
	if err == nil {
		s.logEvent(EventAuthDenied, serial, commonName, "blacklisted: "+blReason)
		return false, "device is blacklisted"
	}

	var status string
	var expiresAt time.Time
	err = s.db.QueryRow(`SELECT status, expires_at FROM certificates WHERE serial = ?`, serial).Scan(&status, &expiresAt)
	if err != nil {
		s.logEvent(EventAuthDenied, serial, commonName, "unknown serial (not in issuance records)")
		return false, "certificate not recognized"
	}
	if status == string(StatusRevoked) {
		s.logEvent(EventAuthDenied, serial, commonName, "revoked")
		return false, "certificate revoked"
	}
	if time.Now().After(expiresAt) {
		s.logEvent(EventAuthDenied, serial, commonName, "expired")
		return false, "certificate expired"
	}

	s.logEvent(EventAuthSuccess, serial, commonName, "")

	// Flag (in the log, not to the device) when a valid cert is close to expiry,
	// so an operator scanning events can see it coming before it causes an outage.
	if time.Until(expiresAt) < 30*24*time.Hour {
		s.logEvent(EventExpiryWarning, serial, commonName, fmt.Sprintf("expires %s", expiresAt.Format("2006-01-02")))
	}

	return true, ""
}

func (s *Store) commonNameForSerial(serial string) (string, error) {
	var cn string
	err := s.db.QueryRow(`SELECT common_name FROM certificates WHERE serial = ?`, serial).Scan(&cn)
	return cn, err
}

func (s *Store) logEvent(t EventType, serial, commonName, detail string) error {
	_, err := s.db.Exec(
		`INSERT INTO events (ts, event_type, serial, common_name, detail) VALUES (?, ?, ?, ?, ?)`,
		time.Now(), string(t), serial, commonName, detail,
	)
	return err
}

// ListCertificates returns every certificate, most recently issued first,
// with Blacklisted set from a join against the blacklist table — so a
// device blocked at the identity level (regardless of which cert serial
// it's currently using) is visible in the same view, not just via the
// separate revoked-serial status.
func (s *Store) ListCertificates() ([]Certificate, error) {
	rows, err := s.db.Query(`
		SELECT c.serial, c.name, c.type, c.common_name, c.issued_at, c.expires_at,
		       c.status, COALESCE(c.status_reason,''), CASE WHEN b.common_name IS NULL THEN 0 ELSE 1 END,
		       COALESCE(c.key_path,''), COALESCE(c.algorithm,'')
		FROM certificates c
		LEFT JOIN blacklist b ON b.common_name = c.common_name
		ORDER BY c.issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		var c Certificate
		var bl int
		if err := rows.Scan(&c.Serial, &c.Name, &c.Type, &c.CommonName, &c.IssuedAt, &c.ExpiresAt, &c.Status, &c.StatusReason, &bl, &c.KeyPath, &c.Algorithm); err != nil {
			return nil, err
		}
		c.Blacklisted = bl == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetCertificatePEM returns the stored public certificate content for a
// device by name, read entirely from the database — no filesystem access.
// This is what proves the database is a self-contained record: you can
// hand someone a copy of pki.db and they can pull out every issued public
// certificate without needing certs/ on disk at all (they still can't get
// any private key, by design — see the package doc comment).
func (s *Store) GetCertificatePEM(name string) (pem string, err error) {
	err = s.db.QueryRow(`SELECT cert_pem FROM certificates WHERE name = ? ORDER BY issued_at DESC LIMIT 1`, name).Scan(&pem)
	return pem, err
}

// ExpiringSoon returns issued (non-revoked) certificates expiring within `within`.
func (s *Store) ExpiringSoon(within time.Duration) ([]Certificate, error) {
	rows, err := s.db.Query(
		`SELECT serial, name, type, common_name, issued_at, expires_at, status, COALESCE(status_reason,'')
		 FROM certificates WHERE status = ? AND expires_at <= ? ORDER BY expires_at ASC`,
		StatusIssued, time.Now().Add(within),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.Serial, &c.Name, &c.Type, &c.CommonName, &c.IssuedAt, &c.ExpiresAt, &c.Status, &c.StatusReason); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecentEvents returns the most recent N log entries, newest first — this
// is the "log files stored in a database" requirement: every issued,
// revoked, blacklisted, auth, and expiry-warning event lives in one
// queryable table instead of scattered flat files.
func (s *Store) RecentEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(
		`SELECT ts, event_type, COALESCE(serial,''), COALESCE(common_name,''), COALESCE(detail,'')
		 FROM events ORDER BY ts DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Timestamp, &e.Type, &e.Serial, &e.CommonName, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type Event struct {
	Timestamp  time.Time
	Type       string
	Serial     string
	CommonName string
	Detail     string
}

// RecordScan upserts a device's latest scan result. On a device seen
// before, first_seen and scan_count are preserved/incremented; on a new
// device, this is its first appearance in the inventory. Onboarding status
// is derived from the trust score unless the device already has a manual
// override recorded (SetOnboardingStatus) more recent than this scan —
// callers pass the status they want applied; ScanAndClassify in certctl
// decides whether to honor an existing manual override before calling this.
func (s *Store) RecordScan(d Device) error {
	var firstSeen time.Time
	var scanCount int
	err := s.db.QueryRow(`SELECT first_seen, scan_count FROM devices WHERE device_id = ?`, d.DeviceID).Scan(&firstSeen, &scanCount)
	if err != nil {
		firstSeen = time.Now()
		scanCount = 0
	}

	_, err = s.db.Exec(`
		INSERT INTO devices (device_id, ip_address, mac_address, mac_vendor_known, device_type,
		                      open_ports, risky_ports_found, trust_score, onboarding_status,
		                      first_seen, last_seen, scan_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			ip_address = excluded.ip_address,
			mac_address = excluded.mac_address,
			mac_vendor_known = excluded.mac_vendor_known,
			device_type = excluded.device_type,
			open_ports = excluded.open_ports,
			risky_ports_found = excluded.risky_ports_found,
			trust_score = excluded.trust_score,
			onboarding_status = excluded.onboarding_status,
			last_seen = excluded.last_seen,
			scan_count = excluded.scan_count`,
		d.DeviceID, d.IPAddress, d.MACAddress, boolToInt(d.MACVendorKnown), d.DeviceType,
		d.OpenPorts, d.RiskyPortsFound, d.TrustScore, string(d.OnboardingStatus),
		firstSeen, time.Now(), scanCount+1,
	)
	if err != nil {
		return err
	}
	return s.logEvent(EventDeviceScanned, "", d.DeviceID,
		fmt.Sprintf("trust_score=%d status=%s ports=%s", d.TrustScore, d.OnboardingStatus, d.OpenPorts))
}

// GetDevice returns the current inventory record for a device, or an error
// if it has never been scanned.
func (s *Store) GetDevice(deviceID string) (Device, error) {
	var d Device
	var macVendorKnown int
	err := s.db.QueryRow(`
		SELECT device_id, ip_address, mac_address, mac_vendor_known, device_type,
		       open_ports, risky_ports_found, trust_score, onboarding_status,
		       first_seen, last_seen, scan_count
		FROM devices WHERE device_id = ?`, deviceID,
	).Scan(&d.DeviceID, &d.IPAddress, &d.MACAddress, &macVendorKnown, &d.DeviceType,
		&d.OpenPorts, &d.RiskyPortsFound, &d.TrustScore, &d.OnboardingStatus,
		&d.FirstSeen, &d.LastSeen, &d.ScanCount)
	d.MACVendorKnown = macVendorKnown == 1
	return d, err
}

// ListDevices returns the full device inventory, most recently seen first.
func (s *Store) ListDevices() ([]Device, error) {
	rows, err := s.db.Query(`
		SELECT device_id, ip_address, mac_address, mac_vendor_known, device_type,
		       open_ports, risky_ports_found, trust_score, onboarding_status,
		       first_seen, last_seen, scan_count
		FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		var macVendorKnown int
		if err := rows.Scan(&d.DeviceID, &d.IPAddress, &d.MACAddress, &macVendorKnown, &d.DeviceType,
			&d.OpenPorts, &d.RiskyPortsFound, &d.TrustScore, &d.OnboardingStatus,
			&d.FirstSeen, &d.LastSeen, &d.ScanCount); err != nil {
			return nil, err
		}
		d.MACVendorKnown = macVendorKnown == 1
		out = append(out, d)
	}
	return out, rows.Err()
}

// SetOnboardingStatus manually overrides a device's status — e.g. an
// operator approving a device that scored "pending", or hard-rejecting one
// regardless of its score. Logged distinctly from an automatic scan result
// so the audit trail shows a human made this call, not the scoring formula.
func (s *Store) SetOnboardingStatus(deviceID string, status OnboardingStatus, reason string) error {
	res, err := s.db.Exec(`UPDATE devices SET onboarding_status = ? WHERE device_id = ?`, string(status), deviceID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no device found with id %s — scan it first", deviceID)
	}
	return s.logEvent(EventTrustOverride, "", deviceID, fmt.Sprintf("manually set to %s: %s", status, reason))
}

// CheckIssuanceAllowed is the trust gate certctl issue calls before signing
// anything for a client device: no scan record at all, or a status other
// than "trusted", blocks issuance (the caller can still force-override,
// but that path is logged separately as an explicit, named exception).
func (s *Store) CheckIssuanceAllowed(deviceID string) (allowed bool, reason string) {
	d, err := s.GetDevice(deviceID)
	if err != nil {
		return false, fmt.Sprintf("device '%s' has never been scanned — run `certctl scan` first", deviceID)
	}
	if d.OnboardingStatus != StatusTrusted {
		return false, fmt.Sprintf("device '%s' is '%s' (trust score %d) — not eligible for issuance", deviceID, d.OnboardingStatus, d.TrustScore)
	}
	return true, ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// LogIssueBlocked records that certctl issue refused to sign a cert
// because the device failed the trust gate — kept distinct from
// auth_denied (which is about an already-issued cert being used) so the
// audit trail can show "we never even issued this" separately.
func (s *Store) LogIssueBlocked(deviceID, reason string) error {
	return s.logEvent(EventIssueBlocked, "", deviceID, reason)
}

// LogTrustForceOverride records that an operator used --force to issue a
// certificate despite the device failing the trust gate — this is the
// specific, named exception path referenced in CheckIssuanceAllowed's
// caller; it must never be silent.
func (s *Store) LogTrustForceOverride(deviceID, reason string) error {
	return s.logEvent(EventTrustOverride, "", deviceID, "FORCED ISSUANCE despite: "+reason)
}
