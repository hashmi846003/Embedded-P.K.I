// Package trust implements device discovery (via nmap) and a weighted
// trust score used to gate certificate issuance: a device must be scanned
// and score above the "trusted" threshold before certctl issue will sign
// anything for it. This is deliberately a simple, transparent weighted
// model — not a machine-learned classifier — so every point gained or
// lost is traceable to a specific, explainable signal.
package trust

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ScanResult is what a network probe of one IP address produced, before
// any scoring is applied.
type ScanResult struct {
	IPAddress  string
	MACAddress string
	OpenPorts  []Port
}

type Port struct {
	Number  int
	Service string
}

// knownVendorOUIs is a small, illustrative set of MAC address prefixes for
// vendors common in embedded/IoT hardware. A real deployment would use a
// full IEEE OUI database; this is enough to demonstrate the signal without
// shipping a multi-megabyte lookup table in a portfolio project.
var knownVendorOUIs = map[string]string{
	"D8:F1:5B": "BeagleBoard.org",
	"C8:A0:30": "BeagleBoard.org",
	"1C:BA:8C": "Raspberry Pi Foundation",
	"B8:27:EB": "Raspberry Pi Foundation",
	"DC:A6:32": "Raspberry Pi Foundation",
	"18:FE:34": "Espressif (ESP8266/32)",
	"24:6F:28": "Espressif (ESP8266/32)",
	"AC:67:B2": "Espressif (ESP8266/32)",
	"BC:DD:C2": "Hikvision (IP cameras)",
	"44:19:B6": "Hikvision (IP cameras)",
	"00:12:12": "Cisco",
}

// riskyPorts flags services that are disproportionately associated with
// weak/default-credential IoT compromises (Mirai-class botnets and
// successors specifically target telnet and TR-069 CWMP).
var riskyPorts = map[int]string{
	21:   "FTP — often anonymous/default creds on embedded devices",
	23:   "Telnet — plaintext, the single most common IoT botnet vector",
	3389: "RDP — not expected on an embedded/IoT device at all",
	5900: "VNC — frequently deployed with no or default password",
	7547: "TR-069 CWMP — widely exploited in home-router botnets",
}

// Scan runs an nmap service scan against a single IP and reads its MAC
// from the kernel's neighbor table (works for devices on the same local
// subnet — the normal case for IoT gear behind a gateway/USB link).
func Scan(ip string) (ScanResult, error) {
	res := ScanResult{IPAddress: ip}

	out, err := exec.Command("nmap", "-T4", "-sV", "--open", ip).CombinedOutput()
	if err != nil {
		return res, fmt.Errorf("nmap failed: %w (output: %s)", err, string(out))
	}
	res.OpenPorts = parseNmapPorts(string(out))

	if mac, err := lookupMAC(ip); err == nil {
		res.MACAddress = mac
	}
	// A device that's actually the machine running the scan (e.g. testing
	// against localhost) has no neighbor-table MAC — that's expected, not
	// an error; the score treats an unknown MAC neutrally, not as risky.

	return res, nil
}

var nmapPortLine = regexp.MustCompile(`^(\d+)/tcp\s+open\s+(\S+)`)

func parseNmapPorts(nmapOutput string) []Port {
	var ports []Port
	for _, line := range strings.Split(nmapOutput, "\n") {
		m := nmapPortLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		ports = append(ports, Port{Number: n, Service: m[2]})
	}
	return ports
}

func lookupMAC(ip string) (string, error) {
	out, err := exec.Command("ip", "neigh", "show", ip).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "lladdr" && i+1 < len(fields) {
			return strings.ToUpper(fields[i+1]), nil
		}
	}
	return "", fmt.Errorf("no MAC found for %s (not in local ARP/neighbor table)", ip)
}

// Score is the outcome of applying the weighted model to a ScanResult:
// the final 0-100 score, which factors moved it, and the recommended
// onboarding status. Every factor is included even when it didn't fire,
// so the caller can show a full breakdown, not just the winning reasons.
type Score struct {
	Value           int
	Status          string // "trusted" | "pending" | "suspicious"
	Factors         []string
	MACVendorKnown  bool
	VendorName      string
	RiskyPortsFound []int
}

// Calculate applies the weighted trust model described in the project's
// docs: known-vendor MAC and a small open-port count push the score up;
// any historically-exploited port (telnet, TR-069, etc.) or an unknown/
// locally-administered MAC pulls it down hard, since those are the two
// strongest available signals from a network-only vantage point.
func Calculate(scan ScanResult) Score {
	score := 50 // neutral baseline
	var factors []string

	vendorKnown, vendorName := matchVendor(scan.MACAddress)
	if vendorKnown {
		score += 20
		factors = append(factors, fmt.Sprintf("+20: known embedded/IoT vendor MAC (%s)", vendorName))
	} else if scan.MACAddress == "" {
		factors = append(factors, "+0: MAC unknown (not in local neighbor table — neutral, not penalized)")
	} else if isLocallyAdministered(scan.MACAddress) {
		score -= 30
		factors = append(factors, "-30: MAC has the locally-administered bit set (common spoofing/randomization signal)")
	} else {
		factors = append(factors, "+0: MAC vendor not in the known embedded/IoT list (neutral)")
	}

	if len(scan.OpenPorts) <= 3 {
		score += 15
		factors = append(factors, fmt.Sprintf("+15: small open-port count (%d) — typical of a single-purpose embedded device", len(scan.OpenPorts)))
	} else {
		factors = append(factors, fmt.Sprintf("+0: %d open ports — more than expected for a single-purpose device", len(scan.OpenPorts)))
	}

	var risky []int
	for _, p := range scan.OpenPorts {
		if reason, isRisky := riskyPorts[p.Number]; isRisky {
			risky = append(risky, p.Number)
			factors = append(factors, fmt.Sprintf("-50: port %d open — %s", p.Number, reason))
			score -= 50
		}
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}

	status := "suspicious"
	switch {
	case score >= 70:
		status = "trusted"
	case score >= 40:
		status = "pending"
	}

	return Score{
		Value:           score,
		Status:          status,
		Factors:         factors,
		MACVendorKnown:  vendorKnown,
		VendorName:      vendorName,
		RiskyPortsFound: risky,
	}
}

func matchVendor(mac string) (known bool, vendor string) {
	if mac == "" {
		return false, ""
	}
	prefix := strings.ToUpper(mac)
	if len(prefix) >= 8 {
		prefix = prefix[:8]
	}
	if v, ok := knownVendorOUIs[prefix]; ok {
		return true, v
	}
	return false, ""
}

// isLocallyAdministered checks the second bit of the first octet — the
// standard IEEE indicator that a MAC was set in software (common in
// randomized/spoofed addresses) rather than burned in by a manufacturer.
func isLocallyAdministered(mac string) bool {
	parts := strings.Split(mac, ":")
	if len(parts) == 0 {
		return false
	}
	b, err := strconv.ParseUint(parts[0], 16, 8)
	if err != nil {
		return false
	}
	return b&0x02 != 0
}

// PortsJSON renders the open ports as the compact JSON array stored in
// the devices table (e.g. "[22,80,443]").
func (r ScanResult) PortsJSON() string {
	nums := make([]int, len(r.OpenPorts))
	for i, p := range r.OpenPorts {
		nums[i] = p.Number
	}
	b, _ := json.Marshal(nums)
	return string(b)
}

// RiskyPortsCSV renders risky port numbers as "23,7547" for storage.
func RiskyPortsCSV(nums []int) string {
	strs := make([]string, len(nums))
	for i, n := range nums {
		strs[i] = strconv.Itoa(n)
	}
	return strings.Join(strs, ",")
}
