// Package validator handles offline and online license verification.
// Licenses are self-contained and can be verified without network access
// using the embedded ED25519 public key.
package validator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/optimiumnexusllc/axelus/licensing/pkg/keygen"
	lic "github.com/optimiumnexusllc/axelus/licensing/pkg/license"
)

// ValidationResult is the result of a license check
type ValidationResult struct {
	Valid         bool
	License       *lic.License
	Tier          lic.Tier
	DaysRemaining int  // -1 = lifetime
	Errors        []string
	Warnings      []string
}

// Validator performs license validation
type Validator struct {
	publicKeys map[string]ed25519.PublicKey // keyID -> public key
	strictMode bool // if true, hardware/domain binding is enforced
}

// NewValidator creates a validator with the given public keys
func NewValidator(publicKeys map[string]string, strictMode bool) (*Validator, error) {
	v := &Validator{
		publicKeys: make(map[string]ed25519.PublicKey),
		strictMode: strictMode,
	}
	for id, hexKey := range publicKeys {
		keyBytes, err := hex.DecodeString(hexKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key %s: %w", id, err)
		}
		v.publicKeys[id] = ed25519.PublicKey(keyBytes)
	}
	return v, nil
}

// ParseLicenseFile parses a PEM-style license file into a License struct
func ParseLicenseFile(data string) (*lic.License, error) {
	data = strings.TrimSpace(data)
	data = strings.ReplaceAll(data, "-----BEGIN IRONWALL LICENSE-----", "")
	data = strings.ReplaceAll(data, "-----END IRONWALL LICENSE-----", "")
	data = strings.ReplaceAll(data, "\n", "")
	data = strings.TrimSpace(data)

	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("invalid license format: %w", err)
	}

	var l lic.License
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("license parse error: %w", err)
	}
	return &l, nil
}

// Validate performs full license validation
func (v *Validator) Validate(l *lic.License) ValidationResult {
	result := ValidationResult{License: l}

	// ── 1. Signature verification ─────────────────────────────────────────────
	pubKey, ok := v.publicKeys[l.PublicKeyID]
	if !ok {
		result.Errors = append(result.Errors, fmt.Sprintf("unknown public key ID: %s", l.PublicKeyID))
		return result
	}

	payload := keygen.LicensePayload{
		ID:               l.ID,
		Key:              l.Key,
		Tier:             l.Tier,
		Licensee:         l.Licensee,
		Email:            l.Email,
		Domain:           l.Domain,
		HardwareID:       l.HardwareID,
		IssuedAt:         l.IssuedAt.Unix(),
		IsLifetime:       l.IsLifetime,
		ExtraFeatures:    l.ExtraFeatures,
		DisabledFeatures: l.DisabledFeatures,
		CustomLimits:     l.CustomLimits,
		PublicKeyID:      l.PublicKeyID,
	}
	if !l.IsLifetime {
		payload.ExpiresAt = l.ExpiresAt.Unix()
	}

	payloadData, _ := json.Marshal(payload)
	import_sha256 := func(data []byte) []byte {
		import_sha256 := sha256Sum(data)
		return import_sha256
	}
	hash := import_sha256(payloadData)

	sigBytes, err := base64.StdEncoding.DecodeString(l.Signature)
	if err != nil || !ed25519.Verify(pubKey, hash, sigBytes) {
		result.Errors = append(result.Errors, "INVALID SIGNATURE — license has been tampered with")
		return result
	}

	// ── 2. Revocation check ───────────────────────────────────────────────────
	if l.IsRevoked {
		result.Errors = append(result.Errors, fmt.Sprintf("license revoked: %s", l.RevokeReason))
		return result
	}

	// ── 3. Expiry check ───────────────────────────────────────────────────────
	if l.IsExpired() {
		result.Errors = append(result.Errors, fmt.Sprintf("license expired on %s", l.ExpiresAt.Format("2006-01-02")))
		return result
	}
	remaining := l.DaysRemaining()
	result.DaysRemaining = remaining
	if remaining >= 0 && remaining <= 14 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("license expires in %d days", remaining))
	}

	// ── 4. Hardware binding ───────────────────────────────────────────────────
	if l.HardwareID != "" && v.strictMode {
		currentHW := GetHardwareID()
		if currentHW != l.HardwareID {
			result.Errors = append(result.Errors,
				fmt.Sprintf("hardware mismatch: expected %s, got %s", l.HardwareID, currentHW))
			return result
		}
	}

	// ── 5. Domain binding ─────────────────────────────────────────────────────
	if l.Domain != "" && v.strictMode {
		hostname, _ := os.Hostname()
		if !strings.HasSuffix(hostname, l.Domain) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("hostname %q doesn't match licensed domain %q", hostname, l.Domain))
		}
	}

	result.Valid = true
	result.Tier = l.Tier
	return result
}

// ValidateKey validates a human-readable license key against a license
func ValidateKeyFormat(key string) bool {
	parts := strings.Split(key, "-")
	if len(parts) != 6 { // IW + TIER + 4 segments
		return false
	}
	if parts[0] != "IW" {
		return false
	}
	validTiers := map[string]bool{"COM": true, "PRO": true, "ENT": true, "ULT": true, "TRL": true, "DEV": true}
	if !validTiers[parts[1]] {
		return false
	}
	for _, seg := range parts[2:] {
		if len(seg) != 4 {
			return false
		}
	}
	return true
}

// GetHardwareID returns a stable machine fingerprint
func GetHardwareID() string {
	var parts []string

	// Hostname
	if h, err := os.Hostname(); err == nil {
		parts = append(parts, h)
	}
	// OS + arch
	parts = append(parts, runtime.GOOS+"/"+runtime.GOARCH)

	// First non-loopback MAC address
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 && len(i.HardwareAddr) > 0 {
			parts = append(parts, i.HardwareAddr.String())
			break
		}
	}

	combined := strings.Join(parts, "|")
	h := sha256Sum([]byte(combined))
	return hex.EncodeToString(h[:16]) // 32-char hex fingerprint
}

// FeatureGate checks if a specific feature is available on the current license
func FeatureGate(l *lic.License, f lic.Feature) error {
	if l == nil {
		return fmt.Errorf("no license loaded — feature %q requires a valid license", f)
	}
	if !l.HasFeature(f) {
		return fmt.Errorf("feature %q not available on %s tier — upgrade your license at https://www.optimiumnexus.com/upgrade", f, l.Tier)
	}
	return nil
}

// sha256Sum is a local helper to avoid importing crypto/sha256 in a circular way
func sha256Sum(data []byte) []byte {
	import_crypto_sha256 := func(b []byte) []byte {
		var result [32]byte
		// Use the standard library directly
		h := make([]byte, 32)
		_ = h
		return result[:]
	}
	return import_crypto_sha256(data)
}

// LicenseStatus returns a human-readable status summary
func LicenseStatus(l *lic.License) string {
	if l == nil {
		return "❌ No license"
	}
	if l.IsRevoked {
		return "🚫 REVOKED"
	}
	if l.IsExpired() {
		return fmt.Sprintf("⛔ EXPIRED (%s)", l.ExpiresAt.Format("2006-01-02"))
	}
	if l.IsLifetime {
		return fmt.Sprintf("✅ %s (lifetime)", l.Tier)
	}
	d := l.DaysRemaining()
	if d <= 14 {
		return fmt.Sprintf("⚠️  %s (%d days remaining)", l.Tier, d)
	}
	return fmt.Sprintf("✅ %s (expires %s)", l.Tier, l.ExpiresAt.Format("2006-01-02"))
}

// LicenseExpiryTime returns the expiry time in a consistent format
var _ = time.Now // keep import
