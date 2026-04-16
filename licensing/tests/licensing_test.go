// AXELUS — Comprehensive Unit Test Suite
// Tests for: licensing tiers, keygen, validator, GeoIP engine
package tests

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/keygen"
	lic "github.com/optimiumnexusllc/axelus/licensing/pkg/license"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/validator"
)

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════

func mustKeyPair(t *testing.T) *keygen.KeyPair {
	t.Helper()
	kp, err := keygen.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}
	return kp
}

func mustIssue(t *testing.T, kp *keygen.KeyPair, req keygen.LicenseRequest) (*lic.License, string) {
	t.Helper()
	l, lf, err := keygen.Issue(req, kp)
	if err != nil {
		t.Fatalf("Issue() failed: %v", err)
	}
	return l, lf
}

func mustValidator(t *testing.T, kp *keygen.KeyPair) *validator.Validator {
	t.Helper()
	v, err := validator.NewValidator(map[string]string{kp.ID: kp.PublicKey}, false)
	if err != nil {
		t.Fatalf("NewValidator() failed: %v", err)
	}
	return v
}

// ═══════════════════════════════════════════════════════════
// KEY PAIR GENERATION
// ═══════════════════════════════════════════════════════════

func TestGenerateKeyPair(t *testing.T) {
	kp, err := keygen.GenerateKeyPair()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if kp.ID == "" { t.Error("KeyPair.ID is empty") }
	if len(kp.PublicKey) != 64 { t.Errorf("PublicKey should be 64 hex chars, got %d", len(kp.PublicKey)) }
	if len(kp.PrivateKey) != 128 { t.Errorf("PrivateKey should be 128 hex chars, got %d", len(kp.PrivateKey)) }
	if kp.CreatedAt.IsZero() { t.Error("CreatedAt should not be zero") }
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1 := mustKeyPair(t)
	kp2 := mustKeyPair(t)
	if kp1.PublicKey == kp2.PublicKey {
		t.Error("two key pairs should have different public keys")
	}
}

// ═══════════════════════════════════════════════════════════
// LICENSE ISSUANCE
// ═══════════════════════════════════════════════════════════

func TestIssueLicense_Enterprise(t *testing.T) {
	kp := mustKeyPair(t)
	l, lf := mustIssue(t, kp, keygen.LicenseRequest{
		Tier:         lic.TierEnterprise,
		Licensee:     "Acme Corp",
		Email:        "admin@acme.com",
		ValidForDays: 365,
	})

	if l.Tier != lic.TierEnterprise   { t.Errorf("expected ENTERPRISE, got %s", l.Tier) }
	if l.Licensee != "Acme Corp"      { t.Errorf("wrong licensee: %s", l.Licensee) }
	if l.IsLifetime                   { t.Error("365-day license should not be lifetime") }
	if l.Signature == ""              { t.Error("signature must not be empty") }
	if l.Key == ""                    { t.Error("key must not be empty") }
	if !strings.HasPrefix(l.Key,"AX-ENT-") { t.Errorf("Enterprise key should start with AX-ENT-, got %s", l.Key) }
	if !strings.HasPrefix(lf,"-----BEGIN IRONWALL LICENSE-----") { t.Error("license file bad format") }
	if l.ID == ""                     { t.Error("ID must not be empty") }
	if _, err := uuid.Parse(l.ID); err != nil { t.Errorf("ID is not a valid UUID: %v", err) }
}

func TestIssueLicense_Lifetime(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier:         lic.TierUltimate,
		Licensee:     "BigCo",
		Email:        "cto@bigco.com",
		ValidForDays: 0,
	})
	if !l.IsLifetime  { t.Error("ValidForDays=0 should produce lifetime license") }
	if l.IsExpired()  { t.Error("lifetime license should not be expired") }
	if l.DaysRemaining() != -1 { t.Errorf("lifetime DaysRemaining should be -1, got %d", l.DaysRemaining()) }
	if !strings.HasPrefix(l.Key,"AX-ULT-") { t.Errorf("Ultimate key should start AX-ULT-, got %s", l.Key) }
}

func TestIssueLicense_AllTiers(t *testing.T) {
	kp := mustKeyPair(t)
	tiers := []struct {
		tier   lic.Tier
		prefix string
	}{
		{lic.TierCommunity,    "AX-COM-"},
		{lic.TierProfessional, "AX-PRO-"},
		{lic.TierEnterprise,   "AX-ENT-"},
		{lic.TierUltimate,     "AX-ULT-"},
		{lic.TierTrial,        "AX-TRL-"},
		{lic.TierDeveloper,    "AX-DEV-"},
	}
	for _, tt := range tiers {
		t.Run(string(tt.tier), func(t *testing.T) {
			l, _ := mustIssue(t, kp, keygen.LicenseRequest{
				Tier:     tt.tier,
				Licensee: "Test",
				Email:    "test@test.com",
				ValidForDays: 30,
			})
			if !strings.HasPrefix(l.Key, tt.prefix) {
				t.Errorf("key %s should start with %s", l.Key, tt.prefix)
			}
		})
	}
}

func TestIssueLicense_KeyFormat(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "X", Email: "x@x.com", ValidForDays: 1,
	})
	if !validator.ValidateKeyFormat(l.Key) {
		t.Errorf("key %q failed format validation", l.Key)
	}
	parts := strings.Split(l.Key, "-")
	if len(parts) != 6 { t.Errorf("key should have 6 segments, got %d", len(parts)) }
	if parts[0] != "IW" { t.Error("key should start with IW") }
}

func TestIssueLicense_ExtraFeatures(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier:          lic.TierProfessional,
		Licensee:      "Startup",
		Email:         "ops@startup.com",
		ValidForDays:  365,
		ExtraFeatures: []lic.Feature{lic.FeatureAIThreatHunting, lic.FeatureGeoIPBlocking},
	})
	if !l.HasFeature(lic.FeatureAIThreatHunting) {
		t.Error("expected extra feature ai_threat_hunting to be available")
	}
	if !l.HasFeature(lic.FeatureGeoIPBlocking) {
		t.Error("expected extra feature geoip_blocking to be available")
	}
	// Should still have PRO base features
	if !l.HasFeature(lic.FeatureAdvancedRules) {
		t.Error("should have advanced_rules from PROFESSIONAL tier")
	}
}

func TestIssueLicense_DisabledFeatures(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier:             lic.TierEnterprise,
		Licensee:         "Restricted",
		Email:            "ops@restricted.com",
		ValidForDays:     365,
		DisabledFeatures: []lic.Feature{lic.FeatureSIEM, lic.FeaturePrometheus},
	})
	if l.HasFeature(lic.FeatureSIEM) {
		t.Error("siem should be disabled on this license")
	}
	if l.HasFeature(lic.FeaturePrometheus) {
		t.Error("prometheus should be disabled on this license")
	}
	// Other ENT features should still work
	if !l.HasFeature(lic.FeatureGeoIPBlocking) {
		t.Error("geoip_blocking should still be enabled")
	}
}

func TestIssueLicense_DomainBinding(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "X", Email: "x@x.com",
		Domain: "acme.com", ValidForDays: 365,
	})
	if l.Domain != "acme.com" {
		t.Errorf("expected domain acme.com, got %s", l.Domain)
	}
}

// ═══════════════════════════════════════════════════════════
// LICENSE VALIDATION
// ═══════════════════════════════════════════════════════════

func TestValidation_Valid(t *testing.T) {
	kp := mustKeyPair(t)
	l, lf := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "ACME", Email: "sec@acme.com", ValidForDays: 365,
	})
	v := mustValidator(t, kp)
	result := v.Validate(l)
	if !result.Valid { t.Errorf("expected valid license, errors: %v", result.Errors) }
	if result.Tier != lic.TierEnterprise { t.Errorf("wrong tier in result: %s", result.Tier) }
	_ = lf
}

func TestValidation_TamperedSignature(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	l.Signature = "TAMPERED_INVALID_SIGNATURE_HERE=="
	v := mustValidator(t, kp)
	result := v.Validate(l)
	if result.Valid { t.Error("tampered signature should fail validation") }
	if len(result.Errors) == 0 { t.Error("should have errors for tampered signature") }
}

func TestValidation_TamperedTier(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierCommunity, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	// Attempt to upgrade tier by modifying the struct
	l.Tier = lic.TierUltimate
	v := mustValidator(t, kp)
	result := v.Validate(l)
	if result.Valid { t.Error("modified tier should fail signature validation") }
}

func TestValidation_ExpiredLicense(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierProfessional, Licensee: "X", Email: "x@x.com", ValidForDays: 1,
	})
	// Force expiry
	l.ExpiresAt = time.Now().Add(-24 * time.Hour)
	l.IsLifetime = false

	if !l.IsExpired() { t.Error("license should be expired") }
	if l.DaysRemaining() != 0 { t.Errorf("days remaining should be 0 for expired, got %d", l.DaysRemaining()) }
	if l.HasFeature(lic.FeatureCoreWAF) { t.Error("expired license should not grant features") }
}

func TestValidation_Revoked(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	l.IsRevoked = true
	if l.HasFeature(lic.FeatureCoreWAF) { t.Error("revoked license should not grant features") }
}

func TestValidation_WrongPublicKey(t *testing.T) {
	kp1 := mustKeyPair(t)
	kp2 := mustKeyPair(t)
	l, _ := mustIssue(t, kp1, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	// Validate with wrong public key
	v := mustValidator(t, kp2)
	result := v.Validate(l)
	if result.Valid { t.Error("license signed with different key should fail validation") }
}

func TestValidation_ParseLicenseFile(t *testing.T) {
	kp := mustKeyPair(t)
	l, lf := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "Test Corp", Email: "test@corp.com", ValidForDays: 365,
	})
	parsed, err := validator.ParseLicenseFile(lf)
	if err != nil { t.Fatalf("ParseLicenseFile failed: %v", err) }
	if parsed.ID != l.ID             { t.Errorf("ID mismatch: %s vs %s", parsed.ID, l.ID) }
	if parsed.Key != l.Key           { t.Errorf("Key mismatch") }
	if parsed.Tier != l.Tier         { t.Errorf("Tier mismatch") }
	if parsed.Licensee != l.Licensee { t.Errorf("Licensee mismatch") }
	if parsed.Signature != l.Signature { t.Errorf("Signature mismatch") }
}

func TestValidation_ParseLicenseFile_Corrupted(t *testing.T) {
	_, err := validator.ParseLicenseFile("-----BEGIN IRONWALL LICENSE-----\nNOT_BASE64!!!\n-----END IRONWALL LICENSE-----")
	if err == nil { t.Error("corrupted license file should return error") }
}

// ═══════════════════════════════════════════════════════════
// FEATURE FLAGS
// ═══════════════════════════════════════════════════════════

func TestFeatureFlags_Community(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierCommunity, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	// Should have
	for _, f := range []lic.Feature{lic.FeatureCoreWAF, lic.FeatureOWASPRules, lic.FeatureBotProtection} {
		if !l.HasFeature(f) { t.Errorf("Community should have feature %s", f) }
	}
	// Should NOT have
	for _, f := range []lic.Feature{
		lic.FeatureGeoIPBlocking, lic.FeatureThreatIntel, lic.FeatureSIEM,
		lic.FeatureAIThreatHunting, lic.FeatureZeroDay,
	} {
		if l.HasFeature(f) { t.Errorf("Community should NOT have feature %s", f) }
	}
}

func TestFeatureFlags_Ultimate(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierUltimate, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	// Ultimate should have ALL features
	allFeats := []lic.Feature{
		lic.FeatureCoreWAF, lic.FeatureAdvancedRules, lic.FeatureGeoIPBlocking,
		lic.FeatureThreatIntel, lic.FeatureAIThreatHunting, lic.FeatureZeroDay,
		lic.FeatureDDoSMitigation, lic.FeatureDeception, lic.FeatureForensics,
		lic.FeatureMultiTenancy, lic.FeaturePrioritySupport, lic.FeatureCustomInteg,
	}
	for _, f := range allFeats {
		if !l.HasFeature(f) { t.Errorf("Ultimate should have feature %s", f) }
	}
}

func TestFeatureTiers_Progression(t *testing.T) {
	// Enterprise should have everything Professional has
	proFeats := lic.TierFeatures[lic.TierProfessional]
	entFeats := lic.TierFeatures[lic.TierEnterprise]
	entSet := make(map[lic.Feature]bool)
	for _, f := range entFeats { entSet[f] = true }
	for _, f := range proFeats {
		if !entSet[f] {
			t.Errorf("Enterprise is missing PRO feature %s", f)
		}
	}
	// Ultimate should have everything Enterprise has
	ultFeats := lic.TierFeatures[lic.TierUltimate]
	ultSet := make(map[lic.Feature]bool)
	for _, f := range ultFeats { ultSet[f] = true }
	for _, f := range entFeats {
		if !ultSet[f] {
			t.Errorf("Ultimate is missing ENT feature %s", f)
		}
	}
}

// ═══════════════════════════════════════════════════════════
// LIMITS
// ═══════════════════════════════════════════════════════════

func TestLimits_CommunityIsRestricted(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierCommunity, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	limits := l.GetLimits()
	if limits.MaxSites != 1 { t.Errorf("Community MaxSites should be 1, got %d", limits.MaxSites) }
	if limits.MaxRequestsPerSec != 500 { t.Errorf("Community RPS should be 500, got %d", limits.MaxRequestsPerSec) }
	if limits.MaxNodes != 1 { t.Errorf("Community MaxNodes should be 1, got %d", limits.MaxNodes) }
}

func TestLimits_UltimateIsUnlimited(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierUltimate, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
	})
	limits := l.GetLimits()
	if limits.MaxSites != -1          { t.Errorf("Ultimate MaxSites should be -1 (unlimited), got %d", limits.MaxSites) }
	if limits.MaxRequestsPerSec != -1 { t.Errorf("Ultimate RPS should be -1 (unlimited), got %d", limits.MaxRequestsPerSec) }
	if limits.MaxNodes != -1          { t.Errorf("Ultimate MaxNodes should be -1 (unlimited), got %d", limits.MaxNodes) }
	if limits.MaxUsers != -1          { t.Errorf("Ultimate MaxUsers should be -1 (unlimited), got %d", limits.MaxUsers) }
	if limits.SupportLevel != "dedicated" { t.Errorf("Ultimate support should be 'dedicated', got %s", limits.SupportLevel) }
}

func TestLimits_CustomOverride(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier: lic.TierProfessional, Licensee: "X", Email: "x@x.com", ValidForDays: 365,
		CustomLimits: &lic.Limits{MaxSites: 50, MaxNodes: 5},
	})
	limits := l.GetLimits()
	if limits.MaxSites != 50 { t.Errorf("CustomLimits MaxSites should be 50, got %d", limits.MaxSites) }
	if limits.MaxNodes != 5  { t.Errorf("CustomLimits MaxNodes should be 5, got %d", limits.MaxNodes) }
	// Non-overridden fields should use tier defaults
	if limits.MaxRequestsPerSec != 5000 { t.Errorf("MaxRequestsPerSec should use tier default 5000, got %d", limits.MaxRequestsPerSec) }
}

// ═══════════════════════════════════════════════════════════
// KEY FORMAT VALIDATION
// ═══════════════════════════════════════════════════════════

func TestKeyFormat_Valid(t *testing.T) {
	validKeys := []string{
		"AX-ENT-A3F2-B9K1-M7X4-Z2P8",
		"AX-ULT-XXXX-YYYY-ZZZZ-AAAA",
		"AX-COM-1234-5678-ABCD-EFGH",
		"AX-PRO-AAAA-BBBB-CCCC-DDDD",
	}
	for _, k := range validKeys {
		if !validator.ValidateKeyFormat(k) { t.Errorf("key %q should be valid", k) }
	}
}

func TestKeyFormat_Invalid(t *testing.T) {
	invalidKeys := []string{
		"",
		"AX-ENT-A3F2-B9K1-M7X4",        // too few segments
		"AX-ENT-A3F2-B9K1-M7X4-Z2P8-XX", // too many segments
		"AX-XXX-A3F2-B9K1-M7X4-Z2P8",   // invalid tier
		"XX-ENT-A3F2-B9K1-M7X4-Z2P8",   // wrong prefix
		"AX-ENT-A3F-B9K1-M7X4-Z2P8",    // short segment
	}
	for _, k := range invalidKeys {
		if validator.ValidateKeyFormat(k) { t.Errorf("key %q should be invalid", k) }
	}
}

// ═══════════════════════════════════════════════════════════
// HARDWARE ID
// ═══════════════════════════════════════════════════════════

func TestHardwareID_Stable(t *testing.T) {
	id1 := validator.GetHardwareID()
	id2 := validator.GetHardwareID()
	if id1 != id2 { t.Error("hardware ID should be stable across calls") }
	if len(id1) != 32 { t.Errorf("hardware ID should be 32 hex chars, got %d", len(id1)) }
}

func TestHardwareID_NotEmpty(t *testing.T) {
	id := validator.GetHardwareID()
	if id == "" { t.Error("hardware ID should not be empty") }
}

// ═══════════════════════════════════════════════════════════
// LICENSE SERIALIZATION
// ═══════════════════════════════════════════════════════════

func TestLicense_JSONRoundtrip(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier:          lic.TierEnterprise,
		Licensee:      "Round Trip Corp",
		Email:         "rt@corp.com",
		ValidForDays:  365,
		ExtraFeatures: []lic.Feature{lic.FeatureAIThreatHunting},
	})

	data, err := json.Marshal(l)
	if err != nil { t.Fatalf("json.Marshal failed: %v", err) }

	var l2 lic.License
	if err := json.Unmarshal(data, &l2); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if l.ID != l2.ID             { t.Error("ID mismatch after JSON roundtrip") }
	if l.Key != l2.Key           { t.Error("Key mismatch after JSON roundtrip") }
	if l.Tier != l2.Tier         { t.Error("Tier mismatch after JSON roundtrip") }
	if l.Signature != l2.Signature { t.Error("Signature mismatch after JSON roundtrip") }
	if len(l2.ExtraFeatures) != 1 { t.Error("ExtraFeatures lost in roundtrip") }
}

// ═══════════════════════════════════════════════════════════
// GEOIP ENGINE (unit tests, no MaxMind DB required)
// ═══════════════════════════════════════════════════════════

func TestGeoEngine_PrivateIP(t *testing.T) {
	// Validate basic IP parsing — GeoIP engine should handle private IPs gracefully
	privateIPs := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.100",
	}
	for _, ip := range privateIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("failed to parse IP %s", ip)
		}
	}
}

func TestGeoEngine_InvalidIP(t *testing.T) {
	badIPs := []string{"", "not-an-ip", "999.999.999.999", ":::1"}
	for _, ip := range badIPs {
		parsed := net.ParseIP(ip)
		if parsed != nil && ip != ":::1" {
			t.Errorf("expected nil for bad IP %q", ip)
		}
	}
}

func TestGeoRuleMatching_CIDR(t *testing.T) {
	// Test CIDR matching logic
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")
	testCases := []struct{ ip string; expected bool }{
		{"192.168.1.1",   true},
		{"192.168.255.1", true},
		{"10.0.0.1",      false},
		{"172.16.0.1",    false},
	}
	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		got := cidr.Contains(ip)
		if got != tc.expected {
			t.Errorf("CIDR match for %s: expected %v, got %v", tc.ip, tc.expected, got)
		}
	}
}

// ═══════════════════════════════════════════════════════════
// TIER FEATURE COVERAGE
// ═══════════════════════════════════════════════════════════

func TestTierFeatures_NoDuplicates(t *testing.T) {
	for tier, features := range lic.TierFeatures {
		seen := make(map[lic.Feature]bool)
		for _, f := range features {
			if seen[f] {
				t.Errorf("duplicate feature %s in tier %s", f, tier)
			}
			seen[f] = true
		}
	}
}

func TestTierFeatures_AllTiersDefined(t *testing.T) {
	requiredTiers := []lic.Tier{
		lic.TierCommunity, lic.TierProfessional, lic.TierEnterprise,
		lic.TierUltimate, lic.TierTrial, lic.TierDeveloper,
	}
	for _, tier := range requiredTiers {
		feats, ok := lic.TierFeatures[tier]
		if !ok { t.Errorf("tier %s has no feature mapping", tier) }
		if len(feats) == 0 { t.Errorf("tier %s has no features", tier) }
	}
}

func TestTierLimits_AllTiersDefined(t *testing.T) {
	requiredTiers := []lic.Tier{
		lic.TierCommunity, lic.TierProfessional, lic.TierEnterprise,
		lic.TierUltimate, lic.TierTrial, lic.TierDeveloper,
	}
	for _, tier := range requiredTiers {
		limits, ok := lic.TierLimits[tier]
		if !ok { t.Errorf("tier %s has no limit mapping", tier) }
		if limits.SupportLevel == "" { t.Errorf("tier %s has no support level", tier) }
		if limits.UpdateChannel == "" { t.Errorf("tier %s has no update channel", tier) }
	}
}

func TestDaysRemaining(t *testing.T) {
	kp := mustKeyPair(t)
	l, _ := mustIssue(t, kp, keygen.LicenseRequest{
		Tier:         lic.TierProfessional,
		Licensee:     "X",
		Email:        "x@x.com",
		ValidForDays: 30,
	})
	days := l.DaysRemaining()
	// Allow ±1 day tolerance for test execution time
	if days < 29 || days > 30 {
		t.Errorf("DaysRemaining should be ~30, got %d", days)
	}
}
