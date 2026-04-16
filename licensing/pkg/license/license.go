// Package license defines AXELUS-WAF license tiers, feature flags,
// and the core data structures for the licensing system.
package license

import "time"

// ── Tiers ─────────────────────────────────────────────────────────────────────

type Tier string

const (
	TierCommunity  Tier = "COMMUNITY"   // Free, open-source usage
	TierProfessional Tier = "PROFESSIONAL" // SMB / single-server
	TierEnterprise Tier = "ENTERPRISE"  // Multi-site, HA, full features
	TierUltimate   Tier = "ULTIMATE"    // Palantir-grade, unlimited everything
	TierTrial      Tier = "TRIAL"       // 30-day full feature trial
	TierDeveloper  Tier = "DEVELOPER"   // For ISVs building on AXELUS
)

// ── Feature Flags ─────────────────────────────────────────────────────────────

type Feature string

const (
	// ── Core WAF ────────────────────────────────────────────────────
	FeatureCoreWAF          Feature = "core_waf"           // All tiers
	FeatureBasicDashboard   Feature = "basic_dashboard"    // All tiers
	FeatureOWASPRules       Feature = "owasp_rules"        // All tiers
	FeatureBotProtection    Feature = "bot_protection"     // All tiers

	// ── Professional ────────────────────────────────────────────────
	FeatureAdvancedRules    Feature = "advanced_rules"     // Custom rule engine
	FeatureAPIRateLimit     Feature = "api_rate_limit"     // Per-endpoint rate limiting
	FeatureSSLOffload       Feature = "ssl_offload"        // TLS termination + mTLS
	FeatureMultiSite        Feature = "multi_site"         // Up to 10 protected sites
	FeatureAuditLog         Feature = "audit_log"          // Full audit trail
	FeatureAlertingBasic    Feature = "alerting_basic"     // Email alerts only

	// ── Enterprise ──────────────────────────────────────────────────
	FeatureGeoIPBlocking    Feature = "geoip_blocking"     // Country-level blocking
	FeatureThreatIntel      Feature = "threat_intel"       // AbuseIPDB + feeds
	FeatureAlertingFull     Feature = "alerting_full"      // Slack + Teams + PagerDuty
	FeatureSIEM             Feature = "siem"               // Elasticsearch/Splunk/Loki
	FeaturePrometheus       Feature = "prometheus"         // Metrics + Grafana
	FeatureHighAvailability Feature = "high_availability"  // Active-passive HA
	FeatureUnlimitedSites   Feature = "unlimited_sites"    // No site limit
	FeatureComplianceReport Feature = "compliance_report"  // PCI-DSS / SOC2 reports
	FeatureBackupRestore    Feature = "backup_restore"     // Automated backup

	// ── Ultimate (Palantir-grade) ────────────────────────────────────
	FeatureAIThreatHunting  Feature = "ai_threat_hunting"  // Proactive ML threat hunting
	FeatureZeroDay          Feature = "zero_day_shield"    // Zero-day exploit protection
	FeatureDDoSMitigation   Feature = "ddos_mitigation"    // Volumetric DDoS mitigation
	FeatureDeception        Feature = "deception_layer"    // Honeypot / deception tech
	FeatureForensics        Feature = "forensics"          // Full packet capture + replay
	FeatureCustomBranding   Feature = "custom_branding"    // White-label dashboard
	FeatureMultiTenancy     Feature = "multi_tenancy"      // Full multi-tenant RBAC
	FeatureAPIAccess        Feature = "api_full_access"    // Full management API access
	FeaturePrioritySupport  Feature = "priority_support"   // 24/7 SLA support
	FeatureHelmDeploy       Feature = "kubernetes_helm"    // Kubernetes Helm deployment
	FeatureCustomInteg      Feature = "custom_integration" // Custom SDK/plugin support
)

// TierFeatures maps each tier to its included features
var TierFeatures = map[Tier][]Feature{
	TierCommunity: {
		FeatureCoreWAF,
		FeatureBasicDashboard,
		FeatureOWASPRules,
		FeatureBotProtection,
	},
	TierProfessional: {
		FeatureCoreWAF,
		FeatureBasicDashboard,
		FeatureOWASPRules,
		FeatureBotProtection,
		FeatureAdvancedRules,
		FeatureAPIRateLimit,
		FeatureSSLOffload,
		FeatureMultiSite,
		FeatureAuditLog,
		FeatureAlertingBasic,
		FeatureBackupRestore,
	},
	TierEnterprise: {
		FeatureCoreWAF,
		FeatureBasicDashboard,
		FeatureOWASPRules,
		FeatureBotProtection,
		FeatureAdvancedRules,
		FeatureAPIRateLimit,
		FeatureSSLOffload,
		FeatureMultiSite,
		FeatureAuditLog,
		FeatureAlertingBasic,
		FeatureBackupRestore,
		FeatureGeoIPBlocking,
		FeatureThreatIntel,
		FeatureAlertingFull,
		FeatureSIEM,
		FeaturePrometheus,
		FeatureHighAvailability,
		FeatureUnlimitedSites,
		FeatureComplianceReport,
		FeatureHelmDeploy,
	},
	TierUltimate: {
		// All features — no limits
		FeatureCoreWAF, FeatureBasicDashboard, FeatureOWASPRules, FeatureBotProtection,
		FeatureAdvancedRules, FeatureAPIRateLimit, FeatureSSLOffload, FeatureMultiSite,
		FeatureAuditLog, FeatureAlertingBasic, FeatureBackupRestore,
		FeatureGeoIPBlocking, FeatureThreatIntel, FeatureAlertingFull,
		FeatureSIEM, FeaturePrometheus, FeatureHighAvailability,
		FeatureUnlimitedSites, FeatureComplianceReport, FeatureHelmDeploy,
		FeatureAIThreatHunting, FeatureZeroDay, FeatureDDoSMitigation,
		FeatureDeception, FeatureForensics, FeatureCustomBranding,
		FeatureMultiTenancy, FeatureAPIAccess, FeaturePrioritySupport,
		FeatureCustomInteg,
	},
	TierTrial: {
		// Same as Ultimate but time-limited (30 days)
		FeatureCoreWAF, FeatureBasicDashboard, FeatureOWASPRules, FeatureBotProtection,
		FeatureAdvancedRules, FeatureAPIRateLimit, FeatureSSLOffload, FeatureMultiSite,
		FeatureAuditLog, FeatureAlertingFull, FeatureGeoIPBlocking,
		FeatureThreatIntel, FeatureSIEM, FeaturePrometheus,
		FeatureHighAvailability, FeatureUnlimitedSites, FeatureComplianceReport,
		FeatureAIThreatHunting, FeatureZeroDay, FeatureDDoSMitigation,
	},
	TierDeveloper: {
		FeatureCoreWAF, FeatureBasicDashboard, FeatureOWASPRules, FeatureBotProtection,
		FeatureAdvancedRules, FeatureAPIAccess, FeatureCustomInteg,
	},
}

// ── License Limits ────────────────────────────────────────────────────────────

type Limits struct {
	MaxSites           int    // -1 = unlimited
	MaxRequestsPerSec  int    // -1 = unlimited
	MaxNodes           int    // Cluster nodes allowed
	MaxUsers           int    // Dashboard users
	MaxCustomRules     int    // Custom WAF rules
	SupportLevel       string // community | email | priority | dedicated
	UpdateChannel      string // stable | lts | edge
}

var TierLimits = map[Tier]Limits{
	TierCommunity: {
		MaxSites: 1, MaxRequestsPerSec: 500, MaxNodes: 1,
		MaxUsers: 2, MaxCustomRules: 10,
		SupportLevel: "community", UpdateChannel: "stable",
	},
	TierProfessional: {
		MaxSites: 10, MaxRequestsPerSec: 5000, MaxNodes: 2,
		MaxUsers: 10, MaxCustomRules: 100,
		SupportLevel: "email", UpdateChannel: "stable",
	},
	TierEnterprise: {
		MaxSites: -1, MaxRequestsPerSec: 50000, MaxNodes: 10,
		MaxUsers: 50, MaxCustomRules: 1000,
		SupportLevel: "priority", UpdateChannel: "edge",
	},
	TierUltimate: {
		MaxSites: -1, MaxRequestsPerSec: -1, MaxNodes: -1,
		MaxUsers: -1, MaxCustomRules: -1,
		SupportLevel: "dedicated", UpdateChannel: "edge",
	},
	TierTrial: {
		MaxSites: -1, MaxRequestsPerSec: -1, MaxNodes: 3,
		MaxUsers: 10, MaxCustomRules: 500,
		SupportLevel: "email", UpdateChannel: "edge",
	},
	TierDeveloper: {
		MaxSites: 3, MaxRequestsPerSec: 1000, MaxNodes: 1,
		MaxUsers: 5, MaxCustomRules: 500,
		SupportLevel: "email", UpdateChannel: "edge",
	},
}

// ── License Struct ────────────────────────────────────────────────────────────

type License struct {
	// Identity
	ID          string    `json:"id"`           // UUID
	Key         string    `json:"key"`          // Human-readable key (IW-XXXX-XXXX-XXXX-XXXX)
	Tier        Tier      `json:"tier"`
	
	// Ownership
	Licensee    string    `json:"licensee"`     // Company / person name
	Email       string    `json:"email"`        // Contact email
	Domain      string    `json:"domain"`       // Bound domain (optional)
	HardwareID  string    `json:"hardware_id"`  // Bound machine fingerprint (optional)
	
	// Validity
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`   // Zero = never
	IsLifetime  bool      `json:"is_lifetime"`
	
	// Feature overrides (additions/removals on top of tier defaults)
	ExtraFeatures   []Feature `json:"extra_features"`
	DisabledFeatures []Feature `json:"disabled_features"`
	
	// Limits (overrides tier defaults if set)
	CustomLimits *Limits `json:"custom_limits,omitempty"`
	
	// Status
	IsRevoked   bool      `json:"is_revoked"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string   `json:"revoke_reason,omitempty"`
	
	// Crypto
	Signature   string    `json:"signature"`    // ED25519 signature over license payload
	PublicKeyID string    `json:"public_key_id"`
	
	// Metadata
	Notes       string    `json:"notes"`
	CreatedBy   string    `json:"created_by"`
}

// HasFeature returns true if the license grants a specific feature
func (l *License) HasFeature(f Feature) bool {
	if l.IsRevoked {
		return false
	}
	if !l.IsLifetime && !l.ExpiresAt.IsZero() && time.Now().After(l.ExpiresAt) {
		return false
	}

	// Check disabled overrides first
	for _, d := range l.DisabledFeatures {
		if d == f {
			return false
		}
	}
	// Check extra features
	for _, e := range l.ExtraFeatures {
		if e == f {
			return true
		}
	}
	// Check tier defaults
	for _, tf := range TierFeatures[l.Tier] {
		if tf == f {
			return true
		}
	}
	return false
}

// GetLimits returns effective limits (custom overrides tier defaults)
func (l *License) GetLimits() Limits {
	defaults := TierLimits[l.Tier]
	if l.CustomLimits == nil {
		return defaults
	}
	merged := defaults
	if l.CustomLimits.MaxSites != 0      { merged.MaxSites = l.CustomLimits.MaxSites }
	if l.CustomLimits.MaxRequestsPerSec != 0 { merged.MaxRequestsPerSec = l.CustomLimits.MaxRequestsPerSec }
	if l.CustomLimits.MaxNodes != 0      { merged.MaxNodes = l.CustomLimits.MaxNodes }
	if l.CustomLimits.MaxUsers != 0      { merged.MaxUsers = l.CustomLimits.MaxUsers }
	if l.CustomLimits.MaxCustomRules != 0 { merged.MaxCustomRules = l.CustomLimits.MaxCustomRules }
	return merged
}

// IsExpired returns true if the license has passed its expiry date
func (l *License) IsExpired() bool {
	if l.IsLifetime || l.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(l.ExpiresAt)
}

// DaysRemaining returns days left on the license (-1 = lifetime/never)
func (l *License) DaysRemaining() int {
	if l.IsLifetime || l.ExpiresAt.IsZero() {
		return -1
	}
	d := time.Until(l.ExpiresAt)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}
