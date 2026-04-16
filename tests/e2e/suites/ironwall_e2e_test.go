// AXELUS-WAF — End-to-End Integration Test Suite
// Tests the full stack: WAF → License → GeoIP → RateLimit → ZeroDay → Portal
// Run: go test ./tests/e2e/... -v -timeout 120s
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/keygen"
	lic "github.com/optimiumnexusllc/axelus/licensing/pkg/license"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/validator"
	"github.com/optimiumnexusllc/axelus/premium/ddos/pkg/engine"
	zdscorer "github.com/optimiumnexusllc/axelus/premium/zerodayshield/pkg/scorer"
	zdapi "github.com/optimiumnexusllc/axelus/premium/zerodayshield/pkg/api"
	geoengine "github.com/optimiumnexusllc/axelus/geoip/pkg"
)

// ── Test Fixtures ─────────────────────────────────────────────────────────────

type TestFixtures struct {
	KeyPair    *keygen.KeyPair
	Validator  *validator.Validator
	Licenses   map[string]*lic.License  // tier → license
	LicFiles   map[string]string        // tier → PEM file
}

func setupFixtures(t *testing.T) *TestFixtures {
	t.Helper()
	kp, err := keygen.GenerateKeyPair()
	if err != nil { t.Fatalf("keygen failed: %v", err) }

	v, err := validator.NewValidator(map[string]string{kp.ID: kp.PublicKey}, false)
	if err != nil { t.Fatalf("validator init failed: %v", err) }

	f := &TestFixtures{
		KeyPair:   kp,
		Validator: v,
		Licenses:  make(map[string]*lic.License),
		LicFiles:  make(map[string]string),
	}

	tiers := []lic.Tier{
		lic.TierCommunity, lic.TierProfessional,
		lic.TierEnterprise, lic.TierUltimate, lic.TierTrial,
	}
	for _, tier := range tiers {
		l, lf, err := keygen.Issue(keygen.LicenseRequest{
			Tier:         tier,
			Licensee:     "E2E Test Corp — " + string(tier),
			Email:        "e2e@test.axelus.local",
			ValidForDays: 30,
		}, kp)
		if err != nil { t.Fatalf("issue %s failed: %v", tier, err) }
		f.Licenses[string(tier)]  = l
		f.LicFiles[string(tier)]  = lf
	}
	return f
}

// ── Helper: JSON HTTP client ───────────────────────────────────────────────────

type APIClient struct {
	base    string
	client  *http.Client
	headers map[string]string
}

func newClient(base string) *APIClient {
	return &APIClient{
		base: base,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		headers: make(map[string]string),
	}
}

func (c *APIClient) WithHeader(k, v string) *APIClient {
	c.headers[k] = v; return c
}

func (c *APIClient) Post(path string, body interface{}) (*http.Response, map[string]interface{}, error) {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", c.base+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers { req.Header.Set(k, v) }
	resp, err := c.client.Do(req)
	if err != nil { return nil, nil, err }
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return resp, result, nil
}

func (c *APIClient) Get(path string) (*http.Response, map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", c.base+path, nil)
	for k, v := range c.headers { req.Header.Set(k, v) }
	resp, err := c.client.Do(req)
	if err != nil { return nil, nil, err }
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return resp, result, nil
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 1: LICENSE SYSTEM E2E
// ════════════════════════════════════════════════════════════════════════════════

func TestE2E_License_IssueAndValidate_AllTiers(t *testing.T) {
	f := setupFixtures(t)

	tiers := []struct {
		tier    string
		feature lic.Feature
		hasIt   bool
	}{
		{"COMMUNITY",    lic.FeatureCoreWAF,        true},
		{"COMMUNITY",    lic.FeatureGeoIPBlocking,   false},
		{"PROFESSIONAL", lic.FeatureAPIRateLimit,    true},
		{"PROFESSIONAL", lic.FeatureAIThreatHunting, false},
		{"ENTERPRISE",   lic.FeatureSIEM,            true},
		{"ENTERPRISE",   lic.FeatureZeroDay,         false},
		{"ULTIMATE",     lic.FeatureZeroDay,         true},
		{"ULTIMATE",     lic.FeatureDDoSMitigation,  true},
		{"TRIAL",        lic.FeatureThreatIntel,     true},
	}

	for _, tt := range tiers {
		t.Run(fmt.Sprintf("%s/%s=%v", tt.tier, tt.feature, tt.hasIt), func(t *testing.T) {
			l := f.Licenses[tt.tier]
			if l == nil { t.Fatalf("no %s license in fixtures", tt.tier) }

			result := f.Validator.Validate(l)
			if !result.Valid {
				t.Fatalf("license should be valid, errors: %v", result.Errors)
			}
			got := l.HasFeature(tt.feature)
			if got != tt.hasIt {
				t.Errorf("HasFeature(%s) on %s: want %v, got %v", tt.feature, tt.tier, tt.hasIt, got)
			}
		})
	}
}

func TestE2E_License_PEMRoundtrip(t *testing.T) {
	f := setupFixtures(t)
	for tier, licFile := range f.LicFiles {
		t.Run(tier, func(t *testing.T) {
			parsed, err := validator.ParseLicenseFile(licFile)
			if err != nil { t.Fatalf("ParseLicenseFile failed: %v", err) }

			original := f.Licenses[tier]
			if parsed.ID != original.ID      { t.Errorf("ID mismatch") }
			if parsed.Key != original.Key    { t.Errorf("Key mismatch") }
			if parsed.Tier != original.Tier  { t.Errorf("Tier mismatch") }

			result := f.Validator.Validate(parsed)
			if !result.Valid {
				t.Errorf("parsed license invalid: %v", result.Errors)
			}
		})
	}
}

func TestE2E_License_TamperedPayload(t *testing.T) {
	f := setupFixtures(t)
	l := f.Licenses["COMMUNITY"]
	// Attempt privilege escalation
	l.Tier = lic.TierUltimate
	result := f.Validator.Validate(l)
	if result.Valid {
		t.Error("tampered tier should fail validation — privilege escalation must be caught")
	}
}

func TestE2E_License_Expiry(t *testing.T) {
	f := setupFixtures(t)
	kp := f.KeyPair

	// Issue a license that is already expired
	l, _, _ := keygen.Issue(keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "Expired", Email: "exp@test.com", ValidForDays: 1,
	}, kp)
	l.ExpiresAt = time.Now().Add(-1 * time.Hour)
	l.IsLifetime = false

	if !l.IsExpired()       { t.Error("license should be expired") }
	if l.HasFeature(lic.FeatureCoreWAF) { t.Error("expired license should not grant features") }
	if l.DaysRemaining() != 0 { t.Errorf("DaysRemaining should be 0, got %d", l.DaysRemaining()) }
}

func TestE2E_License_BulkIssuance(t *testing.T) {
	f := setupFixtures(t)
	kp := f.KeyPair
	const batchSize = 50

	start := time.Now()
	for i := 0; i < batchSize; i++ {
		l, lf, err := keygen.Issue(keygen.LicenseRequest{
			Tier:         lic.TierProfessional,
			Licensee:     fmt.Sprintf("Bulk Client %d", i),
			Email:        fmt.Sprintf("client%d@bulk.test", i),
			ValidForDays: 365,
		}, kp)
		if err != nil { t.Fatalf("batch %d failed: %v", i, err) }
		if l.Key == ""  { t.Errorf("batch %d: empty key", i) }
		if lf == ""     { t.Errorf("batch %d: empty license file", i) }
	}
	elapsed := time.Since(start)
	t.Logf("Issued %d licenses in %s (%.1f/sec)", batchSize, elapsed, float64(batchSize)/elapsed.Seconds())

	// Must be able to issue 50 licenses under 5 seconds
	if elapsed > 5*time.Second {
		t.Errorf("bulk issuance too slow: %s for %d licenses", elapsed, batchSize)
	}
	_ = f
}

func TestE2E_License_HardwareBinding(t *testing.T) {
	f := setupFixtures(t)
	hwID := validator.GetHardwareID()

	l, _, _ := keygen.Issue(keygen.LicenseRequest{
		Tier:         lic.TierEnterprise,
		Licensee:     "Bound Corp",
		Email:        "bound@corp.test",
		HardwareID:   hwID,
		ValidForDays: 365,
	}, f.KeyPair)

	if l.HardwareID != hwID {
		t.Errorf("hardware ID not persisted in license: want %s, got %s", hwID, l.HardwareID)
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 2: LICENSE REST API E2E (httptest)
// ════════════════════════════════════════════════════════════════════════════════

func setupLicenseAPI(t *testing.T, f *TestFixtures) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()

	const adminKey = "e2e-admin-key"
	os.Setenv("LICENSE_ADMIN_KEY", adminKey)

	// Minimal inline license API for E2E
	r.GET("/api/v1/licensing/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.POST("/api/v1/licensing/validate", func(c *gin.Context) {
		var body struct {
			LicenseFile string      `json:"license_file"`
			Feature     lic.Feature `json:"feature"`
		}
		c.ShouldBindJSON(&body)
		parsed, err := validator.ParseLicenseFile(body.LicenseFile)
		if err != nil {
			c.JSON(400, gin.H{"valid": false, "error": err.Error()})
			return
		}
		result := f.Validator.Validate(parsed)
		resp := gin.H{
			"valid":          result.Valid,
			"tier":           parsed.Tier,
			"days_remaining": parsed.DaysRemaining(),
			"errors":         result.Errors,
		}
		if body.Feature != "" {
			resp["feature_available"] = parsed.HasFeature(body.Feature)
		}
		status := 200
		if !result.Valid { status = 403 }
		c.JSON(status, resp)
	})
	r.POST("/api/v1/licensing/admin/licenses", func(c *gin.Context) {
		if c.GetHeader("X-Admin-Key") != adminKey {
			c.JSON(401, gin.H{"error": "unauthorized"}); return
		}
		var req keygen.LicenseRequest
		c.ShouldBindJSON(&req)
		l, lf, err := keygen.Issue(req, f.KeyPair)
		if err != nil { c.JSON(500, gin.H{"error": err.Error()}); return }
		c.JSON(201, gin.H{"key": l.Key, "tier": l.Tier, "license_file": lf})
	})

	return httptest.NewServer(r)
}

func TestE2E_LicenseAPI_HealthCheck(t *testing.T) {
	f := setupFixtures(t)
	srv := setupLicenseAPI(t, f)
	defer srv.Close()

	client := newClient(srv.URL)
	resp, body, err := client.Get("/api/v1/licensing/health")
	if err != nil { t.Fatalf("health check failed: %v", err) }
	if resp.StatusCode != 200 { t.Errorf("want 200, got %d", resp.StatusCode) }
	if body["status"] != "ok" { t.Errorf("want status=ok, got %v", body["status"]) }
}

func TestE2E_LicenseAPI_ValidateLicense(t *testing.T) {
	f := setupFixtures(t)
	srv := setupLicenseAPI(t, f)
	defer srv.Close()

	client := newClient(srv.URL)
	resp, body, err := client.Post("/api/v1/licensing/validate", map[string]interface{}{
		"license_file": f.LicFiles["ENTERPRISE"],
		"feature":      "siem",
	})
	if err != nil { t.Fatalf("validate request failed: %v", err) }
	if resp.StatusCode != 200 { t.Errorf("want 200, got %d: %v", resp.StatusCode, body) }
	if body["valid"] != true { t.Errorf("license should be valid: %v", body) }
	if body["tier"] != "ENTERPRISE" { t.Errorf("wrong tier: %v", body["tier"]) }
	if body["feature_available"] != true { t.Errorf("siem should be available on Enterprise") }
}

func TestE2E_LicenseAPI_ValidateTamperedLicense(t *testing.T) {
	f := setupFixtures(t)
	srv := setupLicenseAPI(t, f)
	defer srv.Close()

	// Corrupt the license file
	corrupted := strings.Replace(f.LicFiles["ULTIMATE"], "ULTIMATE", "COMMUNITY", 1)

	client := newClient(srv.URL)
	resp, body, _ := client.Post("/api/v1/licensing/validate", map[string]interface{}{
		"license_file": corrupted,
	})
	if resp.StatusCode != 400 && resp.StatusCode != 403 {
		t.Errorf("tampered license should return 400/403, got %d: %v", resp.StatusCode, body)
	}
}

func TestE2E_LicenseAPI_IssueWithoutAuth(t *testing.T) {
	f := setupFixtures(t)
	srv := setupLicenseAPI(t, f)
	defer srv.Close()

	client := newClient(srv.URL) // no admin key
	resp, _, _ := client.Post("/api/v1/licensing/admin/licenses", map[string]interface{}{
		"tier": "ENTERPRISE", "licensee": "hacker", "email": "hack@evil.com",
	})
	if resp.StatusCode != 401 {
		t.Errorf("unauthenticated issue should return 401, got %d", resp.StatusCode)
	}
}

func TestE2E_LicenseAPI_IssueWithAuth(t *testing.T) {
	f := setupFixtures(t)
	srv := setupLicenseAPI(t, f)
	defer srv.Close()

	client := newClient(srv.URL).WithHeader("X-Admin-Key", "e2e-admin-key")
	resp, body, err := client.Post("/api/v1/licensing/admin/licenses", map[string]interface{}{
		"tier": "PROFESSIONAL", "licensee": "E2E Corp",
		"email": "e2e@corp.test", "valid_for_days": 365,
	})
	if err != nil { t.Fatalf("issue request failed: %v", err) }
	if resp.StatusCode != 201 { t.Errorf("want 201, got %d: %v", resp.StatusCode, body) }
	if body["key"] == nil || body["key"] == "" { t.Errorf("no license key in response") }
	if !strings.HasPrefix(fmt.Sprint(body["key"]), "AX-PRO-") {
		t.Errorf("wrong key prefix: %v", body["key"])
	}
}

func TestE2E_LicenseAPI_FeatureGating(t *testing.T) {
	f := setupFixtures(t)
	srv := setupLicenseAPI(t, f)
	defer srv.Close()
	client := newClient(srv.URL)

	tests := []struct {
		tier    string
		feature string
		wantAvail bool
	}{
		{"COMMUNITY",    "geoip_blocking",   false},
		{"PROFESSIONAL", "api_rate_limit",   true},
		{"ENTERPRISE",   "siem",             true},
		{"ENTERPRISE",   "ai_threat_hunting",false},
		{"ULTIMATE",     "ai_threat_hunting",true},
		{"ULTIMATE",     "forensics",        true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.tier, tt.feature), func(t *testing.T) {
			_, body, _ := client.Post("/api/v1/licensing/validate", map[string]interface{}{
				"license_file": f.LicFiles[tt.tier],
				"feature":      tt.feature,
			})
			got := body["feature_available"] == true
			if got != tt.wantAvail {
				t.Errorf("feature %s on %s: want %v, got %v", tt.feature, tt.tier, tt.wantAvail, got)
			}
		})
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 3: ZERO-DAY SHIELD E2E
// ════════════════════════════════════════════════════════════════════════════════

func setupZeroDayAPI(t *testing.T) (*zdscorer.Scorer, *httptest.Server) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	sc := zdscorer.NewScorer(zdscorer.ScorerConfig{
		ZeroDayThreshold: 0.85,
		AnomalyThreshold: 0.70,
		SuspectThreshold: 0.50,
		MinTrainSamples:  10, // low for tests
	})

	// Train the model with synthetic normal traffic
	for i := 0; i < 20; i++ {
		sc.Score(zdscorer.RequestInput{
			IP: "192.168.1.1", Method: "GET",
			Path: fmt.Sprintf("/api/resource/%d", i),
			Query: "page=1&limit=20", Body: "",
			UserAgent: "Mozilla/5.0 Chrome/120",
			Timestamp: time.Now(),
		})
	}

	shield := zdapi.New(sc, zdapi.ShieldConfig{
		BlockOnZeroDay: true,
		BlockOnAnomaly: false,
		MaxBodyBytes:   1024,
	})

	r := gin.New()
	shield.Register(r.Group("/api/open"))
	r.POST("/test/score", func(c *gin.Context) {
		shield.Middleware()(c)
		if !c.IsAborted() {
			score := c.GetFloat64("zeroday.score")
			level := c.GetString("zeroday.level")
			c.JSON(200, gin.H{"score": score, "level": level, "passed": true})
		}
	})
	return sc, httptest.NewServer(r)
}

func TestE2E_ZeroDay_NormalRequestPasses(t *testing.T) {
	_, srv := setupZeroDayAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)

	resp, body, err := client.Post("/test/score", map[string]interface{}{
		"method": "GET", "path": "/api/users", "query": "limit=10",
	})
	if err != nil { t.Fatalf("request failed: %v", err) }
	if resp.StatusCode != 200 { t.Errorf("normal request should pass, got %d: %v", resp.StatusCode, body) }
}

func TestE2E_ZeroDay_HealthEndpoint(t *testing.T) {
	_, srv := setupZeroDayAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)
	resp, body, _ := client.Get("/api/open/zerodayshield/health")
	if resp.StatusCode != 200 { t.Errorf("health should return 200, got %d", resp.StatusCode) }
	if body["status"] != "ok" { t.Errorf("health status should be ok: %v", body) }
}

func TestE2E_ZeroDay_ScoreEndpoint(t *testing.T) {
	_, srv := setupZeroDayAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)

	resp, body, err := client.Post("/api/open/zerodayshield/score", map[string]interface{}{
		"ip":     "1.2.3.4",
		"method": "GET",
		"path":   "/api/normal",
		"query":  "id=123",
		"body":   "",
	})
	if err != nil { t.Fatalf("score request failed: %v", err) }
	if resp.StatusCode != 200 { t.Errorf("score endpoint should return 200, got %d: %v", resp.StatusCode, body) }
	if _, ok := body["score"]; !ok { t.Error("response should contain 'score'") }
	if _, ok := body["level"]; !ok { t.Error("response should contain 'level'") }
}

func TestE2E_ZeroDay_StatsEndpoint(t *testing.T) {
	_, srv := setupZeroDayAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)
	resp, body, _ := client.Get("/api/open/zerodayshield/stats")
	if resp.StatusCode != 200 { t.Errorf("stats should return 200, got %d", resp.StatusCode) }
	if _, ok := body["trained"]; !ok { t.Error("stats should contain 'trained'") }
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 4: DDoS MITIGATION E2E
// ════════════════════════════════════════════════════════════════════════════════

func setupDDoSAPI(t *testing.T) (*engine.Engine, *httptest.Server) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := engine.DefaultConfig()
	cfg.IPRPSBlock = 3       // Low thresholds for testing
	cfg.IPRPSChallenge = 2
	cfg.AdaptiveEnabled = false  // Deterministic in tests

	eng := engine.New(cfg, nil, nil)

	r := gin.New()
	r.Use(eng.Middleware())
	eng.Register(r.Group("/api/open"))
	r.GET("/test/hello", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	return eng, httptest.NewServer(r)
}

func TestE2E_DDoS_NormalTrafficPasses(t *testing.T) {
	_, srv := setupDDoSAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)

	resp, _, err := client.Get("/test/hello")
	if err != nil { t.Fatalf("request failed: %v", err) }
	if resp.StatusCode != 200 { t.Errorf("normal request should pass, got %d", resp.StatusCode) }
}

func TestE2E_DDoS_FloodGetsBlocked(t *testing.T) {
	_, srv := setupDDoSAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)

	// Send requests rapidly — should hit block threshold
	var blocked int
	for i := 0; i < 10; i++ {
		resp, _, _ := client.Get("/test/hello")
		if resp.StatusCode == 429 { blocked++ }
	}
	if blocked == 0 {
		t.Error("flood traffic should have been blocked at least once (429)")
	}
	t.Logf("Blocked %d/10 flood requests", blocked)
}

func TestE2E_DDoS_ManualBlacklist(t *testing.T) {
	eng, srv := setupDDoSAPI(t)
	defer srv.Close()

	// Manually blacklist an IP
	eng.Blacklist("10.0.0.99", 5*time.Minute)

	client := newClient(srv.URL)
	// We can't easily send requests "as" 10.0.0.99 from httptest,
	// but we can verify the engine state
	stats := eng.GetStats()
	if blacklisted, ok := stats["blacklisted_ips"].(int); !ok || blacklisted < 1 {
		t.Errorf("blacklist should have 1+ IPs, got: %v", stats["blacklisted_ips"])
	}
}

func TestE2E_DDoS_StatsEndpoint(t *testing.T) {
	_, srv := setupDDoSAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)
	resp, body, _ := client.Get("/api/open/ddos/stats")
	if resp.StatusCode != 200 { t.Errorf("stats should return 200, got %d", resp.StatusCode) }
	if _, ok := body["blacklisted_ips"]; !ok { t.Error("stats should have blacklisted_ips") }
}

func TestE2E_DDoS_EventsEndpoint(t *testing.T) {
	_, srv := setupDDoSAPI(t)
	defer srv.Close()
	client := newClient(srv.URL)
	resp, body, _ := client.Get("/api/open/ddos/events?limit=10")
	if resp.StatusCode != 200 { t.Errorf("events should return 200, got %d", resp.StatusCode) }
	if _, ok := body["events"]; !ok { t.Error("response should have 'events'") }
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 5: GeoIP ENGINE E2E
// ════════════════════════════════════════════════════════════════════════════════

func setupGeoEngine(t *testing.T) *geoengine.Engine {
	t.Helper()
	eng, err := geoengine.New(geoengine.Config{
		DefaultAction: geoengine.ActionAllow,
	})
	if err != nil { t.Fatalf("geoip engine init failed: %v", err) }

	// Add test rules
	eng.AddRule(geoengine.GeoRule{
		ID: "test-block-KP", Target: geoengine.TargetCountry,
		Value: "KP", Action: geoengine.ActionBlock, Priority: 1, Enabled: true,
	})
	eng.AddRule(geoengine.GeoRule{
		ID: "test-block-cidr", Target: geoengine.TargetCIDR,
		Value: "10.0.99.0/24", Action: geoengine.ActionBlock, Priority: 5, Enabled: true,
	})
	return eng
}

func TestE2E_GeoIP_RuleManagement(t *testing.T) {
	eng := setupGeoEngine(t)
	rules := eng.GetRules()
	if len(rules) < 2 { t.Errorf("expected ≥2 rules, got %d", len(rules)) }

	// Verify rule IDs
	ids := make(map[string]bool)
	for _, r := range rules { ids[r.ID] = true }
	if !ids["test-block-KP"]   { t.Error("test-block-KP rule not found") }
	if !ids["test-block-cidr"] { t.Error("test-block-cidr rule not found") }
}

func TestE2E_GeoIP_RemoveRule(t *testing.T) {
	eng := setupGeoEngine(t)
	removed := eng.RemoveRule("test-block-KP")
	if !removed { t.Error("RemoveRule should return true for existing rule") }

	rules := eng.GetRules()
	for _, r := range rules {
		if r.ID == "test-block-KP" { t.Error("removed rule still present") }
	}
}

func TestE2E_GeoIP_CIDRMatching(t *testing.T) {
	eng := setupGeoEngine(t)

	// IPs in the blocked CIDR
	blockedIPs := []string{"10.0.99.1", "10.0.99.100", "10.0.99.254"}
	for _, ip := range blockedIPs {
		dec, err := eng.Evaluate(ip)
		if err != nil { t.Fatalf("evaluate %s: %v", ip, err) }
		if dec.Action != geoengine.ActionBlock {
			t.Errorf("IP %s in blocked CIDR should be blocked, got %s", ip, dec.Action)
		}
	}

	// IPs outside the blocked CIDR
	allowedIPs := []string{"10.0.98.1", "192.168.1.1", "8.8.8.8"}
	for _, ip := range allowedIPs {
		dec, err := eng.Evaluate(ip)
		if err != nil { t.Fatalf("evaluate %s: %v", ip, err) }
		if dec.Action == geoengine.ActionBlock {
			t.Errorf("IP %s should not be blocked by CIDR rule, got %s", ip, dec.Action)
		}
	}
}

func TestE2E_GeoIP_Priority(t *testing.T) {
	eng, _ := geoengine.New(geoengine.Config{DefaultAction: geoengine.ActionAllow})

	// Higher priority allow rule should override lower priority block
	eng.AddRule(geoengine.GeoRule{
		ID: "block-subnet", Target: geoengine.TargetCIDR,
		Value: "1.2.3.0/24", Action: geoengine.ActionBlock, Priority: 10, Enabled: true,
	})
	eng.AddRule(geoengine.GeoRule{
		ID: "allow-specific", Target: geoengine.TargetCIDR,
		Value: "1.2.3.4/32", Action: geoengine.ActionAllow, Priority: 1, Enabled: true,
	})

	dec, _ := eng.Evaluate("1.2.3.4")
	if dec.Action != geoengine.ActionAllow {
		t.Errorf("higher-priority allow rule should win, got %s", dec.Action)
	}
	dec2, _ := eng.Evaluate("1.2.3.100")
	if dec2.Action != geoengine.ActionBlock {
		t.Errorf("other IPs in subnet should still be blocked, got %s", dec2.Action)
	}
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 6: PORTAL E2E
// ════════════════════════════════════════════════════════════════════════════════

func TestE2E_Portal_StaticAssets(t *testing.T) {
	// Verify the portal HTML exists
	data, err := os.ReadFile("../../portal/web/index.html")
	if err != nil { t.Skipf("portal HTML not found (expected): %v", err) }
	if !strings.Contains(string(data), "AXELUS") { t.Error("portal HTML should contain AXELUS") }
	if !strings.Contains(string(data), "OPTIMIUM NEXUS LLC") { t.Error("portal HTML should contain publisher") }
}

// ════════════════════════════════════════════════════════════════════════════════
// SUITE 7: PERFORMANCE BENCHMARKS
// ════════════════════════════════════════════════════════════════════════════════

func BenchmarkLicenseValidation(b *testing.B) {
	kp, _ := keygen.GenerateKeyPair()
	v, _  := validator.NewValidator(map[string]string{kp.ID: kp.PublicKey}, false)
	l, _, _ := keygen.Issue(keygen.LicenseRequest{
		Tier: lic.TierEnterprise, Licensee: "Bench", Email: "bench@test.com", ValidForDays: 365,
	}, kp)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() { v.Validate(l) }
	})
}

func BenchmarkHasFeature(b *testing.B) {
	kp, _ := keygen.GenerateKeyPair()
	l, _, _ := keygen.Issue(keygen.LicenseRequest{
		Tier: lic.TierUltimate, Licensee: "Bench", Email: "bench@test.com", ValidForDays: 365,
	}, kp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.HasFeature(lic.FeatureAIThreatHunting)
	}
}

func BenchmarkZeroDayScoring(b *testing.B) {
	sc := zdscorer.NewScorer(zdscorer.ScorerConfig{MinTrainSamples: 5})
	// Warm up
	for i := 0; i < 10; i++ {
		sc.Score(zdscorer.RequestInput{
			IP: "1.2.3.4", Method: "GET", Path: "/api/test", Timestamp: time.Now(),
		})
	}
	req := zdscorer.RequestInput{
		IP: "5.6.7.8", Method: "POST", Path: "/api/data",
		Query: "id=123", Body: `{"key":"value"}`, Timestamp: time.Now(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ { sc.Score(req) }
}

func BenchmarkLicenseIssuance(b *testing.B) {
	kp, _ := keygen.GenerateKeyPair()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keygen.Issue(keygen.LicenseRequest{
			Tier:         lic.TierEnterprise,
			Licensee:     "Bench Corp",
			Email:        "bench@corp.test",
			ValidForDays: 365,
		}, kp)
	}
}

// TestMain — configure test environment
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

var _ = io.Discard // keep import
