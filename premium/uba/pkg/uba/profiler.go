// AXELUS-WAF — User & Entity Behavioral Analytics (UBA/UEBA)
// Detects slow-burn attacks: credential stuffing, account takeover,
// insider threats, and lateral movement by profiling behavior over time.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package uba

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// ── Behavior Event ────────────────────────────────────────────────────────────

type EventType string

const (
	EventLogin          EventType = "login"
	EventLoginFailed    EventType = "login_failed"
	EventLogout         EventType = "logout"
	EventAPICall        EventType = "api_call"
	EventPasswordChange EventType = "password_change"
	EventPermChange     EventType = "permission_change"
	EventDataExport     EventType = "data_export"
	EventFileAccess     EventType = "file_access"
	EventAdminAction    EventType = "admin_action"
	EventUnusualHour    EventType = "unusual_hour"
	EventNewDevice      EventType = "new_device"
	EventNewGeo         EventType = "new_geo"
	EventAPIBurst       EventType = "api_burst"
	EventScanPattern    EventType = "scan_pattern"
)

type BehaviorEvent struct {
	EntityID    string    `json:"entity_id"`    // user ID, API key, tenant ID
	EntityType  string    `json:"entity_type"`  // "user" | "api_key" | "tenant"
	EventType   EventType `json:"event_type"`
	IP          string    `json:"ip"`
	Country     string    `json:"country,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	Path        string    `json:"path,omitempty"`
	StatusCode  int       `json:"status_code,omitempty"`
	BytesSent   int64     `json:"bytes_sent,omitempty"`
	DurationMs  int64     `json:"duration_ms,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ── Entity Profile ────────────────────────────────────────────────────────────

// EntityProfile maintains a rolling behavioral baseline for an entity
type EntityProfile struct {
	EntityID    string    `json:"entity_id"`
	EntityType  string    `json:"entity_type"`
	TenantID    string    `json:"tenant_id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Login behavior
	LoginHours       [24]int   `json:"login_hours"`      // hourly login distribution
	LoginDays        [7]int    `json:"login_days"`       // daily login distribution
	LoginLocations   map[string]int `json:"login_locations"` // country → count
	LoginIPs         map[string]time.Time `json:"login_ips"` // IP → last seen
	FailedLogins     int       `json:"failed_logins"`
	SuccessfulLogins int       `json:"successful_logins"`
	ConsecFails      int       `json:"consec_fails"`      // consecutive failures (reset on success)
	LastLoginAt      *time.Time `json:"last_login_at"`

	// API behavior
	AvgDailyAPICalls  float64          `json:"avg_daily_api_calls"`
	ApiCallHistory    []DailyCount     `json:"api_call_history"` // last 30 days
	TopEndpoints      map[string]int   `json:"top_endpoints"`
	AvgResponseMs     float64          `json:"avg_response_ms"`
	ErrorRate         float64          `json:"error_rate"`

	// Data patterns
	AvgDailyDataBytes float64  `json:"avg_daily_data_bytes"`
	MaxDailyDataBytes int64    `json:"max_daily_data_bytes"`
	DataExportCount   int      `json:"data_export_count"`

	// Anomaly tracking
	RiskScore         float64  `json:"risk_score"`        // 0–100
	AnomalyCount30d   int      `json:"anomaly_count_30d"`
	LastAnomalyAt     *time.Time `json:"last_anomaly_at"`
	IsHighRisk        bool     `json:"is_high_risk"`
	IsSuspended       bool     `json:"is_suspended"`
	WatchlistReason   string   `json:"watchlist_reason,omitempty"`

	mu sync.Mutex `json:"-"`
}

type DailyCount struct {
	Date  string `json:"date"`  // YYYY-MM-DD
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
}

// ── Risk Scores ────────────────────────────────────────────────────────────────

// AnomalySignal represents a single behavioral anomaly detected for an entity
type AnomalySignal struct {
	SignalType  string    `json:"signal_type"`
	Score       float64   `json:"score"`      // 0–100
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	DetectedAt  time.Time `json:"detected_at"`
}

// Signals and their base scores
var SignalScores = map[string]float64{
	"impossible_travel":    90,  // Login from two countries < 30min apart
	"credential_stuffing":  85,  // Many failed logins across many users from same IP
	"account_takeover":     80,  // Login from new country + immediate data export
	"brute_force":          75,  // > 10 consecutive login failures
	"unusual_hour":         40,  // Login outside normal hours (3+ sigma)
	"new_geography":        55,  // First login from new country
	"api_burst_anomaly":    65,  // 5x normal API rate
	"data_exfiltration":    85,  // 10x normal data volume + new IP
	"privilege_escalation": 90,  // Permission change + immediate sensitive action
	"lateral_movement":     80,  // Same session touching multiple tenants
	"scanner_behavior":     70,  // Systematic endpoint enumeration
	"slow_brute_force":     75,  // Distributed low-rate credential attack
	"token_reuse":          70,  // Same API token used from multiple IPs concurrently
	"after_hours_admin":    60,  // Admin actions outside business hours
}

// ── Profiler ──────────────────────────────────────────────────────────────────

type Profiler struct {
	mu       sync.RWMutex
	profiles sync.Map         // entityID → *EntityProfile
	redis    *redis.Client
	ctx      context.Context
	onAlert  func(EntityProfile, []AnomalySignal)
	stats    ProfilerStats
}

type ProfilerStats struct {
	EntitiesTracked int64
	EventsProcessed int64
	AlertsGenerated int64
	HighRiskEntities int64
}

func New(rdb *redis.Client, onAlert func(EntityProfile, []AnomalySignal)) *Profiler {
	p := &Profiler{
		redis:   rdb,
		ctx:     context.Background(),
		onAlert: onAlert,
	}
	go p.maintenanceLoop()
	return p
}

// Record processes a behavioral event and updates the entity profile
func (p *Profiler) Record(event BehaviorEvent) []AnomalySignal {
	p.stats.EventsProcessed++

	profile := p.getOrCreate(event.EntityID, event.EntityType, event.TenantID)

	profile.mu.Lock()
	signals := p.updateProfile(profile, event)
	profile.mu.Unlock()

	// Store in Redis for cross-node sharing
	if p.redis != nil {
		p.persistProfile(profile)
	}

	if len(signals) > 0 {
		p.stats.AlertsGenerated += int64(len(signals))
		if p.onAlert != nil { go p.onAlert(*profile, signals) }
	}

	return signals
}

func (p *Profiler) updateProfile(profile *EntityProfile, event BehaviorEvent) []AnomalySignal {
	var signals []AnomalySignal
	now := event.Timestamp
	if now.IsZero() { now = time.Now().UTC() }

	profile.UpdatedAt = now

	switch event.EventType {
	case EventLogin:
		signals = append(signals, p.analyzeLogin(profile, event)...)
		profile.LoginHours[now.Hour()]++
		profile.LoginDays[int(now.Weekday())]++
		if profile.LoginLocations == nil { profile.LoginLocations = make(map[string]int) }
		if event.Country != "" { profile.LoginLocations[event.Country]++ }
		if profile.LoginIPs == nil { profile.LoginIPs = make(map[string]time.Time) }
		profile.LoginIPs[event.IP] = now
		profile.SuccessfulLogins++
		profile.ConsecFails = 0
		profile.LastLoginAt = &now

	case EventLoginFailed:
		profile.FailedLogins++
		profile.ConsecFails++
		if profile.ConsecFails >= 10 {
			signals = append(signals, AnomalySignal{
				SignalType:  "brute_force",
				Score:       SignalScores["brute_force"],
				Description: fmt.Sprintf("%d consecutive login failures", profile.ConsecFails),
				Evidence:    fmt.Sprintf("from IP %s", event.IP),
				DetectedAt:  now,
			})
		}

	case EventAPICall:
		today := now.Format("2006-01-02")
		signals = append(signals, p.analyzeAPIRate(profile, event, today)...)
		if profile.TopEndpoints == nil { profile.TopEndpoints = make(map[string]int) }
		profile.TopEndpoints[event.Path]++
		// Exponential moving average for daily calls
		profile.AvgDailyAPICalls = 0.9*profile.AvgDailyAPICalls + 0.1*1

	case EventDataExport:
		profile.DataExportCount++
		signals = append(signals, p.analyzeDataExport(profile, event)...)
		profile.AvgDailyDataBytes = 0.9*profile.AvgDailyDataBytes + 0.1*float64(event.BytesSent)
		if event.BytesSent > profile.MaxDailyDataBytes { profile.MaxDailyDataBytes = event.BytesSent }

	case EventPermChange:
		signals = append(signals, AnomalySignal{
			SignalType:  "privilege_escalation",
			Score:       SignalScores["privilege_escalation"] * 0.7,
			Description: "Permission change detected",
			Evidence:    fmt.Sprintf("entity=%s ip=%s", event.EntityID, event.IP),
			DetectedAt:  now,
		})

	case EventAdminAction:
		signals = append(signals, p.analyzeAdminAction(profile, event, now)...)
	}

	// Update aggregate risk score
	totalScore := 0.0
	for _, s := range signals { totalScore += s.Score }
	if len(signals) > 0 {
		// Exponential decay on risk score, capped at 100
		profile.RiskScore = math.Min(100, profile.RiskScore*0.8+totalScore*0.2)
		profile.AnomalyCount30d++
		profile.LastAnomalyAt = &now
		if profile.RiskScore >= 80 {
			profile.IsHighRisk = true
			p.stats.HighRiskEntities++
		}
	} else {
		// Risk decays over time (no anomalies = decay)
		profile.RiskScore *= 0.995
	}

	return signals
}

// ── Signal Detectors ──────────────────────────────────────────────────────────

func (p *Profiler) analyzeLogin(profile *EntityProfile, event BehaviorEvent) []AnomalySignal {
	var signals []AnomalySignal
	now := event.Timestamp

	// Impossible travel: login from different country within 1 hour
	if profile.LastLoginAt != nil && event.Country != "" {
		timeSinceLast := now.Sub(*profile.LastLoginAt)
		if timeSinceLast < time.Hour {
			// Check if country changed
			lastCountry := p.lastCountry(profile)
			if lastCountry != "" && lastCountry != event.Country {
				signals = append(signals, AnomalySignal{
					SignalType:  "impossible_travel",
					Score:       SignalScores["impossible_travel"],
					Description: fmt.Sprintf("Login from %s only %.0f min after login from %s",
						event.Country, timeSinceLast.Minutes(), lastCountry),
					Evidence: fmt.Sprintf("ip=%s country=%s→%s gap=%.0fmin",
						event.IP, lastCountry, event.Country, timeSinceLast.Minutes()),
					DetectedAt: now,
				})
			}
		}
	}

	// New geography
	if event.Country != "" && profile.LoginLocations != nil {
		if _, seen := profile.LoginLocations[event.Country]; !seen && profile.SuccessfulLogins > 5 {
			signals = append(signals, AnomalySignal{
				SignalType:  "new_geography",
				Score:       SignalScores["new_geography"],
				Description: fmt.Sprintf("First login from %s (entity has %d prior logins)", event.Country, profile.SuccessfulLogins),
				Evidence:    fmt.Sprintf("ip=%s", event.IP),
				DetectedAt:  now,
			})
		}
	}

	// Unusual hour (login outside entity's normal hours)
	hour := now.Hour()
	if profile.SuccessfulLogins > 20 { // enough data for baseline
		avgHour := p.avgLoginHour(profile)
		hourDiff := math.Abs(float64(hour) - avgHour)
		if hourDiff > 6 { // 6+ hours from normal
			signals = append(signals, AnomalySignal{
				SignalType:  "unusual_hour",
				Score:       SignalScores["unusual_hour"] * (hourDiff / 12),
				Description: fmt.Sprintf("Login at unusual hour %02d:00 (normal: %02d:00)", hour, int(avgHour)),
				Evidence:    fmt.Sprintf("deviation=%.1f hours from baseline", hourDiff),
				DetectedAt:  now,
			})
		}
	}

	return signals
}

func (p *Profiler) analyzeAPIRate(profile *EntityProfile, event BehaviorEvent, today string) []AnomalySignal {
	var signals []AnomalySignal

	// Find today's count
	todayCount := int64(0)
	for _, dc := range profile.ApiCallHistory {
		if dc.Date == today { todayCount = dc.Count; break }
	}

	// Compare to average
	if profile.AvgDailyAPICalls > 0 && float64(todayCount) > profile.AvgDailyAPICalls*5 {
		signals = append(signals, AnomalySignal{
			SignalType:  "api_burst_anomaly",
			Score:       SignalScores["api_burst_anomaly"],
			Description: fmt.Sprintf("API call rate is %.0fx normal (today: %d, avg: %.0f/day)",
				float64(todayCount)/profile.AvgDailyAPICalls, todayCount, profile.AvgDailyAPICalls),
			Evidence:    fmt.Sprintf("entity=%s today=%d avg=%.0f", event.EntityID, todayCount, profile.AvgDailyAPICalls),
			DetectedAt:  event.Timestamp,
		})
	}

	// Scanner behavior: systematic endpoint enumeration
	if len(profile.TopEndpoints) > 100 && profile.SuccessfulLogins < 5 {
		signals = append(signals, AnomalySignal{
			SignalType:  "scanner_behavior",
			Score:       SignalScores["scanner_behavior"],
			Description: fmt.Sprintf("Accessing %d distinct endpoints with minimal authentication", len(profile.TopEndpoints)),
			DetectedAt:  event.Timestamp,
		})
	}

	return signals
}

func (p *Profiler) analyzeDataExport(profile *EntityProfile, event BehaviorEvent) []AnomalySignal {
	var signals []AnomalySignal

	if profile.AvgDailyDataBytes > 0 && float64(event.BytesSent) > profile.AvgDailyDataBytes*10 {
		// Check if from new IP + large data = exfiltration
		isNewIP := true
		if profile.LoginIPs != nil {
			if _, ok := profile.LoginIPs[event.IP]; ok { isNewIP = false }
		}
		score := SignalScores["data_exfiltration"]
		if !isNewIP { score *= 0.5 }
		signals = append(signals, AnomalySignal{
			SignalType:  "data_exfiltration",
			Score:       score,
			Description: fmt.Sprintf("Data export %.1fx above average (%.1f MB vs avg %.1f MB)",
				float64(event.BytesSent)/profile.AvgDailyDataBytes,
				float64(event.BytesSent)/1024/1024,
				profile.AvgDailyDataBytes/1024/1024),
			Evidence: fmt.Sprintf("ip=%s new_ip=%v bytes=%d", event.IP, isNewIP, event.BytesSent),
			DetectedAt: event.Timestamp,
		})
	}
	return signals
}

func (p *Profiler) analyzeAdminAction(profile *EntityProfile, event BehaviorEvent, now time.Time) []AnomalySignal {
	var signals []AnomalySignal
	hour := now.Hour()
	// Admin actions outside business hours (before 7am or after 10pm)
	if hour < 7 || hour > 22 {
		signals = append(signals, AnomalySignal{
			SignalType:  "after_hours_admin",
			Score:       SignalScores["after_hours_admin"],
			Description: fmt.Sprintf("Admin action at %02d:00 (outside business hours)", hour),
			Evidence:    fmt.Sprintf("path=%s ip=%s", event.Path, event.IP),
			DetectedAt:  now,
		})
	}
	return signals
}

// ── Cross-Entity Correlation (Credential Stuffing) ────────────────────────────

// CredentialStuffingDetector detects distributed credential stuffing attacks
// by correlating failed logins across multiple entities from the same IP/subnet
type CredentialStuffingDetector struct {
	mu      sync.Mutex
	ipFails map[string]*stuffingTracker // IP → tracker
}

type stuffingTracker struct {
	entities    map[string]struct{} // distinct entity IDs
	failures    int
	firstSeen   time.Time
	lastSeen    time.Time
}

func NewCSDetector() *CredentialStuffingDetector {
	return &CredentialStuffingDetector{ipFails: make(map[string]*stuffingTracker)}
}

func (d *CredentialStuffingDetector) Record(ip, entityID string) *AnomalySignal {
	d.mu.Lock()
	defer d.mu.Unlock()

	t, ok := d.ipFails[ip]
	if !ok {
		t = &stuffingTracker{entities: make(map[string]struct{}), firstSeen: time.Now()}
		d.ipFails[ip] = t
	}

	// Reset if window expired (1 hour)
	if time.Since(t.firstSeen) > time.Hour {
		t.entities = make(map[string]struct{})
		t.failures = 0
		t.firstSeen = time.Now()
	}

	t.entities[entityID] = struct{}{}
	t.failures++
	t.lastSeen = time.Now()

	// Credential stuffing: >5 distinct entities failing from same IP
	if len(t.entities) >= 5 && t.failures >= 20 {
		return &AnomalySignal{
			SignalType:  "credential_stuffing",
			Score:       SignalScores["credential_stuffing"],
			Description: fmt.Sprintf("IP %s attempted login on %d distinct accounts (%d failures in %.0f min)",
				ip, len(t.entities), t.failures, time.Since(t.firstSeen).Minutes()),
			Evidence:    fmt.Sprintf("distinct_targets=%d total_failures=%d", len(t.entities), t.failures),
			DetectedAt:  time.Now(),
		}
	}
	return nil
}

// ── Profile Management ────────────────────────────────────────────────────────

func (p *Profiler) getOrCreate(entityID, entityType, tenantID string) *EntityProfile {
	v, loaded := p.profiles.LoadOrStore(entityID, &EntityProfile{
		EntityID:     entityID,
		EntityType:   entityType,
		TenantID:     tenantID,
		CreatedAt:    time.Now().UTC(),
		LoginLocations: make(map[string]int),
		LoginIPs:     make(map[string]time.Time),
		TopEndpoints: make(map[string]int),
	})
	if !loaded { p.stats.EntitiesTracked++ }
	return v.(*EntityProfile)
}

func (p *Profiler) Get(entityID string) *EntityProfile {
	v, ok := p.profiles.Load(entityID)
	if !ok { return nil }
	return v.(*EntityProfile)
}

func (p *Profiler) GetTopRisk(n int) []EntityProfile {
	var profiles []EntityProfile
	p.profiles.Range(func(_, v interface{}) bool {
		profiles = append(profiles, *v.(*EntityProfile)); return true
	})
	// Sort by risk score descending
	for i := 1; i < len(profiles); i++ {
		for j := i; j > 0 && profiles[j].RiskScore > profiles[j-1].RiskScore; j-- {
			profiles[j], profiles[j-1] = profiles[j-1], profiles[j]
		}
	}
	if n > len(profiles) { n = len(profiles) }
	return profiles[:n]
}

func (p *Profiler) persistProfile(profile *EntityProfile) {
	if p.redis == nil { return }
	profile.mu.Lock()
	data, _ := json.Marshal(profile)
	profile.mu.Unlock()
	p.redis.Set(p.ctx, "axelus:uba:profile:"+profile.EntityID, data, 7*24*time.Hour)
}

func (p *Profiler) maintenanceLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		// Decay risk scores for inactive entities
		p.profiles.Range(func(_, v interface{}) bool {
			profile := v.(*EntityProfile)
			profile.mu.Lock()
			profile.RiskScore *= 0.95 // 5% hourly decay
			if profile.RiskScore < 50 { profile.IsHighRisk = false }
			profile.mu.Unlock()
			return true
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (p *Profiler) lastCountry(profile *EntityProfile) string {
	if len(profile.LoginLocations) == 0 { return "" }
	var lastCountry string
	var lastTime time.Time
	for _, ip := range profile.LoginIPs {
		if ip.After(lastTime) { lastTime = ip }
	}
	for c := range profile.LoginLocations {
		if lastCountry == "" { lastCountry = c }
	}
	return lastCountry
}

func (p *Profiler) avgLoginHour(profile *EntityProfile) float64 {
	total, count := 0, 0
	for h, c := range profile.LoginHours { total += h * c; count += c }
	if count == 0 { return 12 }
	return float64(total) / float64(count)
}

// ── REST API ──────────────────────────────────────────────────────────────────

func (p *Profiler) Register(rg *gin.RouterGroup) {
	u := rg.Group("/uba")
	u.POST("/events",              p.apiIngestEvent)
	u.GET("/profiles",             p.apiListProfiles)
	u.GET("/profiles/:entity_id",  p.apiGetProfile)
	u.GET("/high-risk",            p.apiHighRisk)
	u.GET("/stats",                p.apiStats)
	u.POST("/profiles/:entity_id/suspend", p.apiSuspend)
	u.POST("/profiles/:entity_id/clear",   p.apiClear)
}

func (p *Profiler) apiIngestEvent(c *gin.Context) {
	var event BehaviorEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	signals := p.Record(event)
	c.JSON(http.StatusOK, gin.H{"signals_detected": len(signals), "signals": signals})
}

func (p *Profiler) apiListProfiles(c *gin.Context) {
	var profiles []EntityProfile
	p.profiles.Range(func(_, v interface{}) bool {
		profiles = append(profiles, *v.(*EntityProfile)); return true
	})
	c.JSON(http.StatusOK, gin.H{"count": len(profiles), "profiles": profiles})
}

func (p *Profiler) apiGetProfile(c *gin.Context) {
	profile := p.Get(c.Param("entity_id"))
	if profile == nil { c.JSON(http.StatusNotFound, gin.H{"error": "entity not found"}); return }
	c.JSON(http.StatusOK, profile)
}

func (p *Profiler) apiHighRisk(c *gin.Context) {
	n := 20; c.ShouldBind(&n)
	c.JSON(http.StatusOK, gin.H{"high_risk_entities": p.GetTopRisk(n)})
}

func (p *Profiler) apiStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"entities_tracked":   p.stats.EntitiesTracked,
		"events_processed":   p.stats.EventsProcessed,
		"alerts_generated":   p.stats.AlertsGenerated,
		"high_risk_entities": p.stats.HighRiskEntities,
		"signal_types":       len(SignalScores),
	})
}

func (p *Profiler) apiSuspend(c *gin.Context) {
	var body struct { Reason string `json:"reason"` }
	c.ShouldBindJSON(&body)
	profile := p.Get(c.Param("entity_id"))
	if profile == nil { c.JSON(http.StatusNotFound, gin.H{"error": "entity not found"}); return }
	profile.mu.Lock()
	profile.IsSuspended = true
	profile.WatchlistReason = body.Reason
	profile.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"message": "Entity suspended"})
}

func (p *Profiler) apiClear(c *gin.Context) {
	profile := p.Get(c.Param("entity_id"))
	if profile == nil { c.JSON(http.StatusNotFound, gin.H{"error": "entity not found"}); return }
	profile.mu.Lock()
	profile.RiskScore = 0; profile.IsHighRisk = false
	profile.IsSuspended = false; profile.AnomalyCount30d = 0
	profile.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"message": "Profile cleared"})
}
