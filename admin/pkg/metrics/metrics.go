// AXELUS-WAF — Tenant Metrics & Resource Quota Enforcement
// Real-time per-tenant metrics, quota checking, isolation enforcement.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// ── Quota ─────────────────────────────────────────────────────────────────────

type Quota struct {
	MaxRequestsPerSec  int64  // -1 = unlimited
	MaxBandwidthBPS    int64  // bytes/sec, -1 = unlimited
	MaxActiveSites     int    // number of protected sites
	MaxActiveUsers     int
	MaxStorageBytes    int64  // for PCAP/forensics storage
	MaxCustomRules     int
	MaxAPICallsPerDay  int64
}

var PlanQuotas = map[string]Quota{
	"trial": {
		MaxRequestsPerSec: 500, MaxBandwidthBPS: 50 * 1024 * 1024,
		MaxActiveSites: 1, MaxActiveUsers: 3,
		MaxStorageBytes: 1 * 1024 * 1024 * 1024, // 1 GB
		MaxCustomRules: 10, MaxAPICallsPerDay: 1000,
	},
	"pro": {
		MaxRequestsPerSec: 5000, MaxBandwidthBPS: 500 * 1024 * 1024,
		MaxActiveSites: 10, MaxActiveUsers: 10,
		MaxStorageBytes: 10 * 1024 * 1024 * 1024, // 10 GB
		MaxCustomRules: 100, MaxAPICallsPerDay: 10000,
	},
	"enterprise": {
		MaxRequestsPerSec: 50000, MaxBandwidthBPS: -1,
		MaxActiveSites: -1, MaxActiveUsers: 50,
		MaxStorageBytes: 100 * 1024 * 1024 * 1024, // 100 GB
		MaxCustomRules: 1000, MaxAPICallsPerDay: -1,
	},
	"ultimate": {
		MaxRequestsPerSec: -1, MaxBandwidthBPS: -1,
		MaxActiveSites: -1, MaxActiveUsers: -1,
		MaxStorageBytes: -1, MaxCustomRules: -1, MaxAPICallsPerDay: -1,
	},
}

// ── Tenant Metrics ────────────────────────────────────────────────────────────

type TenantMetrics struct {
	TenantID      string
	Plan          string
	Period        string    // "2006-01-02T15:04" (minute bucket)

	// Request metrics
	TotalRequests  int64
	BlockedReqs    int64
	PassedReqs     int64
	BlockRate      float64

	// Performance
	AvgLatencyMs   float64
	P95LatencyMs   float64
	P99LatencyMs   float64

	// Traffic
	IngressBytes   int64
	EgressBytes    int64
	ActiveConns    int64

	// Threat intel
	ThreatHits     int64
	GeoBlocks      int64
	RateLimitHits  int64
	HoneypotTriggers int64
	ZeroDayEvents  int64

	// Top attackers (updated async)
	TopAttackerIPs []AttackerEntry
	TopAttackTypes map[string]int64

	// Health
	WAFUptime      float64 // percentage
	ErrorRate      float64
	LastSeen       time.Time
}

type AttackerEntry struct {
	IP       string  `json:"ip"`
	Count    int64   `json:"count"`
	LastSeen string  `json:"last_seen"`
	Country  string  `json:"country,omitempty"`
	Blocked  bool    `json:"blocked"`
}

// ── Metrics Store ─────────────────────────────────────────────────────────────

type MetricsStore struct {
	mu      sync.RWMutex
	redis   *redis.Client
	ctx     context.Context
	// In-memory counters per tenant (minute-level, flushed to Redis)
	counters sync.Map // tenantID → *TenantCounters
}

type TenantCounters struct {
	requests  atomic.Int64
	blocked   atomic.Int64
	ingress   atomic.Int64
	egress    atomic.Int64
	threats   atomic.Int64
	latencies []int64
	mu        sync.Mutex
}

func NewMetricsStore(rdb *redis.Client) *MetricsStore {
	s := &MetricsStore{redis: rdb, ctx: context.Background()}
	go s.flushLoop()
	return s
}

// Record records a request event for a tenant
func (s *MetricsStore) Record(tenantID string, blocked bool, latencyMs int64, ingressBytes, egressBytes int64) {
	raw, _ := s.counters.LoadOrStore(tenantID, &TenantCounters{})
	c := raw.(*TenantCounters)
	c.requests.Add(1)
	if blocked { c.blocked.Add(1) }
	c.ingress.Add(ingressBytes)
	c.egress.Add(egressBytes)
	c.mu.Lock()
	c.latencies = append(c.latencies, latencyMs)
	if len(c.latencies) > 10000 { c.latencies = c.latencies[5000:] } // keep last 10k
	c.mu.Unlock()
}

// RecordThreat records a threat event
func (s *MetricsStore) RecordThreat(tenantID, threatType string) {
	raw, _ := s.counters.LoadOrStore(tenantID, &TenantCounters{})
	c := raw.(*TenantCounters)
	c.threats.Add(1)
	if s.redis != nil {
		s.redis.ZIncrBy(s.ctx, fmt.Sprintf("iw:threats:%s:types", tenantID), 1, threatType)
	}
}

// GetLive returns live metrics for a tenant (from in-memory counters)
func (s *MetricsStore) GetLive(tenantID string) map[string]interface{} {
	raw, ok := s.counters.Load(tenantID)
	if !ok {
		return map[string]interface{}{"tenant_id": tenantID, "live": true, "requests": 0}
	}
	c := raw.(*TenantCounters)
	reqs    := c.requests.Load()
	blocked := c.blocked.Load()
	blockRate := 0.0
	if reqs > 0 { blockRate = float64(blocked) / float64(reqs) * 100 }

	c.mu.Lock()
	p50, p95, p99 := percentiles(c.latencies)
	c.mu.Unlock()

	return map[string]interface{}{
		"tenant_id":     tenantID,
		"live":          true,
		"requests":      reqs,
		"blocked":       blocked,
		"block_rate_pct": blockRate,
		"ingress_bytes": c.ingress.Load(),
		"egress_bytes":  c.egress.Load(),
		"threats":       c.threats.Load(),
		"latency_p50_ms": p50,
		"latency_p95_ms": p95,
		"latency_p99_ms": p99,
		"snapshot_at":   time.Now().UTC().Format(time.RFC3339),
	}
}

// GetHistorical returns historical metrics from Redis (last N hours)
func (s *MetricsStore) GetHistorical(tenantID string, hours int) []map[string]interface{} {
	if s.redis == nil { return nil }
	var results []map[string]interface{}
	now := time.Now().UTC()
	for i := hours - 1; i >= 0; i-- {
		ts := now.Add(time.Duration(-i) * time.Hour).Format("2006-01-02T15")
		key := fmt.Sprintf("iw:metrics:%s:%s", tenantID, ts)
		data, err := s.redis.HGetAll(s.ctx, key).Result()
		if err != nil || len(data) == 0 { continue }
		point := map[string]interface{}{"period": ts}
		for k, v := range data { point[k] = v }
		results = append(results, point)
	}
	return results
}

// GetAllTenantSummary returns a summary of metrics for all tenants (admin view)
func (s *MetricsStore) GetAllTenantSummary() []map[string]interface{} {
	var summaries []map[string]interface{}
	s.counters.Range(func(k, v interface{}) bool {
		tenantID := k.(string)
		summaries = append(summaries, s.GetLive(tenantID))
		return true
	})
	return summaries
}

// flushLoop periodically flushes in-memory counters to Redis
func (s *MetricsStore) flushLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.flush()
	}
}

func (s *MetricsStore) flush() {
	if s.redis == nil { return }
	hour := time.Now().UTC().Format("2006-01-02T15")
	s.counters.Range(func(k, v interface{}) bool {
		tenantID := k.(string)
		c := v.(*TenantCounters)
		key := fmt.Sprintf("iw:metrics:%s:%s", tenantID, hour)
		pipe := s.redis.Pipeline()
		pipe.HIncrBy(s.ctx, key, "requests", c.requests.Swap(0))
		pipe.HIncrBy(s.ctx, key, "blocked",  c.blocked.Swap(0))
		pipe.HIncrBy(s.ctx, key, "ingress",  c.ingress.Swap(0))
		pipe.HIncrBy(s.ctx, key, "egress",   c.egress.Swap(0))
		pipe.HIncrBy(s.ctx, key, "threats",  c.threats.Swap(0))
		pipe.Expire(s.ctx, key, 30*24*time.Hour) // keep 30 days
		pipe.Exec(s.ctx)
		return true
	})
}

// ── Quota Enforcement ─────────────────────────────────────────────────────────

type QuotaEnforcer struct {
	store  *MetricsStore
	redis  *redis.Client
	ctx    context.Context
}

func NewQuotaEnforcer(store *MetricsStore, rdb *redis.Client) *QuotaEnforcer {
	return &QuotaEnforcer{store: store, redis: rdb, ctx: context.Background()}
}

type QuotaCheck struct {
	Allowed    bool
	Resource   string
	Current    int64
	Limit      int64
	UsagePct   float64
	Message    string
}

// CheckRPS checks if a tenant is within their requests/sec quota
func (qe *QuotaEnforcer) CheckRPS(tenantID, plan string) QuotaCheck {
	quota := PlanQuotas[plan]
	if quota.MaxRequestsPerSec == -1 {
		return QuotaCheck{Allowed: true, Resource: "rps", Limit: -1, UsagePct: 0}
	}
	metrics := qe.store.GetLive(tenantID)
	current := int64(0)
	if v, ok := metrics["requests"].(int64); ok { current = v }

	allowed := current < quota.MaxRequestsPerSec
	usagePct := float64(current) / float64(quota.MaxRequestsPerSec) * 100
	return QuotaCheck{
		Allowed:  allowed, Resource: "requests_per_sec",
		Current:  current, Limit: quota.MaxRequestsPerSec,
		UsagePct: usagePct,
		Message:  fmt.Sprintf("%.1f%% of %d req/s quota used", usagePct, quota.MaxRequestsPerSec),
	}
}

// CheckStorage checks storage quota for forensics/PCAP
func (qe *QuotaEnforcer) CheckStorage(tenantID, plan string, currentBytes int64) QuotaCheck {
	quota := PlanQuotas[plan]
	if quota.MaxStorageBytes == -1 {
		return QuotaCheck{Allowed: true, Resource: "storage", Limit: -1, UsagePct: 0}
	}
	usagePct := float64(currentBytes) / float64(quota.MaxStorageBytes) * 100
	return QuotaCheck{
		Allowed:  currentBytes < quota.MaxStorageBytes,
		Resource: "storage_bytes",
		Current:  currentBytes, Limit: quota.MaxStorageBytes,
		UsagePct: usagePct,
		Message:  fmt.Sprintf("%.1f%% of %s storage used", usagePct, humanBytes(quota.MaxStorageBytes)),
	}
}

// CheckAPIQuota checks the daily API call quota using Redis sliding window
func (qe *QuotaEnforcer) CheckAPIQuota(tenantID, plan string) QuotaCheck {
	quota := PlanQuotas[plan]
	if quota.MaxAPICallsPerDay == -1 {
		return QuotaCheck{Allowed: true, Resource: "api_calls_day", Limit: -1, UsagePct: 0}
	}
	if qe.redis == nil {
		return QuotaCheck{Allowed: true, Resource: "api_calls_day"}
	}

	key := fmt.Sprintf("iw:apiquota:%s:%s", tenantID, time.Now().UTC().Format("2006-01-02"))
	current, _ := qe.redis.Get(qe.ctx, key).Int64()
	usagePct := float64(current) / float64(quota.MaxAPICallsPerDay) * 100
	return QuotaCheck{
		Allowed:  current < quota.MaxAPICallsPerDay,
		Resource: "api_calls_per_day",
		Current:  current, Limit: quota.MaxAPICallsPerDay,
		UsagePct: usagePct,
		Message:  fmt.Sprintf("%.1f%% of %d daily API calls used", usagePct, quota.MaxAPICallsPerDay),
	}
}

// IncrementAPICall atomically increments the daily API call counter
func (qe *QuotaEnforcer) IncrementAPICall(tenantID string) {
	if qe.redis == nil { return }
	key := fmt.Sprintf("iw:apiquota:%s:%s", tenantID, time.Now().UTC().Format("2006-01-02"))
	pipe := qe.redis.Pipeline()
	pipe.Incr(qe.ctx, key)
	pipe.Expire(qe.ctx, key, 25*time.Hour)
	pipe.Exec(qe.ctx)
}

// GetAllQuotas returns quota status for all resources for a tenant
func (qe *QuotaEnforcer) GetAllQuotas(tenantID, plan string, storageBytes int64) map[string]QuotaCheck {
	return map[string]QuotaCheck{
		"requests_per_sec": qe.CheckRPS(tenantID, plan),
		"storage":          qe.CheckStorage(tenantID, plan, storageBytes),
		"api_calls_day":    qe.CheckAPIQuota(tenantID, plan),
	}
}

// ── Tenant Isolation ──────────────────────────────────────────────────────────

// IsolationPolicy enforces network + data isolation between tenants
type IsolationPolicy struct {
	TenantID      string
	Namespace     string // Kubernetes namespace
	NetworkPolicy string // k8s network policy name
	DataPrefix    string // Redis key prefix
	DBSchema      string // PostgreSQL schema name
	Isolated      bool   // full isolation (Ultimate/Enterprise) vs shared (Community/Pro)
}

func NewIsolationPolicy(tenantID, plan string) IsolationPolicy {
	slug := tenantID[:8]
	isolated := plan == "enterprise" || plan == "ultimate"
	return IsolationPolicy{
		TenantID:      tenantID,
		Namespace:     fmt.Sprintf("axelus-tenant-%s", slug),
		NetworkPolicy: fmt.Sprintf("np-tenant-%s", slug),
		DataPrefix:    fmt.Sprintf("iw:t:%s:", tenantID),
		DBSchema:      fmt.Sprintf("tenant_%s", slug),
		Isolated:      isolated,
	}
}

// RedisKey returns an isolated Redis key for a tenant
func (p IsolationPolicy) RedisKey(key string) string {
	return p.DataPrefix + key
}

// EnforceMiddlewareKey returns the data isolation middleware config
func (p IsolationPolicy) MiddlewareConfig() map[string]interface{} {
	return map[string]interface{}{
		"tenant_id":      p.TenantID,
		"data_prefix":    p.DataPrefix,
		"db_schema":      p.DBSchema,
		"full_isolation": p.Isolated,
		"namespace":      p.Namespace,
	}
}

// ── Platform Health Aggregator ────────────────────────────────────────────────

type PlatformHealth struct {
	TotalTenantsActive int
	TotalRPS           int64
	TotalBlockedLast1h int64
	P99LatencyMs       float64
	TopThreats         []ThreatSummary
	WorstTenants       []TenantAlert  // tenants exceeding quota thresholds
	ComputedAt         time.Time
}

type ThreatSummary struct {
	Type   string `json:"type"`
	Count  int64  `json:"count"`
	Trend  string `json:"trend"` // "rising"|"falling"|"stable"
}

type TenantAlert struct {
	TenantID    string  `json:"tenant_id"`
	TenantName  string  `json:"tenant_name"`
	AlertType   string  `json:"alert_type"` // "quota_exceeded"|"high_error_rate"|"attack_surge"
	Details     string  `json:"details"`
	Severity    string  `json:"severity"` // "warning"|"critical"
}

func (s *MetricsStore) GetPlatformHealth() PlatformHealth {
	var totalRPS, totalBlocked int64
	var latencies []int64

	s.counters.Range(func(_, v interface{}) bool {
		c := v.(*TenantCounters)
		totalRPS     += c.requests.Load()
		totalBlocked += c.blocked.Load()
		c.mu.Lock()
		latencies = append(latencies, c.latencies...)
		c.mu.Unlock()
		return true
	})

	_, _, p99 := percentiles(latencies)

	return PlatformHealth{
		TotalRPS:         totalRPS,
		TotalBlockedLast1h: totalBlocked,
		P99LatencyMs:     p99,
		ComputedAt:       time.Now().UTC(),
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func percentiles(latencies []int64) (p50, p95, p99 float64) {
	if len(latencies) == 0 { return 0, 0, 0 }
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)
	// Simple insertion sort for small slices
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	n := len(sorted)
	p50 = float64(sorted[n*50/100])
	p95 = float64(sorted[n*95/100])
	p99 = float64(sorted[n*99/100])
	return
}

func humanBytes(b int64) string {
	if b < 0 { return "∞" }
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// MarshalMetrics serializes tenant metrics to JSON for API responses
func MarshalMetrics(m *TenantMetrics) ([]byte, error) {
	return json.Marshal(m)
}
