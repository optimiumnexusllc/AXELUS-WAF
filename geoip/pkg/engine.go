// AXELUS GeoIP Module — Country/Region/ASN-based access control
// Uses MaxMind GeoIP2 databases for offline lookup + Redis-backed rule cache.
package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type Action string

const (
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge" // CAPTCHA
	ActionLog       Action = "log"       // Allow but log
	ActionAllow     Action = "allow"     // Explicit allowlist
)

type RuleTarget string

const (
	TargetCountry RuleTarget = "country"
	TargetASN     RuleTarget = "asn"
	TargetContinent RuleTarget = "continent"
	TargetCIDR    RuleTarget = "cidr"
)

type GeoRule struct {
	ID        string     `json:"id"`
	Target    RuleTarget `json:"target"`
	Value     string     `json:"value"`      // ISO country code, ASN number, CIDR
	Action    Action     `json:"action"`
	Priority  int        `json:"priority"`   // Lower = higher priority
	Enabled   bool       `json:"enabled"`
	Note      string     `json:"note"`
	CreatedAt time.Time  `json:"created_at"`
	HitCount  int64      `json:"hit_count"`
}

type GeoLookup struct {
	IP          string  `json:"ip"`
	CountryCode string  `json:"country_code"` // ISO 3166-1 alpha-2
	CountryName string  `json:"country_name"`
	Continent   string  `json:"continent"`
	City        string  `json:"city,omitempty"`
	ASN         uint    `json:"asn,omitempty"`
	ASNOrg      string  `json:"asn_org,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	IsVPN       bool    `json:"is_vpn"`
	IsTor       bool    `json:"is_tor"`
	IsProxy     bool    `json:"is_proxy"`
	IsHosting   bool    `json:"is_hosting"`
	RiskScore   int     `json:"risk_score"` // 0-100
}

type Decision struct {
	Action      Action    `json:"action"`
	Reason      string    `json:"reason"`
	MatchedRule *GeoRule  `json:"matched_rule,omitempty"`
	Lookup      *GeoLookup `json:"lookup"`
	Latency     time.Duration `json:"latency_us"`
}

// ── Engine ────────────────────────────────────────────────────────────────────

type Engine struct {
	mu          sync.RWMutex
	rules       []GeoRule
	dbPath      string
	rdb         *redis.Client
	ctx         context.Context
	defaultAction Action
	stats       Stats
}

type Stats struct {
	mu          sync.Mutex
	Blocked     int64
	Challenged  int64
	Allowed     int64
	Logged      int64
	CacheHits   int64
	CacheMisses int64
	ByCountry   map[string]int64
}

type Config struct {
	DBPath        string // Path to MaxMind GeoIP2-City.mmdb
	RedisAddr     string
	RedisPassword string
	DefaultAction Action // Action when no rule matches (default: allow)
	Rules         []GeoRule
	MaxMindKey    string // For auto-download
	MaxMindAccID  string
}

// New creates a new GeoIP engine
func New(cfg Config) (*Engine, error) {
	e := &Engine{
		dbPath:        cfg.DBPath,
		defaultAction: cfg.DefaultAction,
		ctx:           context.Background(),
	}
	if e.defaultAction == "" {
		e.defaultAction = ActionAllow
	}
	e.rules = cfg.Rules
	e.stats.ByCountry = make(map[string]int64)

	// Redis (optional — used for caching and rule sync)
	if cfg.RedisAddr != "" {
		e.rdb = redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
		})
		if err := e.rdb.Ping(e.ctx).Err(); err != nil {
			fmt.Printf("[geoip] Redis unavailable (%v) — cache disabled\n", err)
			e.rdb = nil
		}
	}

	return e, nil
}

// ── Lookup ────────────────────────────────────────────────────────────────────

// Lookup returns geo information for an IP address.
// Uses a tiered approach: Redis cache → MaxMind DB → fallback.
func (e *Engine) Lookup(ipStr string) (*GeoLookup, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", ipStr)
	}

	// Strip IPv4-mapped IPv6
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Cache check
	if e.rdb != nil {
		key := "axelus:geoip:" + ipStr
		cached, err := e.rdb.Get(e.ctx, key).Result()
		if err == nil {
			var lookup GeoLookup
			if json.Unmarshal([]byte(cached), &lookup) == nil {
				e.stats.mu.Lock(); e.stats.CacheHits++; e.stats.mu.Unlock()
				return &lookup, nil
			}
		}
	}
	e.stats.mu.Lock(); e.stats.CacheMisses++; e.stats.mu.Unlock()

	// MaxMind DB lookup (using pure-go implementation without CGO)
	lookup := e.lookupFromDB(ip)

	// Enrich with risk signals
	lookup.RiskScore = e.calculateRiskScore(lookup)

	// Cache result
	if e.rdb != nil {
		if data, err := json.Marshal(lookup); err == nil {
			e.rdb.Set(e.ctx, "axelus:geoip:"+ipStr, data, 6*time.Hour)
		}
	}

	return lookup, nil
}

// lookupFromDB performs a MaxMind binary database lookup.
// In production, integrate oschwald/geoip2-golang for full MMDB support.
func (e *Engine) lookupFromDB(ip net.IP) *GeoLookup {
	lookup := &GeoLookup{IP: ip.String()}

	// Read MMDB if available
	if e.dbPath != "" {
		if result := readMMDB(e.dbPath, ip); result != nil {
			return result
		}
	}

	// Fallback: IANA special ranges
	switch {
	case ip.IsLoopback() || ip.IsPrivate():
		lookup.CountryCode = "ZZ"
		lookup.CountryName = "Private/Internal"
		lookup.Continent = "XX"
	case isRFC6598(ip):
		lookup.CountryCode = "ZZ"
		lookup.CountryName = "Carrier-Grade NAT"
	default:
		lookup.CountryCode = "XX"
		lookup.CountryName = "Unknown"
	}
	return lookup
}

// readMMDB reads from a MaxMind binary database file.
// This is a stub — integrate github.com/oschwald/geoip2-golang for production.
func readMMDB(path string, ip net.IP) *GeoLookup {
	// Production implementation:
	// db, err := geoip2.Open(path)
	// if err != nil { return nil }
	// defer db.Close()
	// record, err := db.City(ip)
	// if err != nil { return nil }
	// return &GeoLookup{
	//   IP: ip.String(),
	//   CountryCode: record.Country.IsoCode,
	//   CountryName: record.Country.Names["en"],
	//   Continent: record.Continent.Code,
	//   City: record.City.Names["en"],
	//   ASN: uint(record.Traits.AutonomousSystemNumber),
	//   ASNOrg: record.Traits.AutonomousSystemOrganization,
	//   Latitude: record.Location.Latitude,
	//   Longitude: record.Location.Longitude,
	// }
	_ = path; _ = ip
	return nil
}

func isRFC6598(ip net.IP) bool {
	_, block, _ := net.ParseCIDR("100.64.0.0/10")
	return block.Contains(ip)
}

// calculateRiskScore assigns a risk score 0-100 based on geo signals
func (e *Engine) calculateRiskScore(l *GeoLookup) int {
	score := 0
	highRiskCountries := map[string]int{
		"KP": 95, "IR": 85, "SY": 80, "BY": 75,
		"RU": 60, "CN": 40, "VN": 30,
	}
	if s, ok := highRiskCountries[l.CountryCode]; ok {
		score += s
	}
	if l.IsVPN     { score += 20 }
	if l.IsTor     { score += 40 }
	if l.IsProxy   { score += 15 }
	if l.IsHosting { score += 10 }
	if score > 100 { score = 100 }
	return score
}

// ── Enforcement ───────────────────────────────────────────────────────────────

// Evaluate returns the action to take for a given IP
func (e *Engine) Evaluate(ipStr string) (*Decision, error) {
	start := time.Now()
	lookup, err := e.Lookup(ipStr)
	if err != nil {
		return &Decision{Action: ActionAllow, Reason: "lookup failed — fail open", Latency: time.Since(start)}, nil
	}

	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	// Sort rules by priority (already sorted on insert)
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		if e.ruleMatches(r, lookup, ipStr) {
			// Track stats
			e.stats.mu.Lock()
			switch r.Action {
			case ActionBlock:     e.stats.Blocked++
			case ActionChallenge: e.stats.Challenged++
			case ActionLog:       e.stats.Logged++
			case ActionAllow:     e.stats.Allowed++
			}
			e.stats.ByCountry[lookup.CountryCode]++
			e.stats.mu.Unlock()

			// Increment rule hit counter in Redis
			if e.rdb != nil {
				e.rdb.Incr(e.ctx, fmt.Sprintf("axelus:geoip:hits:%s", r.ID))
			}

			return &Decision{
				Action:      r.Action,
				Reason:      fmt.Sprintf("matched rule %s: %s %s %s", r.ID, r.Target, r.Value, r.Action),
				MatchedRule: r,
				Lookup:      lookup,
				Latency:     time.Since(start),
			}, nil
		}
	}

	// High risk score → auto-challenge even without explicit rule
	if lookup.RiskScore >= 90 {
		return &Decision{
			Action:  ActionBlock,
			Reason:  fmt.Sprintf("risk score %d/100 exceeds threshold", lookup.RiskScore),
			Lookup:  lookup,
			Latency: time.Since(start),
		}, nil
	}
	if lookup.RiskScore >= 70 {
		return &Decision{
			Action:  ActionChallenge,
			Reason:  fmt.Sprintf("risk score %d/100 — CAPTCHA challenge", lookup.RiskScore),
			Lookup:  lookup,
			Latency: time.Since(start),
		}, nil
	}

	return &Decision{
		Action:  e.defaultAction,
		Reason:  "no matching rule — default action",
		Lookup:  lookup,
		Latency: time.Since(start),
	}, nil
}

func (e *Engine) ruleMatches(r *GeoRule, l *GeoLookup, ip string) bool {
	switch r.Target {
	case TargetCountry:
		return strings.EqualFold(l.CountryCode, r.Value)
	case TargetContinent:
		return strings.EqualFold(l.Continent, r.Value)
	case TargetASN:
		return fmt.Sprintf("%d", l.ASN) == r.Value
	case TargetCIDR:
		_, cidr, err := net.ParseCIDR(r.Value)
		if err != nil { return false }
		parsed := net.ParseIP(ip)
		return parsed != nil && cidr.Contains(parsed)
	}
	return false
}

// ── Rule Management ───────────────────────────────────────────────────────────

// AddRule adds a new GeoIP rule (sorted by priority)
func (e *Engine) AddRule(r GeoRule) {
	if r.ID == "" { r.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano()) }
	if r.CreatedAt.IsZero() { r.CreatedAt = time.Now().UTC() }

	e.mu.Lock()
	defer e.mu.Unlock()

	// Insert sorted by priority
	inserted := false
	for i, existing := range e.rules {
		if r.Priority < existing.Priority {
			e.rules = append(e.rules[:i], append([]GeoRule{r}, e.rules[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		e.rules = append(e.rules, r)
	}

	// Persist to Redis
	if e.rdb != nil {
		data, _ := json.Marshal(r)
		e.rdb.HSet(e.ctx, "axelus:geoip:rules", r.ID, data)
	}
}

// RemoveRule removes a rule by ID
func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			if e.rdb != nil {
				e.rdb.HDel(e.ctx, "axelus:geoip:rules", id)
			}
			return true
		}
	}
	return false
}

// GetRules returns all rules
func (e *Engine) GetRules() []GeoRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]GeoRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// GetStats returns engine statistics
func (e *Engine) GetStats() map[string]interface{} {
	e.stats.mu.Lock()
	defer e.stats.mu.Unlock()
	return map[string]interface{}{
		"blocked":    e.stats.Blocked,
		"challenged": e.stats.Challenged,
		"allowed":    e.stats.Allowed,
		"logged":     e.stats.Logged,
		"cache_hits": e.stats.CacheHits,
		"cache_miss": e.stats.CacheMisses,
		"by_country": e.stats.ByCountry,
	}
}

// ── MaxMind Database Updater ──────────────────────────────────────────────────

// UpdateDatabase downloads the latest MaxMind GeoIP2-City database
func UpdateDatabase(accountID, licenseKey, destDir string) error {
	url := fmt.Sprintf(
		"https://download.maxmind.com/app/geoip_download?edition_id=GeoIP2-City&license_key=%s&suffix=tar.gz",
		licenseKey,
	)

	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(accountID, licenseKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("MaxMind returned HTTP %d — check account ID and license key", resp.StatusCode)
	}

	// Extract .mmdb from tar.gz
	gz, err := gzip.NewReader(resp.Body)
	if err != nil { return err }
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF { break }
		if err != nil { return err }
		if strings.HasSuffix(hdr.Name, ".mmdb") {
			dest := filepath.Join(destDir, "GeoIP2-City.mmdb")
			f, err := os.Create(dest)
			if err != nil { return err }
			if _, err := io.Copy(f, tr); err != nil {
				f.Close(); return err
			}
			f.Close()
			fmt.Printf("[geoip] Database updated: %s\n", dest)
			return nil
		}
	}
	return fmt.Errorf("no .mmdb file found in MaxMind archive")
}

// ── Default High-Risk Rule Set ────────────────────────────────────────────────

// DefaultBlockRules returns a pre-configured set of high-risk country block rules
func DefaultBlockRules() []GeoRule {
	highRisk := []struct{ code, name string }{
		{"KP", "North Korea"},
		{"IR", "Iran"},
		{"SY", "Syria"},
		{"BY", "Belarus"},
	}
	challengeRisk := []struct{ code, name string }{
		{"RU", "Russia"},
		{"CN", "China"},
	}

	var rules []GeoRule
	for i, c := range highRisk {
		rules = append(rules, GeoRule{
			ID: fmt.Sprintf("default-block-%s", strings.ToLower(c.code)),
			Target: TargetCountry, Value: c.code,
			Action: ActionBlock, Priority: i + 1,
			Enabled: true,
			Note: fmt.Sprintf("Default high-risk block: %s", c.name),
			CreatedAt: time.Now().UTC(),
		})
	}
	for i, c := range challengeRisk {
		rules = append(rules, GeoRule{
			ID: fmt.Sprintf("default-challenge-%s", strings.ToLower(c.code)),
			Target: TargetCountry, Value: c.code,
			Action: ActionChallenge, Priority: 100 + i,
			Enabled: false, // off by default — operator must enable
			Note: fmt.Sprintf("Default challenge rule: %s (disabled by default)", c.name),
			CreatedAt: time.Now().UTC(),
		})
	}
	return rules
}
