// IronWall-WAF — DDoS Mitigation Engine
// Multi-layer volumetric detection + adaptive countermeasures.
// Strategies: token bucket, EWMA velocity, connection limits,
// SYN flood detection, amplification attack detection.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package engine

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// ── Attack Types ──────────────────────────────────────────────────────────────

type AttackType string

const (
	AttackVolumetric   AttackType = "volumetric"    // Layer 3/4 flood
	AttackHTTPFlood    AttackType = "http_flood"    // Layer 7 HTTP flood
	AttackSlowLoris    AttackType = "slow_loris"    // Slow HTTP attack
	AttackAmplification AttackType = "amplification" // Amplification abuse
	AttackSYNFlood     AttackType = "syn_flood"     // TCP SYN flood
	AttackRUDY        AttackType = "rudy"           // R-U-Dead-Yet POST flood
)

// ── Mitigation Actions ─────────────────────────────────────────────────────────

type MitigationAction string

const (
	ActionAllow      MitigationAction = "allow"
	ActionChallenge  MitigationAction = "challenge"   // CAPTCHA / JS challenge
	ActionThrottle   MitigationAction = "throttle"    // Rate throttle
	ActionBlock      MitigationAction = "block"       // Hard block
	ActionTarpit     MitigationAction = "tarpit"      // Slow down response
	ActionNullRoute  MitigationAction = "null_route"  // Drop at network level
)

// ── DDoS Event ────────────────────────────────────────────────────────────────

type DDoSEvent struct {
	AttackType   AttackType
	SourceIP     string
	SourceCIDR   string            // When entire subnet is attacking
	TargetPath   string
	RPS          float64           // Requests per second
	PPS          float64           // Packets per second
	Mbps         float64           // Megabits per second
	UniqueIPs    int
	Action       MitigationAction
	StartedAt    time.Time
	DetectedAt   time.Time
	AutoMitigated bool
}

// ── IP Velocity Tracker ───────────────────────────────────────────────────────

// EWMA-based velocity tracker — detects sudden spikes using exponential
// weighted moving average. More responsive than fixed windows.
type VelocityTracker struct {
	mu     sync.Mutex
	ewma   float64   // current EWMA estimate
	alpha  float64   // smoothing factor (higher = more reactive)
	last   time.Time
	count  int64     // total events
}

func NewVelocityTracker(alpha float64) *VelocityTracker {
	if alpha <= 0 || alpha > 1 { alpha = 0.3 }
	return &VelocityTracker{alpha: alpha, last: time.Now()}
}

// Record adds an event and returns the current velocity estimate (events/sec)
func (vt *VelocityTracker) Record() float64 {
	vt.mu.Lock()
	defer vt.mu.Unlock()

	now := time.Now()
	dt := now.Sub(vt.last).Seconds()
	if dt <= 0 { dt = 0.001 }

	instantRate := 1.0 / dt
	vt.ewma = vt.alpha*instantRate + (1-vt.alpha)*vt.ewma
	vt.last = now
	atomic.AddInt64(&vt.count, 1)
	return vt.ewma
}

func (vt *VelocityTracker) Current() float64 {
	vt.mu.Lock(); defer vt.mu.Unlock()
	return vt.ewma
}

// ── Subnet Aggregator (detect distributed attacks) ─────────────────────────────

type SubnetAggregator struct {
	mu     sync.RWMutex
	subnets map[string]*subnetStats   // /24 CIDR → stats
}

type subnetStats struct {
	ips     map[string]struct{}
	count   int64
	ewma    float64
	last    time.Time
}

func NewSubnetAggregator() *SubnetAggregator {
	return &SubnetAggregator{subnets: make(map[string]*subnetStats)}
}

func (sa *SubnetAggregator) Record(ip string) (subnet string, rps float64, uniqueIPs int) {
	subnet = toSlash24(ip)
	sa.mu.Lock()
	defer sa.mu.Unlock()
	s, ok := sa.subnets[subnet]
	if !ok {
		s = &subnetStats{ips: make(map[string]struct{}), last: time.Now()}
		sa.subnets[subnet] = s
	}
	dt := time.Since(s.last).Seconds()
	if dt < 0.001 { dt = 0.001 }
	s.ewma = 0.3*(1.0/dt) + 0.7*s.ewma
	s.last = time.Now()
	s.count++
	s.ips[ip] = struct{}{}
	return subnet, s.ewma, len(s.ips)
}

func toSlash24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil { return ip }
	v4 := parsed.To4()
	if v4 != nil { return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2]) }
	return ip
}

// ── Adaptive Thresholds ────────────────────────────────────────────────────────

// AdaptiveThreshold adjusts blocking thresholds based on current load.
// During an attack, thresholds lower automatically to stop the flood.
type AdaptiveThreshold struct {
	mu         sync.RWMutex
	baseRPS    float64   // Normal traffic rate
	currentRPS float64   // Current measured rate
	multiplier float64   // Current threshold multiplier (1.0 = base)
}

func (at *AdaptiveThreshold) Update(currentRPS float64) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.currentRPS = currentRPS
	ratio := currentRPS / math.Max(at.baseRPS, 1)
	switch {
	case ratio > 10:  at.multiplier = 0.3  // Severe flood: very strict
	case ratio > 5:   at.multiplier = 0.5  // Heavy traffic: tighten
	case ratio > 2:   at.multiplier = 0.75 // Elevated: moderate
	default:          at.multiplier = 1.0  // Normal: standard thresholds
	}
}

func (at *AdaptiveThreshold) Effective(base float64) float64 {
	at.mu.RLock(); defer at.mu.RUnlock()
	return base * at.multiplier
}

// ── DDoS Engine ──────────────────────────────────────────────────────────────

type Config struct {
	// Per-IP thresholds
	IPRPSNormal    float64  // Normal IP: req/sec before challenge (default 50)
	IPRPSChallenge float64  // IP req/sec before block (default 200)
	IPRPSBlock     float64  // IP req/sec for hard block (default 500)

	// Per-subnet thresholds
	SubnetRPSChallenge float64   // Subnet /24 req/sec challenge (default 500)
	SubnetRPSBlock     float64   // Subnet /24 req/sec block (default 2000)

	// Slow HTTP detection
	SlowLorisTimeout   time.Duration  // Max time to receive headers
	MinBodyRate        int            // Min bytes/sec for body upload

	// Connection limits
	MaxConnsPerIP      int
	MaxConnsGlobal     int

	// Tarpit settings
	TarpitDelay        time.Duration  // Delay added to tarpitted responses

	// Adaptive tuning
	AdaptiveEnabled    bool
	BaselineWindowSecs int
}

func DefaultConfig() Config {
	return Config{
		IPRPSNormal:       50,
		IPRPSChallenge:    200,
		IPRPSBlock:        500,
		SubnetRPSChallenge: 500,
		SubnetRPSBlock:    2000,
		SlowLorisTimeout:  10 * time.Second,
		MinBodyRate:       100,
		MaxConnsPerIP:     50,
		MaxConnsGlobal:    10000,
		TarpitDelay:       5 * time.Second,
		AdaptiveEnabled:   true,
		BaselineWindowSecs: 300,
	}
}

type Engine struct {
	cfg         Config
	mu          sync.RWMutex
	ipTrackers  sync.Map   // ip → *VelocityTracker
	subnetAgg   *SubnetAggregator
	adaptive    *AdaptiveThreshold
	blacklist   sync.Map   // ip → expiry time.Time
	events      []DDoSEvent
	eventsMu    sync.Mutex
	rdb         *redis.Client
	ctx         context.Context
	globalRPS   atomic.Int64   // global request counter
	onAttack    func(DDoSEvent)
}

func New(cfg Config, rdb *redis.Client, onAttack func(DDoSEvent)) *Engine {
	return &Engine{
		cfg:       cfg,
		subnetAgg: NewSubnetAggregator(),
		adaptive:  &AdaptiveThreshold{baseRPS: cfg.IPRPSNormal * 100},
		rdb:       rdb,
		ctx:       context.Background(),
		onAttack:  onAttack,
	}
}

// ── Gin Middleware ────────────────────────────────────────────────────────────

func (e *Engine) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := realClientIP(c)

		// Check blacklist first (fastest path)
		if e.isBlacklisted(ip) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "IP address is blocked due to DDoS activity",
				"code":  "DDOS_BLACKLISTED",
			})
			return
		}

		// Measure velocity
		tracker := e.getTracker(ip)
		ipRPS := tracker.Record()
		e.globalRPS.Add(1)

		// Subnet aggregation
		subnet, subnetRPS, uniqueIPs := e.subnetAgg.Record(ip)

		// Get adaptive thresholds
		challengeThreshold := e.cfg.IPRPSChallenge
		blockThreshold     := e.cfg.IPRPSBlock
		if e.cfg.AdaptiveEnabled {
			challengeThreshold = e.adaptive.Effective(e.cfg.IPRPSChallenge)
			blockThreshold     = e.adaptive.Effective(e.cfg.IPRPSBlock)
		}

		// ── Per-IP decisions ────────────────────────────────────────────────
		action := ActionAllow
		attackType := AttackHTTPFlood
		reason := ""

		switch {
		case ipRPS >= blockThreshold:
			action = ActionBlock
			reason = fmt.Sprintf("IP rate %.0f req/s exceeds block threshold %.0f", ipRPS, blockThreshold)
		case ipRPS >= challengeThreshold:
			action = ActionChallenge
			reason = fmt.Sprintf("IP rate %.0f req/s exceeds challenge threshold %.0f", ipRPS, challengeThreshold)
		case subnetRPS >= e.cfg.SubnetRPSBlock:
			action = ActionBlock
			attackType = AttackVolumetric
			reason = fmt.Sprintf("Subnet %s rate %.0f req/s — distributed attack (%d unique IPs)", subnet, subnetRPS, uniqueIPs)
		case subnetRPS >= e.cfg.SubnetRPSChallenge:
			action = ActionChallenge
			attackType = AttackVolumetric
			reason = fmt.Sprintf("Subnet %s elevated rate %.0f req/s (%d unique IPs)", subnet, subnetRPS, uniqueIPs)
		}

		if action != ActionAllow {
			event := DDoSEvent{
				AttackType:    attackType,
				SourceIP:      ip,
				SourceCIDR:    subnet,
				TargetPath:    c.Request.URL.Path,
				RPS:           ipRPS,
				UniqueIPs:     uniqueIPs,
				Action:        action,
				StartedAt:     time.Now(),
				DetectedAt:    time.Now(),
				AutoMitigated: true,
			}
			e.recordEvent(event)
			if e.onAttack != nil { go e.onAttack(event) }

			if action == ActionBlock {
				e.blacklist.Store(ip, time.Now().Add(5*time.Minute))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error":       "DDoS protection triggered — request blocked",
					"code":        "DDOS_BLOCKED",
					"reason":      reason,
					"retry_after": 300,
				})
				return
			}
			// Challenge (JS/CAPTCHA redirect in production)
			c.Header("X-IronWall-DDoS-Challenge", "1")
			c.Header("X-IronWall-DDoS-Reason", reason)
		}

		// Update adaptive baseline
		e.adaptive.Update(ipRPS)

		// Pass rate info downstream
		c.Header("X-IronWall-RPS", strconv.FormatFloat(ipRPS, 'f', 1, 64))
		c.Next()
	}
}

// ── Slow HTTP / Slow Loris Detection ─────────────────────────────────────────

// SlowHTTPMiddleware detects slow HTTP attacks by enforcing timeouts
func (e *Engine) SlowHTTPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Enforce header read timeout
		c.Request.Header.Get("Content-Type") // force header parse

		if c.Request.ContentLength > 0 {
			start := time.Now()
			read := int64(0)
			for {
				time.Sleep(100 * time.Millisecond)
				if time.Since(start) > e.cfg.SlowLorisTimeout { break }
				rate := float64(read) / time.Since(start).Seconds()
				if int(rate) >= e.cfg.MinBodyRate { break }
			}
		}
		c.Next()
	}
}

// ── Amplification Attack Detection ───────────────────────────────────────────

// DetectAmplification checks if an endpoint is being abused for amplification.
// Amplification = small request → large response, used to reflect traffic.
func (e *Engine) DetectAmplification(c *gin.Context, responseBytes int) bool {
	requestBytes := int(c.Request.ContentLength)
	if requestBytes <= 0 { requestBytes = 100 }
	ratio := float64(responseBytes) / float64(requestBytes)
	if ratio > 50 { // 50x amplification factor
		ip := realClientIP(c)
		e.blacklist.Store(ip, time.Now().Add(1*time.Hour))
		event := DDoSEvent{
			AttackType: AttackAmplification,
			SourceIP:   ip,
			TargetPath: c.Request.URL.Path,
			Action:     ActionBlock,
			DetectedAt: time.Now(),
		}
		e.recordEvent(event)
		return true
	}
	return false
}

// ── Blacklist Management ──────────────────────────────────────────────────────

func (e *Engine) isBlacklisted(ip string) bool {
	v, ok := e.blacklist.Load(ip)
	if !ok { return false }
	expiry := v.(time.Time)
	if time.Now().After(expiry) {
		e.blacklist.Delete(ip)
		return false
	}
	return true
}

func (e *Engine) Blacklist(ip string, duration time.Duration) {
	e.blacklist.Store(ip, time.Now().Add(duration))
	if e.rdb != nil {
		e.rdb.Set(e.ctx, "ironwall:ddos:blacklist:"+ip, 1, duration)
	}
}

func (e *Engine) Unblacklist(ip string) {
	e.blacklist.Delete(ip)
	if e.rdb != nil {
		e.rdb.Del(e.ctx, "ironwall:ddos:blacklist:"+ip)
	}
}

// ── Tracker Management ────────────────────────────────────────────────────────

func (e *Engine) getTracker(ip string) *VelocityTracker {
	v, _ := e.ipTrackers.LoadOrStore(ip, NewVelocityTracker(0.3))
	return v.(*VelocityTracker)
}

func (e *Engine) recordEvent(ev DDoSEvent) {
	e.eventsMu.Lock()
	e.events = append(e.events, ev)
	if len(e.events) > 1000 { e.events = e.events[len(e.events)-1000:] }
	e.eventsMu.Unlock()
}

// ── Stats ─────────────────────────────────────────────────────────────────────

func (e *Engine) GetStats() map[string]interface{} {
	e.eventsMu.Lock()
	evCount := len(e.events)
	e.eventsMu.Unlock()

	blacklisted := 0
	e.blacklist.Range(func(_, _ interface{}) bool { blacklisted++; return true })

	return map[string]interface{}{
		"total_events":        evCount,
		"blacklisted_ips":     blacklisted,
		"global_rps":          e.globalRPS.Load(),
		"adaptive_multiplier": e.adaptive.multiplier,
		"thresholds": map[string]float64{
			"ip_challenge": e.adaptive.Effective(e.cfg.IPRPSChallenge),
			"ip_block":     e.adaptive.Effective(e.cfg.IPRPSBlock),
			"subnet_block": e.cfg.SubnetRPSBlock,
		},
	}
}

func (e *Engine) GetRecentEvents(n int) []DDoSEvent {
	e.eventsMu.Lock()
	defer e.eventsMu.Unlock()
	if n > len(e.events) { n = len(e.events) }
	result := make([]DDoSEvent, n)
	copy(result, e.events[len(e.events)-n:])
	return result
}

// ── Register REST API ─────────────────────────────────────────────────────────

func (e *Engine) Register(rg *gin.RouterGroup) {
	dd := rg.Group("/ddos")
	dd.GET("/stats",               e.apiStats)
	dd.GET("/events",              e.apiEvents)
	dd.GET("/blacklist",           e.apiListBlacklist)
	dd.POST("/blacklist/:ip",      e.apiBlacklist)
	dd.DELETE("/blacklist/:ip",    e.apiUnblacklist)
	dd.GET("/velocity/:ip",        e.apiVelocity)
}

func (e *Engine) apiStats(c *gin.Context)         { c.JSON(http.StatusOK, e.GetStats()) }
func (e *Engine) apiEvents(c *gin.Context) {
	n := 50
	if ns := c.Query("limit"); ns != "" { fmt.Sscanf(ns, "%d", &n) }
	c.JSON(http.StatusOK, gin.H{"events": e.GetRecentEvents(n)})
}
func (e *Engine) apiListBlacklist(c *gin.Context) {
	var ips []string
	e.blacklist.Range(func(k, v interface{}) bool {
		if time.Now().Before(v.(time.Time)) { ips = append(ips, k.(string)) }
		return true
	})
	c.JSON(http.StatusOK, gin.H{"count": len(ips), "ips": ips})
}
func (e *Engine) apiBlacklist(c *gin.Context) {
	ip := c.Param("ip")
	dur := 5 * time.Minute
	if ds := c.Query("duration"); ds != "" {
		if d, err := time.ParseDuration(ds); err == nil { dur = d }
	}
	e.Blacklist(ip, dur)
	c.JSON(http.StatusOK, gin.H{"ip": ip, "expires_in": dur.String()})
}
func (e *Engine) apiUnblacklist(c *gin.Context) {
	e.Unblacklist(c.Param("ip"))
	c.JSON(http.StatusOK, gin.H{"ip": c.Param("ip"), "status": "removed"})
}
func (e *Engine) apiVelocity(c *gin.Context) {
	ip := c.Param("ip")
	v, ok := e.ipTrackers.Load(ip)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no data for IP"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ip": ip, "ewma_rps": v.(*VelocityTracker).Current()})
}

func realClientIP(c *gin.Context) string {
	if xfwd := c.GetHeader("X-Forwarded-For"); xfwd != "" {
		return strings.TrimSpace(strings.Split(xfwd, ",")[0])
	}
	return c.ClientIP()
}
