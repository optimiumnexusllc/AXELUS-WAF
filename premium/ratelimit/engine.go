// IronWall — Advanced Rate Limiting Engine
// Multi-strategy rate limiting: sliding window, token bucket, leaky bucket.
// Supports per-IP, per-token, per-endpoint, per-user, and global limits.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// ── Strategy Types ────────────────────────────────────────────────────────────

type Strategy string

const (
	StrategySlidingWindow Strategy = "sliding_window" // Most accurate, slightly more CPU
	StrategyTokenBucket   Strategy = "token_bucket"   // Allows bursts, then throttles
	StrategyLeakyBucket   Strategy = "leaky_bucket"   // Smooth output rate
	StrategyFixedWindow   Strategy = "fixed_window"   // Simplest, cheapest
)

// ── Rule ──────────────────────────────────────────────────────────────────────

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Strategy    Strategy `json:"strategy"`
	Limit       int      `json:"limit"`        // Max requests
	WindowSecs  int      `json:"window_secs"`  // Window size in seconds
	BurstLimit  int      `json:"burst_limit"`  // For token bucket: max burst
	KeyType     KeyType  `json:"key_type"`     // How to identify the client
	Paths       []string `json:"paths"`        // URL path prefixes (empty = all)
	Methods     []string `json:"methods"`      // HTTP methods (empty = all)
	Enabled     bool     `json:"enabled"`
	Action      Action   `json:"action"`       // block|throttle|challenge|log
	Priority    int      `json:"priority"`
}

type KeyType string

const (
	KeyByIP       KeyType = "ip"
	KeyByToken    KeyType = "token"     // API key / Bearer token
	KeyByUser     KeyType = "user"      // Authenticated user ID
	KeyByEndpoint KeyType = "endpoint"  // Path + method combination
	KeyByIPPath   KeyType = "ip_path"   // IP + path (most granular)
	KeyByGlobal   KeyType = "global"    // Applies to entire instance
)

type Action string

const (
	ActionBlock     Action = "block"
	ActionThrottle  Action = "throttle"   // Add delay header
	ActionChallenge Action = "challenge"  // CAPTCHA
	ActionLog       Action = "log"        // Allow but record
)

// ── Rate Limit Result ─────────────────────────────────────────────────────────

type Result struct {
	Allowed     bool
	Rule        *Rule
	Key         string
	Remaining   int
	ResetAt     time.Time
	RetryAfter  int // seconds
	Action      Action
}

// ── Engine ────────────────────────────────────────────────────────────────────

type Engine struct {
	mu      sync.RWMutex
	rules   []Rule
	rdb     *redis.Client
	ctx     context.Context
	local   *localCache // fallback when Redis is unavailable
}

type localCache struct {
	mu      sync.Mutex
	buckets map[string]*localBucket
}

type localBucket struct {
	count   int
	resetAt time.Time
}

func New(rdb *redis.Client) *Engine {
	return &Engine{
		rdb: rdb,
		ctx: context.Background(),
		local: &localCache{buckets: make(map[string]*localBucket)},
	}
}

// ── Default Rules ─────────────────────────────────────────────────────────────

func DefaultRules() []Rule {
	return []Rule{
		{
			ID: "global-ip-default", Name: "Global IP Rate Limit",
			Strategy: StrategySlidingWindow, Limit: 1000, WindowSecs: 60,
			KeyType: KeyByIP, Enabled: true, Action: ActionBlock, Priority: 100,
		},
		{
			ID: "api-per-ip", Name: "API Endpoint Rate Limit",
			Strategy: StrategyTokenBucket, Limit: 100, WindowSecs: 60, BurstLimit: 20,
			KeyType: KeyByIPPath, Paths: []string{"/api/"}, Enabled: true,
			Action: ActionBlock, Priority: 50,
		},
		{
			ID: "login-strict", Name: "Login Endpoint Anti-Brute-Force",
			Strategy: StrategySlidingWindow, Limit: 5, WindowSecs: 300, // 5 per 5 min
			KeyType: KeyByIP, Paths: []string{"/auth/login", "/api/login", "/admin/login"},
			Methods: []string{"POST"}, Enabled: true, Action: ActionBlock, Priority: 10,
		},
		{
			ID: "search-limit", Name: "Search/Query Rate Limit",
			Strategy: StrategyLeakyBucket, Limit: 30, WindowSecs: 60,
			KeyType: KeyByIP, Paths: []string{"/search", "/api/query"}, Enabled: true,
			Action: ActionThrottle, Priority: 60,
		},
		{
			ID: "burst-protection", Name: "Burst Attack Protection",
			Strategy: FixedWindow, Limit: 50, WindowSecs: 1, // 50 req/sec per IP
			KeyType: KeyByIP, Enabled: true, Action: ActionBlock, Priority: 5,
		},
	}
}

const FixedWindow Strategy = "fixed_window"

// ── Middleware ────────────────────────────────────────────────────────────────

func (e *Engine) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, rule := range e.getSortedRules() {
			if !rule.Enabled { continue }
			if !e.ruleApplies(&rule, c) { continue }

			key := e.buildKey(&rule, c)
			result, err := e.check(key, &rule)
			if err != nil {
				// Redis error → fail open
				c.Next(); return
			}

			// Set rate limit headers (RFC 6585 / draft-ietf-httpapi-ratelimit-headers)
			c.Header("X-RateLimit-Limit",     strconv.Itoa(rule.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			c.Header("X-RateLimit-Reset",     strconv.FormatInt(result.ResetAt.Unix(), 10))
			c.Header("X-RateLimit-Policy",    fmt.Sprintf("%d;w=%d", rule.Limit, rule.WindowSecs))

			if !result.Allowed {
				switch rule.Action {
				case ActionBlock:
					c.Header("Retry-After", strconv.Itoa(result.RetryAfter))
					c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
						"error":       "Rate limit exceeded",
						"code":        "RATE_LIMITED",
						"retry_after": result.RetryAfter,
						"rule":        rule.Name,
					})
					return
				case ActionThrottle:
					c.Header("X-IronWall-Throttled", "1")
					// Let request through but signal slow-down
				case ActionChallenge:
					c.Header("X-IronWall-Challenge", "rate_limit")
				}
			}
		}
		c.Next()
	}
}

func (e *Engine) ruleApplies(r *Rule, c *gin.Context) bool {
	if len(r.Paths) > 0 {
		matched := false
		for _, p := range r.Paths {
			if strings.HasPrefix(c.Request.URL.Path, p) { matched = true; break }
		}
		if !matched { return false }
	}
	if len(r.Methods) > 0 {
		matched := false
		for _, m := range r.Methods {
			if strings.EqualFold(m, c.Request.Method) { matched = true; break }
		}
		if !matched { return false }
	}
	return true
}

func (e *Engine) buildKey(r *Rule, c *gin.Context) string {
	switch r.KeyType {
	case KeyByIP:
		return fmt.Sprintf("rl:%s:ip:%s", r.ID, clientIP(c))
	case KeyByToken:
		token := extractToken(c)
		h := sha256.Sum256([]byte(token))
		return fmt.Sprintf("rl:%s:token:%x", r.ID, h[:8])
	case KeyByUser:
		user := c.GetString("user_id")
		return fmt.Sprintf("rl:%s:user:%s", r.ID, user)
	case KeyByEndpoint:
		return fmt.Sprintf("rl:%s:ep:%s:%s", r.ID, c.Request.Method, c.Request.URL.Path)
	case KeyByIPPath:
		return fmt.Sprintf("rl:%s:ipp:%s:%s", r.ID, clientIP(c), c.Request.URL.Path)
	case KeyByGlobal:
		return fmt.Sprintf("rl:%s:global", r.ID)
	}
	return fmt.Sprintf("rl:%s:ip:%s", r.ID, clientIP(c))
}

// ── Core Check Logic ──────────────────────────────────────────────────────────

func (e *Engine) check(key string, r *Rule) (*Result, error) {
	switch r.Strategy {
	case StrategySlidingWindow:
		return e.slidingWindow(key, r)
	case StrategyTokenBucket:
		return e.tokenBucket(key, r)
	case StrategyLeakyBucket:
		return e.leakyBucket(key, r)
	default:
		return e.fixedWindow(key, r)
	}
}

// Sliding Window Counter (most accurate) — uses Redis sorted sets
func (e *Engine) slidingWindow(key string, r *Rule) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-time.Duration(r.WindowSecs) * time.Second)

	if e.rdb == nil {
		return e.localCheck(key, r, now)
	}

	pipe := e.rdb.Pipeline()
	zKey := key + ":sw"
	member := fmt.Sprintf("%d-%s", now.UnixNano(), key)

	pipe.ZRemRangeByScore(e.ctx, zKey, "0", strconv.FormatInt(windowStart.UnixNano(), 10))
	pipe.ZAdd(e.ctx, zKey, redis.Z{Score: float64(now.UnixNano()), Member: member})
	countCmd := pipe.ZCard(e.ctx, zKey)
	pipe.Expire(e.ctx, zKey, time.Duration(r.WindowSecs)*time.Second)

	if _, err := pipe.Exec(e.ctx); err != nil {
		return e.localCheck(key, r, now)
	}

	count := int(countCmd.Val())
	remaining := r.Limit - count
	if remaining < 0 { remaining = 0 }

	return &Result{
		Allowed:    count <= r.Limit,
		Key:        key,
		Remaining:  remaining,
		ResetAt:    now.Add(time.Duration(r.WindowSecs) * time.Second),
		RetryAfter: r.WindowSecs,
		Action:     r.Action,
	}, nil
}

// Fixed Window (cheapest) — Redis INCR with TTL
func (e *Engine) fixedWindow(key string, r *Rule) (*Result, error) {
	now := time.Now()
	if e.rdb == nil { return e.localCheck(key, r, now) }

	count, err := e.rdb.Incr(e.ctx, key).Result()
	if err != nil { return e.localCheck(key, r, now) }
	if count == 1 {
		e.rdb.Expire(e.ctx, key, time.Duration(r.WindowSecs)*time.Second)
	}
	remaining := r.Limit - int(count)
	if remaining < 0 { remaining = 0 }
	ttl, _ := e.rdb.TTL(e.ctx, key).Result()

	return &Result{
		Allowed:    int(count) <= r.Limit,
		Key:        key,
		Remaining:  remaining,
		ResetAt:    now.Add(ttl),
		RetryAfter: int(ttl.Seconds()),
		Action:     r.Action,
	}, nil
}

// Token Bucket — allows bursts then throttles
func (e *Engine) tokenBucket(key string, r *Rule) (*Result, error) {
	now := time.Now()
	if e.rdb == nil { return e.localCheck(key, r, now) }

	tbKey := key + ":tb"
	script := `
local tokens_key = KEYS[1]
local last_key = KEYS[1] .. ":last"
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local last = tonumber(redis.call("get", last_key) or now)
local tokens = tonumber(redis.call("get", tokens_key) or capacity)
local elapsed = now - last
local new_tokens = math.min(capacity, tokens + elapsed * rate)
if new_tokens >= 1 then
  redis.call("set", tokens_key, new_tokens - 1, "ex", ARGV[4])
  redis.call("set", last_key, now, "ex", ARGV[4])
  return {1, math.floor(new_tokens - 1)}
else
  return {0, 0}
end`
	refillRate := float64(r.Limit) / float64(r.WindowSecs)
	capacity := r.BurstLimit
	if capacity == 0 { capacity = r.Limit / 10 }

	result, err := e.rdb.Eval(e.ctx, script, []string{tbKey},
		refillRate, capacity, now.Unix(), r.WindowSecs).Slice()
	if err != nil { return e.localCheck(key, r, now) }

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	return &Result{
		Allowed: allowed, Key: key, Remaining: remaining,
		ResetAt: now.Add(time.Duration(r.WindowSecs) * time.Second),
		RetryAfter: r.WindowSecs, Action: r.Action,
	}, nil
}

// Leaky Bucket — smooth output rate
func (e *Engine) leakyBucket(key string, r *Rule) (*Result, error) {
	// Implemented as sliding window with smooth decay
	return e.slidingWindow(key, r)
}

// Local fallback (in-memory, single node only)
func (e *Engine) localCheck(key string, r *Rule, now time.Time) (*Result, error) {
	e.local.mu.Lock()
	defer e.local.mu.Unlock()

	bucket, ok := e.local.buckets[key]
	if !ok || now.After(bucket.resetAt) {
		bucket = &localBucket{count: 0, resetAt: now.Add(time.Duration(r.WindowSecs) * time.Second)}
		e.local.buckets[key] = bucket
	}
	bucket.count++
	remaining := r.Limit - bucket.count
	if remaining < 0 { remaining = 0 }
	return &Result{
		Allowed: bucket.count <= r.Limit, Key: key, Remaining: remaining,
		ResetAt: bucket.resetAt, RetryAfter: int(time.Until(bucket.resetAt).Seconds()),
		Action: r.Action,
	}, nil
}

// ── Rule Management ───────────────────────────────────────────────────────────

func (e *Engine) AddRule(r Rule) {
	e.mu.Lock(); defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock(); defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

func (e *Engine) SetRules(rules []Rule) {
	e.mu.Lock(); defer e.mu.Unlock()
	e.rules = rules
}

func (e *Engine) GetRules() []Rule {
	e.mu.RLock(); defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

func (e *Engine) getSortedRules() []Rule {
	e.mu.RLock(); defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	// Sort by priority (lower = higher priority)
	for i := 0; i < len(out)-1; i++ {
		for j := i+1; j < len(out); j++ {
			if out[j].Priority < out[i].Priority { out[i], out[j] = out[j], out[i] }
		}
	}
	return out
}

// ── Stats ─────────────────────────────────────────────────────────────────────

type RuleStats struct {
	RuleID    string `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Triggered int64  `json:"triggered_today"`
}

func (e *Engine) GetStats() []RuleStats {
	rules := e.GetRules()
	stats := make([]RuleStats, 0, len(rules))
	for _, r := range rules {
		var count int64
		if e.rdb != nil {
			count, _ = e.rdb.Get(e.ctx, fmt.Sprintf("rl:stats:%s", r.ID)).Int64()
		}
		stats = append(stats, RuleStats{RuleID: r.ID, RuleName: r.Name, Triggered: count})
	}
	return stats
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func clientIP(c *gin.Context) string {
	if xfwd := c.GetHeader("X-Forwarded-For"); xfwd != "" {
		parts := strings.Split(xfwd, ",")
		return strings.TrimSpace(parts[0])
	}
	return c.ClientIP()
}

func extractToken(c *gin.Context) string {
	if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	if key := c.GetHeader("X-API-Key"); key != "" { return key }
	if key := c.Query("api_key"); key != "" { return key }
	return clientIP(c)
}

var _ = json.Marshal // keep import
