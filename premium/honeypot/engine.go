// IronWall — Deception Layer / Honeypot Engine
// Traps attackers by injecting hidden decoy endpoints and fake credentials.
// Automatically blacklists IPs that interact with honeypot traps.
package honeypot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// ── Trap Types ────────────────────────────────────────────────────────────────

type TrapType string

const (
	TrapHiddenEndpoint TrapType = "hidden_endpoint" // /admin/.env /wp-admin etc.
	TrapFakeCredential TrapType = "fake_credential"  // fake API keys in HTML comments
	TrapHoneyCookie    TrapType = "honey_cookie"     // Cookie that only bots read
	TrapHoneytokenURL  TrapType = "honeytoken_url"   // Unique URLs that should never be visited
	TrapSQLComment     TrapType = "sql_comment"      // Fake SQL comments in responses
	TrapHTMLCanary     TrapType = "html_canary"      // Hidden form fields
)

// ── Trap Config ────────────────────────────────────────────────────────────────

type Trap struct {
	ID          string   `json:"id"`
	Type        TrapType `json:"type"`
	Path        string   `json:"path,omitempty"`     // URL path
	Name        string   `json:"name"`
	Enabled     bool     `json:"enabled"`
	AutoBlock   bool     `json:"auto_block"`         // Auto-blacklist on trigger
	BlockDays   int      `json:"block_days"`
	TriggerCount int64   `json:"trigger_count"`
	LastTriggered *time.Time `json:"last_triggered,omitempty"`
}

// ── Trigger Event ─────────────────────────────────────────────────────────────

type TriggerEvent struct {
	TrapID    string    `json:"trap_id"`
	TrapType  TrapType  `json:"trap_type"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	Headers   map[string]string `json:"headers"`
	Timestamp time.Time `json:"timestamp"`
}

// ── Engine ────────────────────────────────────────────────────────────────────

type Engine struct {
	mu       sync.RWMutex
	traps    []Trap
	rdb      *redis.Client
	ctx      context.Context
	onTrigger func(TriggerEvent) // callback for alerting
}

// Default hidden paths that attackers commonly probe
var DefaultHoneypotPaths = []string{
	"/.env", "/.git/config", "/wp-admin", "/wp-login.php",
	"/phpmyadmin", "/admin", "/administrator", "/.aws/credentials",
	"/api/v1/users", "/backup.zip", "/dump.sql", "/config.yml",
	"/.htpasswd", "/server-status", "/actuator/env", "/actuator/heapdump",
	"/.DS_Store", "/crossdomain.xml", "/xmlrpc.php", "/shell.php",
	"/eval.php", "/upload.php", "/cmd.php", "/webshell.php",
}

func New(rdb *redis.Client, onTrigger func(TriggerEvent)) *Engine {
	e := &Engine{rdb: rdb, ctx: context.Background(), onTrigger: onTrigger}
	e.initDefaultTraps()
	return e
}

func (e *Engine) initDefaultTraps() {
	for i, path := range DefaultHoneypotPaths {
		e.traps = append(e.traps, Trap{
			ID:        fmt.Sprintf("hp-%03d", i+1),
			Type:      TrapHiddenEndpoint,
			Path:      path,
			Name:      fmt.Sprintf("Hidden endpoint: %s", path),
			Enabled:   true,
			AutoBlock: true,
			BlockDays: 30,
		})
	}
	// Honey cookie trap
	e.traps = append(e.traps, Trap{
		ID: "hp-cookie-001", Type: TrapHoneyCookie,
		Name: "Honey Cookie Tracker", Enabled: true, AutoBlock: true, BlockDays: 7,
	})
}

// ── Gin Middleware ─────────────────────────────────────────────────────────────

// Middleware intercepts requests to honeypot paths and triggers alerts
func (e *Engine) Middleware() gin.HandlerFunc {
	// Build a fast lookup map
	pathSet := make(map[string]bool)
	e.mu.RLock()
	for _, t := range e.traps {
		if t.Type == TrapHiddenEndpoint && t.Enabled && t.Path != "" {
			pathSet[t.Path] = true
		}
	}
	e.mu.RUnlock()

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		ip := c.ClientIP()

		// Check if path is a honeypot
		if pathSet[path] {
			e.trigger(c, TrapHiddenEndpoint, "hp-endpoint")
			e.blacklist(ip, 30)
			// Return convincing fake response to confuse attacker
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied",
				"code":  "FORBIDDEN",
			})
			c.Abort()
			return
		}

		// Check honey cookie
		if hc := c.Cookie("iwauth_v2"); hc != "" {
			e.trigger(c, TrapHoneyCookie, "hp-cookie-001")
			e.blacklist(ip, 7)
		}

		c.Next()
	}
}

// InjectDecoys adds hidden trap indicators into HTTP responses
func (e *Engine) InjectDecoys(c *gin.Context, responseBody string) string {
	ip := c.ClientIP()

	// Inject unique honeytoken URL (specific to this IP session)
	token := generateToken(ip)
	honeyURL := fmt.Sprintf("<!-- Debug endpoint: /api/debug/%s -->\n", token)
	e.registerHoneytoken(token, ip)

	// Inject fake honey cookie (only bots will use it)
	c.SetCookie("iwauth_v2", "debug-session-token", 3600, "/", "", false, false)

	// Inject hidden form honeypot field (anti-bot)
	hiddenField := `<input type="text" name="website" style="display:none" tabindex="-1" autocomplete="off"/>`

	return honeyURL + responseBody + "\n<!-- " + hiddenField + " -->"
}

func (e *Engine) registerHoneytoken(token, ip string) {
	if e.rdb != nil {
		e.rdb.Set(e.ctx, "ironwall:honeytoken:"+token, ip, 24*time.Hour)
	}
}

// CheckHoneytoken validates if a URL token is a deployed honeytoken
func (e *Engine) CheckHoneytoken(c *gin.Context, token string) {
	if e.rdb == nil { return }
	originalIP, err := e.rdb.Get(e.ctx, "ironwall:honeytoken:"+token).Result()
	if err != nil { return }

	// Someone is visiting our unique URL — definite attacker
	currentIP := c.ClientIP()
	e.trigger(c, TrapHoneytokenURL, "hp-token")
	e.blacklist(currentIP, 90) // 90 days for honeytoken visitors

	fmt.Printf("[honeypot] HONEYTOKEN TRIGGERED: token=%s original_ip=%s current_ip=%s\n",
		token, originalIP, currentIP)
}

// ── Trigger & Blacklist ────────────────────────────────────────────────────────

func (e *Engine) trigger(c *gin.Context, trapType TrapType, trapID string) {
	event := TriggerEvent{
		TrapID:    trapID,
		TrapType:  trapType,
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Path:      c.Request.URL.Path,
		Method:    c.Request.Method,
		Timestamp: time.Now().UTC(),
	}

	// Log to Redis
	if e.rdb != nil {
		data, _ := json.Marshal(event)
		e.rdb.LPush(e.ctx, "ironwall:honeypot:events", data)
		e.rdb.LTrim(e.ctx, "ironwall:honeypot:events", 0, 999) // keep last 1000
		e.rdb.Incr(e.ctx, fmt.Sprintf("ironwall:honeypot:hits:%s", trapID))
	}

	if e.onTrigger != nil {
		go e.onTrigger(event)
	}

	fmt.Printf("[honeypot] TRAP TRIGGERED: type=%s ip=%s path=%s ua=%s\n",
		trapType, event.IP, event.Path, event.UserAgent)
}

func (e *Engine) blacklist(ip string, days int) {
	if e.rdb == nil { return }
	key := "ironwall:blacklist:" + ip
	e.rdb.Set(e.ctx, key, "honeypot", time.Duration(days)*24*time.Hour)
	e.rdb.SAdd(e.ctx, "ironwall:honeypot:blacklisted", ip)
	fmt.Printf("[honeypot] BLACKLISTED: ip=%s duration=%dd\n", ip, days)
}

// IsBlacklisted checks if an IP is in the honeypot blacklist
func (e *Engine) IsBlacklisted(ip string) bool {
	if e.rdb == nil { return false }
	exists, _ := e.rdb.Exists(e.ctx, "ironwall:blacklist:"+ip).Result()
	return exists > 0
}

// GetStats returns honeypot statistics
func (e *Engine) GetStats() map[string]interface{} {
	stats := map[string]interface{}{"traps": len(e.traps)}
	if e.rdb != nil {
		total, _ := e.rdb.LLen(e.ctx, "ironwall:honeypot:events").Result()
		blacklisted, _ := e.rdb.SCard(e.ctx, "ironwall:honeypot:blacklisted").Result()
		stats["total_triggers"] = total
		stats["blacklisted_ips"] = blacklisted
	}
	return stats
}

func generateToken(seed string) string {
	h := fmt.Sprintf("%x", []byte(seed+fmt.Sprintf("%d", time.Now().UnixNano())))
	if len(h) > 16 { h = h[:16] }
	return h
}
