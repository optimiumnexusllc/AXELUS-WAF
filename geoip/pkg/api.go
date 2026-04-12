// IronWall GeoIP API — Gin middleware and REST management endpoints
package geoip

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ── Middleware ────────────────────────────────────────────────────────────────

// Middleware returns a Gin middleware that enforces GeoIP rules on every request.
// Adds X-IronWall-Country, X-IronWall-Risk headers to proxied requests.
func (e *Engine) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := realIP(c)

		decision, err := e.Evaluate(ip)
		if err != nil || decision == nil {
			c.Next()
			return
		}

		// Set headers for upstream and logging
		if decision.Lookup != nil {
			c.Request.Header.Set("X-IronWall-Country", decision.Lookup.CountryCode)
			c.Request.Header.Set("X-IronWall-Risk", fmt.Sprintf("%d", decision.Lookup.RiskScore))
			c.Request.Header.Set("X-IronWall-ASN", decision.Lookup.ASNOrg)
		}

		switch decision.Action {
		case ActionBlock:
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Access denied",
				"reason":  "Your location is not permitted to access this resource.",
				"code":    "GEO_BLOCKED",
				"country": decision.Lookup.CountryCode,
			})
			return
		case ActionChallenge:
			// In production: redirect to CAPTCHA challenge page
			c.Header("X-IronWall-Challenge", "1")
			// Challenge handled by Tengine lua module — pass through with header
		}

		c.Next()
	}
}

// realIP extracts the true client IP, respecting trusted proxy headers
func realIP(c *gin.Context) string {
	// X-Forwarded-For (take the first, leftmost IP)
	if xfwd := c.GetHeader("X-Forwarded-For"); xfwd != "" {
		parts := strings.Split(xfwd, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	if xreal := c.GetHeader("X-Real-IP"); xreal != "" {
		return xreal
	}
	return c.ClientIP()
}

// ── REST API Handlers ─────────────────────────────────────────────────────────

// RegisterAPI registers GeoIP management endpoints on a Gin router group.
// All endpoints are secured with admin middleware (called before this).
func (e *Engine) RegisterAPI(rg *gin.RouterGroup) {
	rg.GET("/geoip/lookup/:ip", e.handleLookup)
	rg.POST("/geoip/evaluate", e.handleEvaluate)
	rg.GET("/geoip/rules", e.handleListRules)
	rg.POST("/geoip/rules", e.handleAddRule)
	rg.DELETE("/geoip/rules/:id", e.handleDeleteRule)
	rg.POST("/geoip/rules/bulk", e.handleBulkRules)
	rg.GET("/geoip/stats", e.handleStats)
	rg.POST("/geoip/database/update", e.handleUpdateDB)
	rg.GET("/geoip/defaults", e.handleGetDefaults)
}

// GET /api/open/geoip/lookup/:ip
func (e *Engine) handleLookup(c *gin.Context) {
	ip := c.Param("ip")
	lookup, err := e.Lookup(ip)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, lookup)
}

// POST /api/open/geoip/evaluate
func (e *Engine) handleEvaluate(c *gin.Context) {
	var body struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	decision, err := e.Evaluate(body.IP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, decision)
}

// GET /api/open/geoip/rules
func (e *Engine) handleListRules(c *gin.Context) {
	rules := e.GetRules()
	c.JSON(http.StatusOK, gin.H{
		"count": len(rules),
		"rules": rules,
	})
}

// POST /api/open/geoip/rules
func (e *Engine) handleAddRule(c *gin.Context) {
	var rule GeoRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if rule.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action is required (block|challenge|log|allow)"})
		return
	}
	rule.CreatedAt = time.Now().UTC()
	e.AddRule(rule)
	c.JSON(http.StatusCreated, rule)
}

// DELETE /api/open/geoip/rules/:id
func (e *Engine) handleDeleteRule(c *gin.Context) {
	id := c.Param("id")
	if e.RemoveRule(id) {
		c.JSON(http.StatusOK, gin.H{"message": "rule deleted", "id": id})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
	}
}

// POST /api/open/geoip/rules/bulk
func (e *Engine) handleBulkRules(c *gin.Context) {
	var body struct {
		Rules  []GeoRule `json:"rules"`
		Action Action    `json:"action"` // Override action for all
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	added := 0
	for _, r := range body.Rules {
		if body.Action != "" { r.Action = body.Action }
		r.CreatedAt = time.Now().UTC()
		e.AddRule(r)
		added++
	}
	c.JSON(http.StatusCreated, gin.H{"added": added})
}

// GET /api/open/geoip/stats
func (e *Engine) handleStats(c *gin.Context) {
	c.JSON(http.StatusOK, e.GetStats())
}

// POST /api/open/geoip/database/update
func (e *Engine) handleUpdateDB(c *gin.Context) {
	var body struct {
		AccountID  string `json:"account_id"`
		LicenseKey string `json:"license_key"`
		DestDir    string `json:"dest_dir"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	go func() {
		if err := UpdateDatabase(body.AccountID, body.LicenseKey, body.DestDir); err != nil {
			fmt.Printf("[geoip] DB update failed: %v\n", err)
		}
	}()
	c.JSON(http.StatusAccepted, gin.H{"message": "database update started in background"})
}

// GET /api/open/geoip/defaults
func (e *Engine) handleGetDefaults(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"default_block_rules": DefaultBlockRules(),
		"note": "These are recommended defaults. Enable/disable as needed for your use case.",
	})
}

// fmt import stub
import "fmt"
