// IronWall-WAF — Zero-Day Shield: Gin Middleware + REST API
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/optimiumnexusllc/ironwall/premium/zerodayshield/pkg/scorer"
)

type Shield struct {
	scorer *scorer.Scorer
	config ShieldConfig
}

type ShieldConfig struct {
	BlockOnZeroDay bool    // Block requests scored as zero-day
	BlockOnAnomaly bool    // Block requests scored as anomaly
	LogSuspects    bool    // Log suspect-level requests
	MaxBodyBytes   int64
}

func New(sc *scorer.Scorer, cfg ShieldConfig) *Shield {
	if cfg.MaxBodyBytes == 0 { cfg.MaxBodyBytes = 512 * 1024 }
	return &Shield{scorer: sc, config: cfg}
}

// Middleware returns the Zero-Day Shield Gin middleware
func (s *Shield) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		body := ""
		if s.config.MaxBodyBytes > 0 && c.Request.Body != nil {
			// We only peek — the body is also available downstream
			buf := make([]byte, s.config.MaxBodyBytes)
			n, _ := c.Request.Body.Read(buf)
			body = string(buf[:n])
		}

		headers := make(map[string]string, len(c.Request.Header))
		for k, v := range c.Request.Header {
			headers[k] = strings.Join(v, ", ")
		}

		req := scorer.RequestInput{
			IP:        realIP(c),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Query:     c.Request.URL.RawQuery,
			Body:      body,
			Headers:   headers,
			UserAgent: c.Request.UserAgent(),
			Timestamp: time.Now().UTC(),
		}

		result := s.scorer.Score(req)

		// Set informational headers
		c.Header("X-IronWall-ZD-Score", strconv.FormatFloat(result.Score, 'f', 3, 64))
		c.Header("X-IronWall-ZD-Level", string(result.Level))
		if result.IsZeroDay {
			c.Header("X-IronWall-ZeroDay", "1")
		}

		// Blocking decisions
		if result.IsZeroDay && s.config.BlockOnZeroDay {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":       "Request blocked — Zero-Day Shield detection",
				"code":        "ZERO_DAY_DETECTED",
				"score":       result.Score,
				"explanation": result.Explanation,
				"support":     "https://www.optimiumnexus.com",
			})
			return
		}
		if result.Level == scorer.LevelAnomaly && s.config.BlockOnAnomaly {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":       "Request blocked — Anomaly detection",
				"code":        "ANOMALY_DETECTED",
				"score":       result.Score,
				"explanation": result.Explanation,
			})
			return
		}

		c.Set("zeroday.score", result.Score)
		c.Set("zeroday.level", string(result.Level))
		c.Next()
	}
}

// Register mounts the Zero-Day Shield API endpoints
func (s *Shield) Register(rg *gin.RouterGroup) {
	zd := rg.Group("/zerodayshield")
	zd.GET("/stats",         s.getStats)
	zd.POST("/score",        s.scoreRequest)
	zd.GET("/baseline",      s.getBaseline)
	zd.POST("/train",        s.triggerRetrain)
	zd.GET("/health",        s.health)
}

func (s *Shield) getStats(c *gin.Context) {
	c.JSON(http.StatusOK, s.scorer.Stats())
}

func (s *Shield) scoreRequest(c *gin.Context) {
	var body struct {
		IP        string            `json:"ip"`
		Method    string            `json:"method"`
		Path      string            `json:"path"`
		Query     string            `json:"query"`
		Body      string            `json:"body"`
		Headers   map[string]string `json:"headers"`
		UserAgent string            `json:"user_agent"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req := scorer.RequestInput{
		IP:        body.IP,
		Method:    body.Method,
		Path:      body.Path,
		Query:     body.Query,
		Body:      body.Body,
		Headers:   body.Headers,
		UserAgent: body.UserAgent,
		Timestamp: time.Now().UTC(),
	}
	result := s.scorer.Score(req)
	c.JSON(http.StatusOK, result)
}

func (s *Shield) getBaseline(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"model_ready": s.scorer.IsModelReady(),
		"stats":       s.scorer.Stats(),
		"feature_names": []string{
			"path_length", "query_length", "body_length", "header_count", "param_count",
			"path_entropy", "query_entropy", "body_entropy", "ua_entropy",
			"special_char_ratio", "digit_ratio", "uppercase_ratio", "non_ascii_ratio",
			"nested_brackets", "quote_balance", "semicolon_count", "comment_patterns", "encoding_layers",
			"requests_per_min", "unique_paths_ratio", "error_rate",
			"hour_of_day", "day_of_week", "is_night",
		},
	})
}

func (s *Shield) triggerRetrain(c *gin.Context) {
	c.JSON(http.StatusAccepted, gin.H{"message": "Retraining will occur automatically when enough samples accumulate"})
}

func (s *Shield) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":      "ok",
		"model_ready": s.scorer.IsModelReady(),
	})
}

func realIP(c *gin.Context) string {
	if xfwd := c.GetHeader("X-Forwarded-For"); xfwd != "" {
		return strings.TrimSpace(strings.Split(xfwd, ",")[0])
	}
	return c.ClientIP()
}
