// IronWall-WAF — Traefik Middleware Plugin
// Integrates IronWall into Traefik v3 via the plugin system.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
//
// Install via traefik static config:
//   experimental:
//     plugins:
//       ironwall-waf:
//         moduleName: github.com/optimiumnexusllc/ironwall-traefik
//         version: v1.0.0
package ironwall_traefik

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	IronWallURL      string `json:"ironwallUrl"`
	AdminKey         string `json:"adminKey"`
	TimeoutMs        int    `json:"timeoutMs"`
	GeoIPEnabled     bool   `json:"geoipEnabled"`
	ThreatIntelEnabled bool `json:"threatIntelEnabled"`
	DPIEnabled       bool   `json:"dpiEnabled"`
	RateLimitEnabled bool   `json:"rateLimitEnabled"`
	HoneypotEnabled  bool   `json:"honeypotEnabled"`
	InspectBody      bool   `json:"inspectBody"`
	BlockStatus      int    `json:"blockStatus"`
	FailOpen         bool   `json:"failOpen"`
	MaxBodyBytes     int64  `json:"maxBodyBytes"`
}

func CreateConfig() *Config {
	return &Config{
		IronWallURL:      "https://ironwall-mgt:9443",
		TimeoutMs:        50,
		GeoIPEnabled:     true,
		ThreatIntelEnabled: true,
		DPIEnabled:       true,
		RateLimitEnabled: true,
		HoneypotEnabled:  false,
		InspectBody:      true,
		BlockStatus:      403,
		FailOpen:         true,
		MaxBodyBytes:     1 * 1024 * 1024, // 1MB
	}
}

// ── Middleware ────────────────────────────────────────────────────────────────

type IronWallMiddleware struct {
	next   http.Handler
	cfg    *Config
	client *http.Client
	name   string
}

func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if cfg.IronWallURL == "" {
		return nil, fmt.Errorf("ironwall-waf: ironwallUrl is required")
	}
	client := &http.Client{
		Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
		},
	}
	return &IronWallMiddleware{next: next, cfg: cfg, client: client, name: name}, nil
}

func (m *IronWallMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP := realIP(req)

	// ── 1. GeoIP ──────────────────────────────────────────────────────────────
	if m.cfg.GeoIPEnabled {
		result, err := m.post("/api/open/geoip/evaluate", map[string]string{"ip": clientIP})
		if err == nil && result != nil {
			if action, _ := result["action"].(string); action == "block" {
				reason, _ := result["reason"].(string)
				m.block(rw, req, "geoip", reason)
				return
			}
			if lookup, ok := result["lookup"].(map[string]interface{}); ok {
				if cc, ok := lookup["country_code"].(string); ok {
					req.Header.Set("X-IronWall-Country", cc)
				}
				if rs, ok := lookup["risk_score"].(float64); ok {
					req.Header.Set("X-IronWall-Risk-Score", fmt.Sprintf("%.0f", rs))
				}
			}
		} else if err != nil && !m.cfg.FailOpen {
			m.block(rw, req, "upstream_error", "IronWall-WAF unreachable")
			return
		}
	}

	// ── 2. Threat Intelligence ────────────────────────────────────────────────
	if m.cfg.ThreatIntelEnabled {
		result, err := m.post("/api/open/threat-intel/check", map[string]string{"ip": clientIP})
		if err == nil && result != nil {
			if blocked, _ := result["blocked"].(bool); blocked {
				m.block(rw, req, "threat_intel", "IP in threat intelligence feed")
				return
			}
		}
	}

	// ── 3. Rate Limiting ──────────────────────────────────────────────────────
	if m.cfg.RateLimitEnabled {
		result, err := m.post("/api/open/ratelimit/check", map[string]interface{}{
			"ip":     clientIP,
			"path":   req.URL.Path,
			"method": req.Method,
			"token":  req.Header.Get("Authorization"),
		})
		if err == nil && result != nil {
			if allowed, _ := result["allowed"].(bool); !allowed {
				if retryAfter, ok := result["retry_after"].(float64); ok {
					rw.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter))
				}
				if limit, ok := result["limit"].(float64); ok {
					rw.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.0f", limit))
				}
				rw.Header().Set("X-RateLimit-Remaining", "0")
				m.blockStatus(rw, req, 429, "rate_limit", "Rate limit exceeded")
				return
			}
		}
	}

	// ── 4. Deep Packet Inspection ─────────────────────────────────────────────
	if m.cfg.DPIEnabled && req.Body != nil &&
		(req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {

		var bodyBytes []byte
		if m.cfg.InspectBody {
			lr := io.LimitReader(req.Body, m.cfg.MaxBodyBytes)
			bodyBytes, _ = io.ReadAll(lr)
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		result, err := m.post("/api/open/inspect", map[string]interface{}{
			"ip":     clientIP,
			"method": req.Method,
			"path":   req.URL.Path,
			"query":  req.URL.RawQuery,
			"body":   string(bodyBytes),
			"headers": map[string]string{
				"user-agent":   req.Header.Get("User-Agent"),
				"content-type": req.Header.Get("Content-Type"),
				"referer":      req.Header.Get("Referer"),
			},
		})
		if err == nil && result != nil {
			if blocked, _ := result["blocked"].(bool); blocked {
				score := 0
				if s, ok := result["score"].(float64); ok { score = int(s) }
				m.block(rw, req, "dpi", fmt.Sprintf("Threat score: %d", score))
				return
			}
			if score, ok := result["score"].(float64); ok {
				req.Header.Set("X-IronWall-Threat-Score", fmt.Sprintf("%.0f", score))
			}
		}
	}

	// ── 5. Honeypot ───────────────────────────────────────────────────────────
	if m.cfg.HoneypotEnabled {
		result, err := m.post("/api/open/honeypot/check", map[string]string{"path": req.URL.Path})
		if err == nil && result != nil {
			if isTrap, _ := result["is_trap"].(bool); isTrap {
				m.block(rw, req, "honeypot", "Honeypot trap triggered")
				return
			}
		}
	}

	// All checks passed
	req.Header.Set("X-IronWall-Inspected", "1")
	req.Header.Set("X-IronWall-Version", "1.0.0")
	m.next.ServeHTTP(rw, req)
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func (m *IronWallMiddleware) post(path string, body interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(body)
	if err != nil { return nil, err }

	req, err := http.NewRequest("POST", m.cfg.IronWallURL+path, bytes.NewReader(data))
	if err != nil { return nil, err }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", m.cfg.AdminKey)

	resp, err := m.client.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { return nil, err }
	return result, nil
}

func (m *IronWallMiddleware) block(rw http.ResponseWriter, req *http.Request, code, reason string) {
	m.blockStatus(rw, req, m.cfg.BlockStatus, code, reason)
}

func (m *IronWallMiddleware) blockStatus(rw http.ResponseWriter, req *http.Request, status int, code, reason string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("X-IronWall-Blocked", "1")
	rw.Header().Set("X-IronWall-Block-Reason", code)
	rw.WriteHeader(status)

	resp := map[string]interface{}{
		"error":      "Request blocked by IronWall-WAF",
		"code":       "IRONWALL_BLOCKED",
		"reason":     code,
		"message":    reason,
		"request_id": req.Header.Get("X-Request-ID"),
		"support":    "https://www.optimiumnexus.com",
	}
	json.NewEncoder(rw).Encode(resp)
}

func realIP(req *http.Request) string {
	if xfwd := req.Header.Get("X-Forwarded-For"); xfwd != "" {
		parts := strings.Split(xfwd, ",")
		return strings.TrimSpace(parts[0])
	}
	if xreal := req.Header.Get("X-Real-IP"); xreal != "" { return xreal }
	host, _, _ := net.SplitHostPort(req.RemoteAddr)
	if host != "" { return host }
	return req.RemoteAddr
}
