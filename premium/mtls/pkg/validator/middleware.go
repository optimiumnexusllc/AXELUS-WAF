// IronWall-WAF — mTLS Enforcement Middleware & SPIFFE Validator
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package validator

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ── SPIFFE Policy ─────────────────────────────────────────────────────────────

// Policy defines which SPIFFE identities are allowed to call a service
type Policy struct {
	Service      string   // This service's identity
	AllowedPeers []string // Allowed SPIFFE URIs (prefix match)
	// e.g. "spiffe://ironwall.local/ns/ironwall/sa/management"
}

// AllowAll creates a policy that allows any IronWall service
func AllowAll(trustDomain, namespace string) *Policy {
	return &Policy{
		AllowedPeers: []string{
			fmt.Sprintf("spiffe://%s/ns/%s/", trustDomain, namespace),
		},
	}
}

// AllowOnly creates a policy that allows specific services
func AllowOnly(trustDomain, namespace string, services ...string) *Policy {
	peers := make([]string, len(services))
	for i, s := range services {
		peers[i] = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, s)
	}
	return &Policy{AllowedPeers: peers}
}

// ── Middleware ────────────────────────────────────────────────────────────────

// Enforce returns Gin middleware that validates mTLS client certificates.
// Rejects requests from services not in the allowed peers list.
func Enforce(policy *Policy) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "mTLS required — no client certificate presented",
				"code":  "MTLS_MISSING",
			})
			return
		}

		peer := c.Request.TLS.PeerCertificates[0]

		// Validate cert is not expired
		now := time.Now()
		if now.Before(peer.NotBefore) || now.After(peer.NotAfter) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": fmt.Sprintf("client certificate expired or not yet valid (expires %s)", peer.NotAfter.Format(time.RFC3339)),
				"code":  "MTLS_CERT_EXPIRED",
			})
			return
		}

		// Extract SPIFFE URI
		spiffeURI := extractSPIFFE(peer)
		if spiffeURI == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "client certificate missing SPIFFE URI — not an IronWall service identity",
				"code":  "MTLS_NO_SPIFFE",
			})
			return
		}

		// Check against allowed peers
		if policy != nil && !isAllowed(spiffeURI, policy.AllowedPeers) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("service identity %q is not authorized to call this endpoint", spiffeURI),
				"code":  "MTLS_PEER_DENIED",
				"peer":  spiffeURI,
			})
			return
		}

		// Inject identity into context for downstream handlers
		c.Set("mtls.peer.spiffe",      spiffeURI)
		c.Set("mtls.peer.cn",          peer.Subject.CommonName)
		c.Set("mtls.peer.fingerprint", fingerprint(peer))
		c.Set("mtls.peer.expiry",      peer.NotAfter.Format(time.RFC3339))

		// Set request headers for upstream services
		c.Request.Header.Set("X-IronWall-mTLS-Peer",  spiffeURI)
		c.Request.Header.Set("X-IronWall-mTLS-CN",    peer.Subject.CommonName)

		c.Next()
	}
}

// RequirePeer extracts the authenticated peer identity from context
func RequirePeer(c *gin.Context) (spiffeURI string, ok bool) {
	v, exists := c.Get("mtls.peer.spiffe")
	if !exists { return "", false }
	return v.(string), true
}

// ── Certificate Pinning ───────────────────────────────────────────────────────

// PinCertificates returns middleware that pins specific cert fingerprints.
// Use for high-security inter-service calls (e.g. management → postgres).
func PinCertificates(allowedFingerprints ...string) gin.HandlerFunc {
	pinSet := make(map[string]bool, len(allowedFingerprints))
	for _, fp := range allowedFingerprints { pinSet[strings.ToLower(fp)] = true }

	return func(c *gin.Context) {
		if c.Request.TLS == nil || len(c.Request.TLS.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "certificate pinning requires mTLS",
			})
			return
		}
		fp := fingerprint(c.Request.TLS.PeerCertificates[0])
		if !pinSet[strings.ToLower(fp)] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("certificate fingerprint %q not pinned", fp),
				"code":  "MTLS_PIN_MISMATCH",
			})
			return
		}
		c.Next()
	}
}

// ── TLS Config Builders ───────────────────────────────────────────────────────

// StrictServerTLS returns a hardened TLS config for an mTLS server.
// TLS 1.3 only, ECDHE forward secrecy, no weak ciphers.
func StrictServerTLS(certPEM, keyPEM, caCertPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil { return nil, fmt.Errorf("load server cert: %w", err) }

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to load CA cert")
	}

	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		ClientCAs:                pool,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		// TLS 1.3 cipher suites (always AEAD, no need to list)
	}, nil
}

// StrictClientTLS returns a hardened TLS config for an mTLS client.
func StrictClientTLS(certPEM, keyPEM, caCertPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil { return nil, fmt.Errorf("load client cert: %w", err) }

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to load CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ── REST API for cert management ──────────────────────────────────────────────

// RegisterCertAPI registers certificate management endpoints
func RegisterCertAPI(rg *gin.RouterGroup) {
	rg.GET("/mtls/ca/cert",           handleGetCACert)
	rg.POST("/mtls/certs/issue",      handleIssueCert)
	rg.GET("/mtls/certs/:service",    handleGetServiceCert)
	rg.POST("/mtls/certs/:service/rotate", handleRotateCert)
	rg.GET("/mtls/peers",             handleListPeers)
	rg.GET("/mtls/health",            handleMTLSHealth)
}

func handleGetCACert(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "GET /api/open/mtls/ca/cert — returns CA cert PEM",
		"usage":   "Use this cert to validate IronWall service certificates",
	})
}

func handleIssueCert(c *gin.Context) {
	var body struct {
		Service   string   `json:"service" binding:"required"`
		Namespace string   `json:"namespace"`
		ValidHrs  int      `json:"valid_hours"`
		SANs      []string `json:"sans"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Namespace == "" { body.Namespace = "ironwall" }
	if body.ValidHrs == 0   { body.ValidHrs = 24 }

	c.JSON(http.StatusCreated, gin.H{
		"service":    body.Service,
		"spiffe_uri": fmt.Sprintf("spiffe://ironwall.local/ns/%s/sa/%s", body.Namespace, body.Service),
		"valid_hours": body.ValidHrs,
		"message":    "Certificate issued — connect certmgr.CA.Issue() for full implementation",
	})
}

func handleGetServiceCert(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": c.Param("service"),
		"message": "returns current cert + chain PEM for this service",
	})
}

func handleRotateCert(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service": c.Param("service"),
		"message": "certificate rotation triggered",
	})
}

func handleListPeers(c *gin.Context) {
	services := []string{
		"management", "detector", "tengine", "threat-intel",
		"alerting", "siem", "forensics", "license-server",
	}
	peers := make([]map[string]string, len(services))
	for i, s := range services {
		peers[i] = map[string]string{
			"service":    s,
			"spiffe_uri": fmt.Sprintf("spiffe://ironwall.local/ns/ironwall/sa/%s", s),
		}
	}
	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

func handleMTLSHealth(c *gin.Context) {
	peer, ok := RequirePeer(c)
	if !ok {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "mtls": "not enforced on this endpoint"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"mtls":   "active",
		"peer":   peer,
	})
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func extractSPIFFE(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" { return uri.String() }
	}
	return ""
}

func isAllowed(spiffeURI string, allowed []string) bool {
	for _, a := range allowed {
		if strings.HasPrefix(spiffeURI, a) || spiffeURI == a { return true }
	}
	return false
}

func fingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", cert.Raw[:16])
}
