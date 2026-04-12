// Package api exposes the IronWall License Management REST API.
// Secured with an admin API key. All sensitive endpoints require authentication.
package api

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/optimiumnexusllc/ironwall/licensing/pkg/keygen"
	lic "github.com/optimiumnexusllc/ironwall/licensing/pkg/license"
	"github.com/optimiumnexusllc/ironwall/licensing/pkg/store"
	"github.com/optimiumnexusllc/ironwall/licensing/pkg/validator"
)

type Server struct {
	store     *store.Store
	keyPair   *keygen.KeyPair
	validator *validator.Validator
	adminKey  string
}

func NewServer(st *store.Store, kp *keygen.KeyPair, v *validator.Validator) *Server {
	adminKey := os.Getenv("LICENSE_ADMIN_KEY")
	if adminKey == "" {
		adminKey = "CHANGE_ME_ADMIN_KEY"
	}
	return &Server{store: st, keyPair: kp, validator: v, adminKey: adminKey}
}

// Register sets up all routes on the given Gin engine
func (s *Server) Register(r *gin.Engine) {
	api := r.Group("/api/v1/licensing")

	// ── Public endpoints ───────────────────────────────────────────────────
	api.POST("/validate", s.validateLicense)
	api.GET("/health", s.health)

	// ── Admin endpoints (require X-Admin-Key header) ────────────────────────
	admin := api.Group("/admin")
	admin.Use(s.adminAuth())
	{
		// License management
		admin.POST("/licenses", s.issueLicense)
		admin.GET("/licenses", s.listLicenses)
		admin.GET("/licenses/:id", s.getLicense)
		admin.DELETE("/licenses/:id/revoke", s.revokeLicense)
		admin.GET("/licenses/:id/download", s.downloadLicense)
		admin.GET("/licenses/:id/events", s.getLicenseEvents)

		// Bulk operations
		admin.POST("/licenses/bulk", s.bulkIssueLicenses)

		// Key pair management
		admin.POST("/keypairs", s.generateKeyPair)
		admin.GET("/keypairs", s.listKeyPairs)

		// Stats
		admin.GET("/stats", s.getStats)
	}
}

// ── Middleware ─────────────────────────────────────────────────────────────────

func (s *Server) adminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-Admin-Key")
		if key == "" {
			key = c.Query("admin_key")
		}
		if key != s.adminKey {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or missing admin key",
			})
			return
		}
		c.Next()
	}
}

// ── Request/Response types ─────────────────────────────────────────────────────

type IssueLicenseRequest struct {
	Tier             lic.Tier      `json:"tier" binding:"required"`
	Licensee         string        `json:"licensee" binding:"required"`
	Email            string        `json:"email" binding:"required,email"`
	Domain           string        `json:"domain"`
	HardwareID       string        `json:"hardware_id"`
	ValidForDays     int           `json:"valid_for_days"` // 0 = lifetime
	ExtraFeatures    []lic.Feature `json:"extra_features"`
	DisabledFeatures []lic.Feature `json:"disabled_features"`
	CustomLimits     *lic.Limits   `json:"custom_limits"`
	Notes            string        `json:"notes"`
}

type LicenseResponse struct {
	ID            string        `json:"id"`
	Key           string        `json:"key"`
	Tier          lic.Tier      `json:"tier"`
	Licensee      string        `json:"licensee"`
	Email         string        `json:"email"`
	Domain        string        `json:"domain,omitempty"`
	IssuedAt      time.Time     `json:"issued_at"`
	ExpiresAt     *time.Time    `json:"expires_at,omitempty"`
	IsLifetime    bool          `json:"is_lifetime"`
	IsRevoked     bool          `json:"is_revoked"`
	DaysRemaining int           `json:"days_remaining"`
	Features      []lic.Feature `json:"features"`
	Limits        lic.Limits    `json:"limits"`
	Status        string        `json:"status"`
	LicenseFile   string        `json:"license_file,omitempty"` // PEM-encoded
}

type ValidateRequest struct {
	LicenseFile string      `json:"license_file"` // PEM content
	LicenseKey  string      `json:"license_key"`  // Human-readable key only
	Feature     lic.Feature `json:"feature"`      // Optional: check specific feature
}

// ── Handlers ───────────────────────────────────────────────────────────────────

// POST /api/v1/licensing/validate
// Public endpoint — validates a license and optionally checks feature access
func (s *Server) validateLicense(c *gin.Context) {
	var req ValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var l *lic.License
	var err error

	if req.LicenseFile != "" {
		l, err = validator.ParseLicenseFile(req.LicenseFile)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid license file: " + err.Error()})
			return
		}
	} else if req.LicenseKey != "" {
		record, err := s.store.GetByKey(req.LicenseKey)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "license key not found"})
			return
		}
		_ = record // parse from stored file
		c.JSON(http.StatusOK, gin.H{"message": "key found", "tier": record.Tier})
		return
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide license_file or license_key"})
		return
	}

	result := s.validator.Validate(l)

	resp := gin.H{
		"valid":          result.Valid,
		"tier":           l.Tier,
		"licensee":       l.Licensee,
		"days_remaining": result.DaysRemaining,
		"status":         validator.LicenseStatus(l),
		"errors":         result.Errors,
		"warnings":       result.Warnings,
	}

	if req.Feature != "" {
		hasFeature := l.HasFeature(req.Feature)
		resp["feature_requested"] = req.Feature
		resp["feature_available"] = hasFeature
		if !hasFeature {
			resp["upgrade_hint"] = fmt.Sprintf("Feature %q requires %s tier or higher", req.Feature, requiredTier(req.Feature))
		}
	}

	// Record check
	if result.Valid {
		s.store.RecordActivation(l.ID, c.ClientIP(), c.Request.UserAgent())
	}

	status := http.StatusOK
	if !result.Valid {
		status = http.StatusForbidden
	}
	c.JSON(status, resp)
}

// POST /api/v1/licensing/admin/licenses
func (s *Server) issueLicense(c *gin.Context) {
	var req IssueLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate tier
	if _, ok := lic.TierFeatures[req.Tier]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tier: " + string(req.Tier)})
		return
	}

	createdBy := c.GetHeader("X-Admin-User")
	if createdBy == "" {
		createdBy = "admin"
	}

	kgReq := keygen.LicenseRequest{
		Tier:             req.Tier,
		Licensee:         req.Licensee,
		Email:            req.Email,
		Domain:           req.Domain,
		HardwareID:       req.HardwareID,
		ValidForDays:     req.ValidForDays,
		ExtraFeatures:    req.ExtraFeatures,
		DisabledFeatures: req.DisabledFeatures,
		CustomLimits:     req.CustomLimits,
		Notes:            req.Notes,
		CreatedBy:        createdBy,
	}

	license, licenseFile, err := keygen.Issue(kgReq, s.keyPair)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "license generation failed: " + err.Error()})
		return
	}

	if err := s.store.SaveLicense(license, licenseFile); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "license save failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, buildLicenseResponse(license, licenseFile))
}

// GET /api/v1/licensing/admin/licenses
func (s *Server) listLicenses(c *gin.Context) {
	tier := c.Query("tier")
	showRevoked := c.Query("revoked") == "true"
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	records, total, err := s.store.ListAll(tier, showRevoked, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"pages":     (total + int64(pageSize) - 1) / int64(pageSize),
		"licenses":  records,
	})
}

// GET /api/v1/licensing/admin/licenses/:id
func (s *Server) getLicense(c *gin.Context) {
	id := c.Param("id")
	record, err := s.store.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "license not found"})
		return
	}
	c.JSON(http.StatusOK, record)
}

// DELETE /api/v1/licensing/admin/licenses/:id/revoke
func (s *Server) revokeLicense(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&body)

	revokedBy := c.GetHeader("X-Admin-User")
	if err := s.store.RevokeLicense(id, body.Reason, revokedBy); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "license revoked", "id": id})
}

// GET /api/v1/licensing/admin/licenses/:id/download
func (s *Server) downloadLicense(c *gin.Context) {
	id := c.Param("id")
	record, err := s.store.GetByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "license not found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=ironwall-%s.lic", record.Key))
	c.Header("Content-Type", "application/octet-stream")
	c.String(http.StatusOK, record.LicenseFileB64)
}

// GET /api/v1/licensing/admin/licenses/:id/events
func (s *Server) getLicenseEvents(c *gin.Context) {
	// Returns audit trail for this license
	c.JSON(http.StatusOK, gin.H{"message": "events endpoint — connect to store.GetEvents(id)"})
}

// POST /api/v1/licensing/admin/licenses/bulk
func (s *Server) bulkIssueLicenses(c *gin.Context) {
	var reqs []IssueLicenseRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(reqs) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "max 100 licenses per bulk request"})
		return
	}

	var results []LicenseResponse
	var errors []string
	createdBy := c.GetHeader("X-Admin-User")

	for _, req := range reqs {
		kgReq := keygen.LicenseRequest{
			Tier: req.Tier, Licensee: req.Licensee, Email: req.Email,
			Domain: req.Domain, ValidForDays: req.ValidForDays,
			Notes: req.Notes, CreatedBy: createdBy,
		}
		l, lf, err := keygen.Issue(kgReq, s.keyPair)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", req.Email, err))
			continue
		}
		s.store.SaveLicense(l, lf)
		results = append(results, buildLicenseResponse(l, ""))
	}

	c.JSON(http.StatusCreated, gin.H{
		"issued": len(results),
		"errors": errors,
		"licenses": results,
	})
}

// POST /api/v1/licensing/admin/keypairs
func (s *Server) generateKeyPair(c *gin.Context) {
	kp, err := keygen.GenerateKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Only return public key — never expose private key via API
	c.JSON(http.StatusCreated, gin.H{
		"id":         kp.ID,
		"public_key": kp.PublicKey,
		"created_at": kp.CreatedAt,
		"warning":    "Private key generated — store it securely. It will not be shown again.",
	})
}

// GET /api/v1/licensing/admin/keypairs
func (s *Server) listKeyPairs(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "key pair list endpoint"})
}

// GET /api/v1/licensing/admin/stats
func (s *Server) getStats(c *gin.Context) {
	stats := s.store.GetStats()
	c.JSON(http.StatusOK, stats)
}

// GET /api/v1/licensing/health
func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "IronWall License Server",
		"version": "1.0.0",
	})
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func buildLicenseResponse(l *lic.License, licFile string) LicenseResponse {
	features := lic.TierFeatures[l.Tier]
	for _, f := range l.ExtraFeatures {
		features = append(features, f)
	}
	var exp *time.Time
	if !l.IsLifetime && !l.ExpiresAt.IsZero() {
		exp = &l.ExpiresAt
	}
	return LicenseResponse{
		ID:            l.ID,
		Key:           l.Key,
		Tier:          l.Tier,
		Licensee:      l.Licensee,
		Email:         l.Email,
		Domain:        l.Domain,
		IssuedAt:      l.IssuedAt,
		ExpiresAt:     exp,
		IsLifetime:    l.IsLifetime,
		IsRevoked:     l.IsRevoked,
		DaysRemaining: l.DaysRemaining(),
		Features:      features,
		Limits:        l.GetLimits(),
		Status:        validator.LicenseStatus(l),
		LicenseFile:   licFile,
	}
}

func requiredTier(f lic.Feature) string {
	for _, tier := range []lic.Tier{
		lic.TierCommunity, lic.TierProfessional, lic.TierEnterprise, lic.TierUltimate,
	} {
		for _, tf := range lic.TierFeatures[tier] {
			if tf == f {
				return strings.Title(strings.ToLower(string(tier)))
			}
		}
	}
	return "Ultimate"
}
