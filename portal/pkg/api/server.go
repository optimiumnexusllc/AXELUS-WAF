// AXELUS-WAF — Customer License Portal Backend
// Self-service portal: register, manage licenses, billing, usage stats.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ── Models ────────────────────────────────────────────────────────────────────

type Customer struct {
	gorm.Model
	ID           string    `gorm:"primaryKey;type:uuid"`
	CompanyName  string    `gorm:"not null"`
	Email        string    `gorm:"uniqueIndex;not null"`
	PasswordHash string    `gorm:"not null"`
	Phone        string
	Country      string
	Website      string
	Plan         string    `gorm:"default:trial"`     // trial|pro|enterprise|ultimate
	Status       string    `gorm:"default:active"`    // active|suspended|cancelled
	EmailVerified bool     `gorm:"default:false"`
	MFAEnabled   bool     `gorm:"default:false"`
	MFASecret    string
	APIKey       string    `gorm:"uniqueIndex"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// Billing
	StripeCustomerID string
	StripeSubID      string
	BillingEmail     string
	// Limits
	MaxLicenses int `gorm:"default:1"`
}

type CustomerLicense struct {
	gorm.Model
	CustomerID  string    `gorm:"not null;index"`
	LicenseID   string    `gorm:"not null;uniqueIndex"`
	LicenseKey  string    `gorm:"not null;uniqueIndex"`
	Tier        string    `gorm:"not null"`
	Domain      string
	IssuedAt    time.Time
	ExpiresAt   *time.Time
	IsLifetime  bool
	IsRevoked   bool
	RevokedAt   *time.Time
	RevokeReason string
	LicenseFile  string  `gorm:"type:text"`
	Notes        string
	// Usage
	ActivationCount int
	LastActivated   *time.Time
	LastSeenIP      string
}

type UsageRecord struct {
	gorm.Model
	CustomerID string    `gorm:"not null;index"`
	LicenseKey string    `gorm:"not null;index"`
	Date       time.Time `gorm:"not null;index"`
	Requests   int64
	Blocked    int64
	Bandwidth  int64  // bytes
	Countries  string // JSON
}

type SupportTicket struct {
	gorm.Model
	CustomerID  string `gorm:"not null;index"`
	Subject     string `gorm:"not null"`
	Body        string `gorm:"type:text"`
	Priority    string `gorm:"default:normal"` // low|normal|high|critical
	Status      string `gorm:"default:open"`   // open|in_progress|resolved|closed
	AssignedTo  string
	ResolvedAt  *time.Time
}

type Invoice struct {
	gorm.Model
	CustomerID  string    `gorm:"not null;index"`
	Number      string    `gorm:"uniqueIndex"`
	Amount      int64     // cents
	Currency    string    `gorm:"default:USD"`
	Status      string    `gorm:"default:unpaid"` // unpaid|paid|void
	PeriodStart time.Time
	PeriodEnd   time.Time
	PaidAt      *time.Time
	PDFURL      string
}

// ── JWT Claims ────────────────────────────────────────────────────────────────

type Claims struct {
	CustomerID  string `json:"cid"`
	Email       string `json:"email"`
	Plan        string `json:"plan"`
	jwt.RegisteredClaims
}

// ── Portal Server ─────────────────────────────────────────────────────────────

type PortalServer struct {
	db        *gorm.DB
	jwtSecret []byte
	licenseAPIURL  string
	licenseAdminKey string
}

func NewPortalServer(db *gorm.DB, jwtSecret, licenseAPIURL, licenseAdminKey string) *PortalServer {
	db.AutoMigrate(&Customer{}, &CustomerLicense{}, &UsageRecord{}, &SupportTicket{}, &Invoice{})
	return &PortalServer{
		db:              db,
		jwtSecret:       []byte(jwtSecret),
		licenseAPIURL:   licenseAPIURL,
		licenseAdminKey: licenseAdminKey,
	}
}

func (ps *PortalServer) Register(r *gin.Engine) {
	// Public routes
	pub := r.Group("/portal/api/v1")
	pub.POST("/auth/register", ps.register)
	pub.POST("/auth/login",    ps.login)
	pub.POST("/auth/refresh",  ps.refresh)
	pub.GET("/plans",          ps.listPlans)

	// Authenticated routes
	auth := r.Group("/portal/api/v1")
	auth.Use(ps.authMiddleware())
	{
		// Account
		auth.GET("/account",          ps.getAccount)
		auth.PUT("/account",          ps.updateAccount)
		auth.PUT("/account/password", ps.changePassword)
		auth.POST("/account/mfa",     ps.enableMFA)
		auth.GET("/account/api-key",  ps.getAPIKey)
		auth.POST("/account/api-key/rotate", ps.rotateAPIKey)

		// Licenses
		auth.GET("/licenses",           ps.listLicenses)
		auth.POST("/licenses",          ps.requestLicense)
		auth.GET("/licenses/:key",      ps.getLicense)
		auth.GET("/licenses/:key/download", ps.downloadLicense)
		auth.PUT("/licenses/:key/domain", ps.updateLicenseDomain)
		auth.POST("/licenses/:key/renew", ps.renewLicense)
		auth.DELETE("/licenses/:key",    ps.revokeSelfLicense)

		// Usage & Analytics
		auth.GET("/usage",             ps.getUsage)
		auth.GET("/usage/daily",       ps.getDailyUsage)
		auth.GET("/usage/summary",     ps.getUsageSummary)

		// Billing
		auth.GET("/billing/invoices",          ps.listInvoices)
		auth.GET("/billing/invoices/:id",      ps.getInvoice)
		auth.GET("/billing/invoices/:id/pdf",  ps.downloadInvoice)
		auth.GET("/billing/subscription",      ps.getSubscription)
		auth.POST("/billing/portal",           ps.billingPortal)
		auth.POST("/billing/upgrade",          ps.requestUpgrade)

		// Support
		auth.GET("/support/tickets",           ps.listTickets)
		auth.POST("/support/tickets",          ps.createTicket)
		auth.GET("/support/tickets/:id",       ps.getTicket)
		auth.POST("/support/tickets/:id/reply", ps.replyTicket)
		auth.POST("/support/tickets/:id/close", ps.closeTicket)

		// Notifications
		auth.GET("/notifications",     ps.getNotifications)
	}

	// Serve the portal SPA
	r.Static("/portal/assets", "./portal/web/dist/assets")
	r.StaticFile("/portal", "./portal/web/dist/index.html")
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/portal") {
			c.File("./portal/web/dist/index.html")
		}
	})
}

// ── Auth Handlers ──────────────────────────────────────────────────────────────

func (ps *PortalServer) register(c *gin.Context) {
	var body struct {
		CompanyName string `json:"company_name" binding:"required"`
		Email       string `json:"email"        binding:"required,email"`
		Password    string `json:"password"     binding:"required,min=8"`
		Country     string `json:"country"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if email already exists
	var existing Customer
	if ps.db.Where("email = ?", body.Email).First(&existing).Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already registered"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	apiKey, _ := generateToken(32)
	custID, _ := generateToken(16)

	customer := Customer{
		ID:           custID,
		CompanyName:  body.CompanyName,
		Email:        strings.ToLower(body.Email),
		PasswordHash: string(hash),
		Country:      body.Country,
		Plan:         "trial",
		Status:       "active",
		APIKey:       apiKey,
		MaxLicenses:  1,
	}

	if err := ps.db.Create(&customer).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed"})
		return
	}

	// Auto-issue a trial license
	go ps.issueLicenseForCustomer(customer.ID, "TRIAL", 30, "Auto-issued trial")

	token, _ := ps.generateJWT(customer)
	c.JSON(http.StatusCreated, gin.H{
		"message":    "Welcome to AXELUS-WAF! A 30-day trial license has been issued.",
		"token":      token,
		"customer":   sanitiseCustomer(customer),
		"next_steps": []string{
			"Check your email for verification link",
			"Download your trial license from /portal/licenses",
			"Follow the quick-start guide at https://www.optimiumnexus.com/docs",
		},
	})
}

func (ps *PortalServer) login(c *gin.Context) {
	var body struct {
		Email    string `json:"email"    binding:"required,email"`
		Password string `json:"password" binding:"required"`
		MFACode  string `json:"mfa_code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var customer Customer
	if err := ps.db.Where("email = ?", strings.ToLower(body.Email)).First(&customer).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if customer.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is " + customer.Status})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(customer.PasswordHash), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, _ := ps.generateJWT(customer)
	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"customer": sanitiseCustomer(customer),
	})
}

func (ps *PortalServer) refresh(c *gin.Context) {
	// Token refresh — extract claims and issue new token
	token := extractBearerToken(c)
	claims, err := ps.validateJWT(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	var customer Customer
	if err := ps.db.First(&customer, "id = ?", claims.CustomerID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Customer not found"})
		return
	}
	newToken, _ := ps.generateJWT(customer)
	c.JSON(http.StatusOK, gin.H{"token": newToken})
}

// ── License Handlers ───────────────────────────────────────────────────────────

func (ps *PortalServer) listLicenses(c *gin.Context) {
	custID := c.GetString("customer_id")
	var licenses []CustomerLicense
	ps.db.Where("customer_id = ?", custID).Order("created_at desc").Find(&licenses)
	c.JSON(http.StatusOK, gin.H{"count": len(licenses), "licenses": licenses})
}

func (ps *PortalServer) requestLicense(c *gin.Context) {
	var body struct {
		Tier         string `json:"tier"         binding:"required"`
		Domain       string `json:"domain"`
		ValidForDays int    `json:"valid_for_days"`
		Notes        string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	custID := c.GetString("customer_id")
	var customer Customer
	if err := ps.db.First(&customer, "id = ?", custID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Customer not found"})
		return
	}

	// Check license quota
	var count int64
	ps.db.Model(&CustomerLicense{}).Where("customer_id = ? AND is_revoked = false", custID).Count(&count)
	if int(count) >= customer.MaxLicenses {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   fmt.Sprintf("License quota reached (%d/%d). Upgrade your plan to issue more.", count, customer.MaxLicenses),
			"upgrade": "/portal/billing/upgrade",
		})
		return
	}

	// Validate tier vs plan
	if !ps.tierAllowedForPlan(body.Tier, customer.Plan) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   fmt.Sprintf("Tier %q is not available on your %q plan", body.Tier, customer.Plan),
			"upgrade": "/portal/billing/upgrade",
		})
		return
	}

	lic, err := ps.issueLicenseForCustomer(custID, body.Tier, body.ValidForDays, body.Notes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "License issuance failed: " + err.Error()})
		return
	}

	if body.Domain != "" {
		ps.db.Model(lic).Update("domain", body.Domain)
	}

	c.JSON(http.StatusCreated, gin.H{
		"license": lic,
		"message": fmt.Sprintf("License %s issued successfully", lic.LicenseKey),
	})
}

func (ps *PortalServer) getLicense(c *gin.Context) {
	custID := c.GetString("customer_id")
	var lic CustomerLicense
	if err := ps.db.Where("license_key = ? AND customer_id = ?", c.Param("key"), custID).First(&lic).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "License not found"})
		return
	}
	c.JSON(http.StatusOK, lic)
}

func (ps *PortalServer) downloadLicense(c *gin.Context) {
	custID := c.GetString("customer_id")
	var lic CustomerLicense
	if err := ps.db.Where("license_key = ? AND customer_id = ?", c.Param("key"), custID).First(&lic).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "License not found"})
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.lic", lic.LicenseKey))
	c.Header("Content-Type", "application/octet-stream")
	c.String(http.StatusOK, lic.LicenseFile)
}

func (ps *PortalServer) renewLicense(c *gin.Context) {
	var body struct { Days int `json:"days" binding:"required,min=1"` }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"message": fmt.Sprintf("Renewal of %d days submitted — contact contact@optimiumnexus.com", body.Days),
	})
}

func (ps *PortalServer) revokeSelfLicense(c *gin.Context) {
	custID := c.GetString("customer_id")
	now := time.Now()
	result := ps.db.Model(&CustomerLicense{}).
		Where("license_key = ? AND customer_id = ? AND is_revoked = false", c.Param("key"), custID).
		Updates(map[string]interface{}{
			"is_revoked": true, "revoked_at": now, "revoke_reason": "Self-revoked by customer",
		})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "License not found or already revoked"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "License revoked"})
}

func (ps *PortalServer) updateLicenseDomain(c *gin.Context) {
	var body struct { Domain string `json:"domain"` }
	c.ShouldBindJSON(&body)
	custID := c.GetString("customer_id")
	ps.db.Model(&CustomerLicense{}).
		Where("license_key = ? AND customer_id = ?", c.Param("key"), custID).
		Update("domain", body.Domain)
	c.JSON(http.StatusOK, gin.H{"domain": body.Domain})
}

// ── Usage Handlers ─────────────────────────────────────────────────────────────

func (ps *PortalServer) getUsage(c *gin.Context) {
	custID := c.GetString("customer_id")
	var records []UsageRecord
	ps.db.Where("customer_id = ?", custID).
		Order("date desc").Limit(90).Find(&records)
	c.JSON(http.StatusOK, gin.H{"count": len(records), "records": records})
}

func (ps *PortalServer) getDailyUsage(c *gin.Context) {
	custID := c.GetString("customer_id")
	var records []UsageRecord
	ps.db.Where("customer_id = ? AND date >= ?", custID, time.Now().AddDate(0, 0, -30)).
		Order("date asc").Find(&records)
	c.JSON(http.StatusOK, gin.H{"records": records})
}

func (ps *PortalServer) getUsageSummary(c *gin.Context) {
	custID := c.GetString("customer_id")
	var totalReqs, totalBlocked, totalBW int64
	ps.db.Model(&UsageRecord{}).
		Where("customer_id = ? AND date >= ?", custID, time.Now().AddDate(0, -1, 0)).
		Select("COALESCE(SUM(requests),0)").Scan(&totalReqs)
	ps.db.Model(&UsageRecord{}).
		Where("customer_id = ? AND date >= ?", custID, time.Now().AddDate(0, -1, 0)).
		Select("COALESCE(SUM(blocked),0)").Scan(&totalBlocked)
	ps.db.Model(&UsageRecord{}).
		Where("customer_id = ? AND date >= ?", custID, time.Now().AddDate(0, -1, 0)).
		Select("COALESCE(SUM(bandwidth),0)").Scan(&totalBW)

	c.JSON(http.StatusOK, gin.H{
		"period":        "last_30_days",
		"total_requests": totalReqs,
		"blocked":        totalBlocked,
		"block_rate_pct": func() float64 {
			if totalReqs == 0 { return 0 }
			return float64(totalBlocked) / float64(totalReqs) * 100
		}(),
		"bandwidth_bytes": totalBW,
	})
}

// ── Billing Handlers ───────────────────────────────────────────────────────────

func (ps *PortalServer) listPlans(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"plans": []map[string]interface{}{
			{"id": "trial",      "name": "Trial",       "price_usd": 0,    "duration": "30 days", "licenses": 1,  "tier": "TRIAL"},
			{"id": "pro",        "name": "Professional", "price_usd": 299,  "duration": "year",    "licenses": 10, "tier": "PROFESSIONAL"},
			{"id": "enterprise", "name": "Enterprise",   "price_usd": 1499, "duration": "year",    "licenses": 50, "tier": "ENTERPRISE"},
			{"id": "ultimate",   "name": "Ultimate",     "price_usd": 4999, "duration": "year",    "licenses": -1, "tier": "ULTIMATE",
				"features": []string{"All Enterprise features", "Forensics + PCAP", "Zero-Day Shield",
					"DDoS Mitigation", "Deception Layer", "24/7 Dedicated Support", "Custom integrations"}},
		},
	})
}

func (ps *PortalServer) listInvoices(c *gin.Context) {
	custID := c.GetString("customer_id")
	var invoices []Invoice
	ps.db.Where("customer_id = ?", custID).Order("created_at desc").Find(&invoices)
	c.JSON(http.StatusOK, gin.H{"count": len(invoices), "invoices": invoices})
}
func (ps *PortalServer) getInvoice(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Invoice details endpoint"})
}
func (ps *PortalServer) downloadInvoice(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Invoice PDF download endpoint"})
}
func (ps *PortalServer) getSubscription(c *gin.Context) {
	custID := c.GetString("customer_id")
	var customer Customer
	ps.db.First(&customer, "id = ?", custID)
	c.JSON(http.StatusOK, gin.H{
		"plan":         customer.Plan,
		"status":       customer.Status,
		"max_licenses": customer.MaxLicenses,
	})
}
func (ps *PortalServer) billingPortal(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"redirect_url": "https://billing.stripe.com/session/xxx", "message": "Stripe billing portal"})
}
func (ps *PortalServer) requestUpgrade(c *gin.Context) {
	var body struct { Plan string `json:"plan" binding:"required"` }
	c.ShouldBindJSON(&body)
	c.JSON(http.StatusOK, gin.H{
		"message":     fmt.Sprintf("Upgrade to %q requested", body.Plan),
		"contact":     "contact@optimiumnexus.com",
		"website":     "https://www.optimiumnexus.com/upgrade",
	})
}

// ── Support Handlers ───────────────────────────────────────────────────────────

func (ps *PortalServer) listTickets(c *gin.Context) {
	custID := c.GetString("customer_id")
	var tickets []SupportTicket
	ps.db.Where("customer_id = ?", custID).Order("created_at desc").Find(&tickets)
	c.JSON(http.StatusOK, gin.H{"count": len(tickets), "tickets": tickets})
}

func (ps *PortalServer) createTicket(c *gin.Context) {
	var body struct {
		Subject  string `json:"subject"  binding:"required"`
		Body     string `json:"body"     binding:"required"`
		Priority string `json:"priority"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Priority == "" { body.Priority = "normal" }
	custID := c.GetString("customer_id")
	ticket := SupportTicket{
		CustomerID: custID,
		Subject:    body.Subject,
		Body:       body.Body,
		Priority:   body.Priority,
		Status:     "open",
	}
	ps.db.Create(&ticket)
	c.JSON(http.StatusCreated, gin.H{"ticket": ticket, "message": "Ticket created — we'll respond within 24h"})
}

func (ps *PortalServer) getTicket(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Ticket detail endpoint"})
}
func (ps *PortalServer) replyTicket(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Reply submitted"})
}
func (ps *PortalServer) closeTicket(c *gin.Context) {
	now := time.Now()
	ps.db.Model(&SupportTicket{}).Where("id = ?", c.Param("id")).
		Updates(map[string]interface{}{"status": "closed", "resolved_at": now})
	c.JSON(http.StatusOK, gin.H{"message": "Ticket closed"})
}

func (ps *PortalServer) getNotifications(c *gin.Context) {
	custID := c.GetString("customer_id")
	var licenses []CustomerLicense
	ps.db.Where("customer_id = ? AND is_revoked = false AND is_lifetime = false AND expires_at > ?",
		custID, time.Now()).Find(&licenses)

	var notifs []map[string]interface{}
	for _, l := range licenses {
		if l.ExpiresAt != nil && time.Until(*l.ExpiresAt) < 30*24*time.Hour {
			days := int(time.Until(*l.ExpiresAt).Hours() / 24)
			notifs = append(notifs, map[string]interface{}{
				"type":    "license_expiring",
				"title":   fmt.Sprintf("License %s expires in %d days", l.LicenseKey, days),
				"action":  "/portal/licenses/" + l.LicenseKey + "/renew",
				"urgent":  days <= 7,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"count": len(notifs), "notifications": notifs})
}

func (ps *PortalServer) getAccount(c *gin.Context) {
	custID := c.GetString("customer_id")
	var customer Customer
	if err := ps.db.First(&customer, "id = ?", custID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}
	c.JSON(http.StatusOK, sanitiseCustomer(customer))
}

func (ps *PortalServer) updateAccount(c *gin.Context) {
	var body struct {
		CompanyName string `json:"company_name"`
		Phone       string `json:"phone"`
		Website     string `json:"website"`
		Country     string `json:"country"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	custID := c.GetString("customer_id")
	ps.db.Model(&Customer{}).Where("id = ?", custID).Updates(map[string]interface{}{
		"company_name": body.CompanyName,
		"phone":        body.Phone,
		"website":      body.Website,
		"country":      body.Country,
	})
	c.JSON(http.StatusOK, gin.H{"message": "Account updated"})
}

func (ps *PortalServer) changePassword(c *gin.Context) {
	var body struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password"     binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	custID := c.GetString("customer_id")
	var customer Customer
	ps.db.First(&customer, "id = ?", custID)
	if err := bcrypt.CompareHashAndPassword([]byte(customer.PasswordHash), []byte(body.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	ps.db.Model(&Customer{}).Where("id = ?", custID).Update("password_hash", string(hash))
	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

func (ps *PortalServer) enableMFA(c *gin.Context)     { c.JSON(http.StatusOK, gin.H{"message": "MFA setup endpoint"}) }
func (ps *PortalServer) getAPIKey(c *gin.Context) {
	custID := c.GetString("customer_id")
	var customer Customer
	ps.db.First(&customer, "id = ?", custID)
	c.JSON(http.StatusOK, gin.H{"api_key": customer.APIKey})
}
func (ps *PortalServer) rotateAPIKey(c *gin.Context) {
	custID := c.GetString("customer_id")
	newKey, _ := generateToken(32)
	ps.db.Model(&Customer{}).Where("id = ?", custID).Update("api_key", newKey)
	c.JSON(http.StatusOK, gin.H{"api_key": newKey, "message": "API key rotated — update your integrations"})
}

// ── Middleware ─────────────────────────────────────────────────────────────────

func (ps *PortalServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearerToken(c)
		if token == "" {
			// Try API key auth
			apiKey := c.GetHeader("X-API-Key")
			if apiKey != "" {
				var customer Customer
				if err := ps.db.Where("api_key = ? AND status = 'active'", apiKey).First(&customer).Error; err == nil {
					c.Set("customer_id", customer.ID)
					c.Set("customer_plan", customer.Plan)
					c.Next()
					return
				}
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			return
		}

		claims, err := ps.validateJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		c.Set("customer_id", claims.CustomerID)
		c.Set("customer_plan", claims.Plan)
		c.Next()
	}
}

// ── JWT Helpers ───────────────────────────────────────────────────────────────

func (ps *PortalServer) generateJWT(c Customer) (string, error) {
	claims := Claims{
		CustomerID: c.ID,
		Email:      c.Email,
		Plan:       c.Plan,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "axelus-portal",
			Subject:   c.ID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(ps.jwtSecret)
}

func (ps *PortalServer) validateJWT(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return ps.jwtSecret, nil
	})
	if err != nil { return nil, err }
	if claims, ok := token.Claims.(*Claims); ok && token.Valid { return claims, nil }
	return nil, fmt.Errorf("invalid token")
}

// ── Internal Helpers ──────────────────────────────────────────────────────────

func (ps *PortalServer) issueLicenseForCustomer(custID, tier string, days int, notes string) (*CustomerLicense, error) {
	licID, _ := generateToken(16)
	licKey   := generateLicenseKey(tier)
	now      := time.Now().UTC()
	var expiresAt *time.Time
	isLifetime := days == 0
	if !isLifetime {
		exp := now.AddDate(0, 0, days)
		expiresAt = &exp
	}

	// Minimal license file (in prod: call the License Server API)
	licFile := fmt.Sprintf("-----BEGIN IRONWALL LICENSE-----\n%s\n-----END IRONWALL LICENSE-----",
		fmt.Sprintf("IW-PORTAL-ISSUED:id=%s:tier=%s:key=%s:customer=%s:issued=%s",
			licID, tier, licKey, custID, now.Format(time.RFC3339)))

	lic := CustomerLicense{
		CustomerID:  custID,
		LicenseID:   licID,
		LicenseKey:  licKey,
		Tier:        tier,
		IssuedAt:    now,
		ExpiresAt:   expiresAt,
		IsLifetime:  isLifetime,
		LicenseFile: licFile,
		Notes:       notes,
	}
	if err := ps.db.Create(&lic).Error; err != nil {
		return nil, err
	}
	return &lic, nil
}

func (ps *PortalServer) tierAllowedForPlan(tier, plan string) bool {
	allowed := map[string][]string{
		"trial":      {"TRIAL", "COMMUNITY"},
		"pro":        {"TRIAL", "COMMUNITY", "PROFESSIONAL"},
		"enterprise": {"TRIAL", "COMMUNITY", "PROFESSIONAL", "ENTERPRISE"},
		"ultimate":   {"TRIAL", "COMMUNITY", "PROFESSIONAL", "ENTERPRISE", "ULTIMATE"},
	}
	for _, t := range allowed[plan] { if t == tier { return true } }
	return false
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func generateLicenseKey(tier string) string {
	prefixes := map[string]string{
		"COMMUNITY": "COM", "PROFESSIONAL": "PRO", "ENTERPRISE": "ENT",
		"ULTIMATE": "ULT", "TRIAL": "TRL", "DEVELOPER": "DEV",
	}
	prefix := prefixes[tier]
	if prefix == "" { prefix = "UNK" }
	seg := func() string {
		b := make([]byte, 2); rand.Read(b)
		return strings.ToUpper(hex.EncodeToString(b))[:4]
	}
	return fmt.Sprintf("IW-%s-%s-%s-%s-%s", prefix, seg(), seg(), seg(), seg())
}

func sanitiseCustomer(c Customer) map[string]interface{} {
	return map[string]interface{}{
		"id":            c.ID,
		"company_name":  c.CompanyName,
		"email":         c.Email,
		"country":       c.Country,
		"plan":          c.Plan,
		"status":        c.Status,
		"max_licenses":  c.MaxLicenses,
		"email_verified": c.EmailVerified,
		"mfa_enabled":   c.MFAEnabled,
		"created_at":    c.CreatedAt,
	}
}

func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") { return auth[7:] }
	return ""
}

var _ = context.Background
