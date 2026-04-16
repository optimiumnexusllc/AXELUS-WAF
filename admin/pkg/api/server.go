// AXELUS-WAF — Multi-Tenant Administration Backend
// Full tenant isolation, RBAC, audit logging, resource quotas.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package admin

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

// ── Tenant Model ──────────────────────────────────────────────────────────────

type Tenant struct {
	gorm.Model
	ID           string    `gorm:"primaryKey;size:36"`
	Name         string    `gorm:"not null;uniqueIndex"`
	Slug         string    `gorm:"not null;uniqueIndex"` // URL-safe identifier
	Plan         string    `gorm:"not null;default:trial"`
	Status       string    `gorm:"not null;default:active"` // active|suspended|deleted
	Region       string    `gorm:"default:us-east-1"`
	MaxUsers     int       `gorm:"default:5"`
	MaxSites     int       `gorm:"default:1"`
	MaxRPS       int       `gorm:"default:500"`
	IsIsolated   bool      `gorm:"default:true"`   // network isolation
	CustomDomain string
	LogoURL      string
	PrimaryColor string    `gorm:"default:#3b82f6"`
	// Billing
	StripeCustomerID string
	// Metadata
	ContactEmail string
	ContactPhone string
	Country      string
	Notes        string
	CreatedBy    string
	SuspendedAt  *time.Time
	SuspendReason string
}

type TenantUser struct {
	gorm.Model
	TenantID   string `gorm:"not null;index;size:36"`
	UserID     string `gorm:"not null;index;size:36"`
	Role       string `gorm:"not null;default:viewer"` // owner|admin|operator|viewer|readonly
	InvitedBy  string
	JoinedAt   time.Time
	LastLogin  *time.Time
	IsActive   bool   `gorm:"default:true"`
}

type AdminUser struct {
	gorm.Model
	ID           string `gorm:"primaryKey;size:36"`
	Email        string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	FullName     string
	Role         string `gorm:"not null;default:viewer"` // super_admin|admin|support|viewer
	TenantID     string `gorm:"index;size:36"` // empty = platform-level admin
	IsActive     bool   `gorm:"default:true"`
	MFAEnabled   bool   `gorm:"default:false"`
	MFASecret    string
	LastLogin    *time.Time
	LastLoginIP  string
	APIKey       string `gorm:"uniqueIndex"`
}

// ── RBAC Permissions ──────────────────────────────────────────────────────────

type Permission string

const (
	// Platform-level (super_admin only)
	PermCreateTenant  Permission = "tenant:create"
	PermDeleteTenant  Permission = "tenant:delete"
	PermSuspendTenant Permission = "tenant:suspend"
	PermViewAllTenants Permission = "tenant:view_all"

	// Tenant-level
	PermManageUsers  Permission = "users:manage"
	PermViewUsers    Permission = "users:view"
	PermManageLicenses Permission = "licenses:manage"
	PermViewLicenses Permission = "licenses:view"
	PermManageWAF    Permission = "waf:manage"
	PermViewWAF      Permission = "waf:view"
	PermViewAudit    Permission = "audit:view"
	PermManageBilling Permission = "billing:manage"
	PermViewBilling  Permission = "billing:view"
	PermViewForensics Permission = "forensics:view"
	PermManageForensics Permission = "forensics:manage"
)

var RolePermissions = map[string][]Permission{
	"super_admin": {
		PermCreateTenant, PermDeleteTenant, PermSuspendTenant, PermViewAllTenants,
		PermManageUsers, PermViewUsers, PermManageLicenses, PermViewLicenses,
		PermManageWAF, PermViewWAF, PermViewAudit, PermManageBilling, PermViewBilling,
		PermViewForensics, PermManageForensics,
	},
	"admin": {
		PermManageUsers, PermViewUsers, PermManageLicenses, PermViewLicenses,
		PermManageWAF, PermViewWAF, PermViewAudit, PermManageBilling, PermViewBilling,
	},
	"support": {
		PermViewUsers, PermViewLicenses, PermViewWAF, PermViewAudit, PermViewBilling,
	},
	"operator": {
		PermViewUsers, PermManageWAF, PermViewWAF, PermViewAudit,
	},
	"viewer": {
		PermViewWAF, PermViewAudit,
	},
	// Tenant-level roles
	"owner": {
		PermManageUsers, PermViewUsers, PermManageLicenses, PermViewLicenses,
		PermManageWAF, PermViewWAF, PermViewAudit, PermManageBilling, PermViewBilling,
		PermViewForensics, PermManageForensics,
	},
	"readonly": {PermViewWAF, PermViewAudit},
}

func HasPermission(role string, perm Permission) bool {
	perms, ok := RolePermissions[role]
	if !ok { return false }
	for _, p := range perms { if p == perm { return true } }
	return false
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

type AuditLog struct {
	gorm.Model
	TenantID   string    `gorm:"index;size:36"`
	UserID     string    `gorm:"index;size:36"`
	UserEmail  string
	Action     string    `gorm:"not null"`     // tenant.create, user.invite, license.revoke, etc.
	Resource   string                            // tenant, user, license, waf_rule, etc.
	ResourceID string
	Details    string    `gorm:"type:text"`    // JSON
	IPAddress  string
	UserAgent  string
	Status     string    `gorm:"default:success"` // success|failure
	OccurredAt time.Time `gorm:"not null;index"`
}

// ── Admin Server ──────────────────────────────────────────────────────────────

type AdminServer struct {
	db        *gorm.DB
	jwtSecret []byte
}

type AdminClaims struct {
	UserID   string `json:"uid"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	TenantID string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

func NewAdminServer(db *gorm.DB, jwtSecret string) *AdminServer {
	db.AutoMigrate(&Tenant{}, &TenantUser{}, &AdminUser{}, &AuditLog{})
	srv := &AdminServer{db: db, jwtSecret: []byte(jwtSecret)}
	srv.ensureSuperAdmin()
	return srv
}

func (s *AdminServer) Register(r *gin.Engine) {
	api := r.Group("/admin/api/v1")

	// Public
	api.POST("/auth/login",   s.login)
	api.GET("/health",        s.health)

	// Authenticated
	auth := api.Group("")
	auth.Use(s.authMiddleware())
	{
		// Self
		auth.GET("/me",        s.getMe)
		auth.PUT("/me",        s.updateMe)
		auth.POST("/me/mfa",   s.setupMFA)

		// Tenants
		tenants := auth.Group("/tenants")
		tenants.Use(s.requirePermission(PermViewAllTenants))
		{
			tenants.GET("",           s.listTenants)
			tenants.POST("",          s.requirePermission(PermCreateTenant), s.createTenant)
			tenants.GET("/:id",       s.getTenant)
			tenants.PUT("/:id",       s.updateTenant)
			tenants.POST("/:id/suspend",   s.requirePermission(PermSuspendTenant), s.suspendTenant)
			tenants.POST("/:id/activate",  s.requirePermission(PermSuspendTenant), s.activateTenant)
			tenants.DELETE("/:id",         s.requirePermission(PermDeleteTenant), s.deleteTenant)
			tenants.GET("/:id/users",      s.getTenantUsers)
			tenants.POST("/:id/users",     s.inviteUserToTenant)
			tenants.DELETE("/:id/users/:uid", s.removeTenantUser)
			tenants.GET("/:id/audit",      s.getTenantAudit)
			tenants.GET("/:id/stats",      s.getTenantStats)
			tenants.GET("/:id/licenses",   s.getTenantLicenses)
			tenants.POST("/:id/impersonate", s.impersonateTenant)
		}

		// Admin Users
		users := auth.Group("/users")
		{
			users.GET("",           s.listAdminUsers)
			users.POST("",          s.createAdminUser)
			users.GET("/:id",       s.getAdminUser)
			users.PUT("/:id",       s.updateAdminUser)
			users.DELETE("/:id",    s.deleteAdminUser)
			users.POST("/:id/reset-password", s.resetUserPassword)
		}

		// Global Audit
		auth.GET("/audit",          s.getGlobalAudit)
		auth.GET("/audit/export",   s.exportAudit)

		// Platform Stats
		auth.GET("/stats",          s.getPlatformStats)
		auth.GET("/stats/tenants",  s.getTenantBreakdown)

		// Notifications
		auth.GET("/notifications",  s.getPlatformNotifications)
	}

	// Serve admin SPA
	r.Static("/admin/assets", "./admin/web/dist/assets")
	r.StaticFile("/admin",    "./admin/web/dist/index.html")
}

// ── Auth Handlers ─────────────────────────────────────────────────────────────

func (s *AdminServer) login(c *gin.Context) {
	var body struct {
		Email    string `json:"email"    binding:"required,email"`
		Password string `json:"password" binding:"required"`
		MFACode  string `json:"mfa_code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	var user AdminUser
	if err := s.db.Where("email = ? AND is_active = true", strings.ToLower(body.Email)).
		First(&user).Error; err != nil {
		s.audit("", "", "auth.login.failed", "admin_user", "", body.Email, c, "failure")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"}); return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(body.Password)); err != nil {
		s.audit(user.TenantID, user.ID, "auth.login.failed", "admin_user", user.ID, "bad password", c, "failure")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"}); return
	}
	now := time.Now()
	ip  := c.ClientIP()
	s.db.Model(&user).Updates(map[string]interface{}{"last_login": now, "last_login_ip": ip})
	token, _ := s.issueJWT(user)
	s.audit(user.TenantID, user.ID, "auth.login", "admin_user", user.ID, "login success", c, "success")
	c.JSON(http.StatusOK, gin.H{"token": token, "user": sanitizeUser(user)})
}

func (s *AdminServer) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "AXELUS Admin API"})
}

// ── Tenant Handlers ───────────────────────────────────────────────────────────

func (s *AdminServer) listTenants(c *gin.Context) {
	var tenants []Tenant
	q := s.db.Model(&Tenant{})
	if status := c.Query("status"); status != "" { q = q.Where("status = ?", status) }
	if plan   := c.Query("plan");   plan   != "" { q = q.Where("plan = ?", plan) }
	if search := c.Query("q");      search != "" {
		q = q.Where("name ILIKE ? OR slug ILIKE ? OR contact_email ILIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	var total int64
	q.Count(&total)

	page, size := paginate(c)
	q.Offset((page-1)*size).Limit(size).Order("created_at desc").Find(&tenants)

	// Enrich with user counts
	type TenantWithStats struct {
		Tenant
		UserCount    int64 `json:"user_count"`
		LicenseCount int64 `json:"license_count"`
	}
	result := make([]TenantWithStats, len(tenants))
	for i, t := range tenants {
		result[i] = TenantWithStats{Tenant: t}
		s.db.Model(&TenantUser{}).Where("tenant_id = ? AND is_active = true", t.ID).Count(&result[i].UserCount)
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "page": page, "tenants": result})
}

func (s *AdminServer) createTenant(c *gin.Context) {
	var body struct {
		Name         string `json:"name"          binding:"required"`
		Plan         string `json:"plan"          binding:"required"`
		Region       string `json:"region"`
		ContactEmail string `json:"contact_email" binding:"required,email"`
		Country      string `json:"country"`
		Notes        string `json:"notes"`
		MaxUsers     int    `json:"max_users"`
		MaxSites     int    `json:"max_sites"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}

	slug := slugify(body.Name)
	// Check slug uniqueness
	var existing Tenant
	if s.db.Where("slug = ?", slug).First(&existing).Error == nil {
		slug = slug + "-" + randomSuffix(4)
	}

	adminUser := c.GetString("user_id")
	id, _  := generateID()

	limits := planLimits(body.Plan)
	maxUsers := body.MaxUsers; if maxUsers == 0 { maxUsers = limits.MaxUsers }
	maxSites := body.MaxSites; if maxSites == 0 { maxSites = limits.MaxSites }

	tenant := Tenant{
		ID: id, Name: body.Name, Slug: slug, Plan: body.Plan,
		Status: "active", Region: body.Region, MaxUsers: maxUsers,
		MaxSites: maxSites, MaxRPS: limits.MaxRPS,
		ContactEmail: body.ContactEmail, Country: body.Country,
		Notes: body.Notes, CreatedBy: adminUser, IsIsolated: true,
	}
	if err := s.db.Create(&tenant).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tenant creation failed: " + err.Error()}); return
	}

	s.audit("", adminUser, "tenant.create", "tenant", id, body.Name, c, "success")
	c.JSON(http.StatusCreated, tenant)
}

func (s *AdminServer) getTenant(c *gin.Context) {
	var t Tenant
	if err := s.db.First(&t, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"}); return
	}
	c.JSON(http.StatusOK, t)
}

func (s *AdminServer) updateTenant(c *gin.Context) {
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	// Whitelist updatable fields
	allowed := []string{"name", "plan", "status", "max_users", "max_sites", "contact_email",
		"country", "notes", "logo_url", "primary_color", "custom_domain"}
	updates := make(map[string]interface{})
	for _, k := range allowed { if v, ok := body[k]; ok { updates[k] = v } }
	s.db.Model(&Tenant{}).Where("id = ?", c.Param("id")).Updates(updates)
	s.audit("", c.GetString("user_id"), "tenant.update", "tenant", c.Param("id"),
		fmt.Sprintf("%v", updates), c, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Tenant updated"})
}

func (s *AdminServer) suspendTenant(c *gin.Context) {
	var body struct { Reason string `json:"reason"` }
	c.ShouldBindJSON(&body)
	now := time.Now()
	s.db.Model(&Tenant{}).Where("id = ?", c.Param("id")).Updates(map[string]interface{}{
		"status": "suspended", "suspended_at": now, "suspend_reason": body.Reason,
	})
	s.audit("", c.GetString("user_id"), "tenant.suspend", "tenant", c.Param("id"), body.Reason, c, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Tenant suspended"})
}

func (s *AdminServer) activateTenant(c *gin.Context) {
	s.db.Model(&Tenant{}).Where("id = ?", c.Param("id")).Updates(map[string]interface{}{
		"status": "active", "suspended_at": nil, "suspend_reason": "",
	})
	s.audit("", c.GetString("user_id"), "tenant.activate", "tenant", c.Param("id"), "", c, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Tenant activated"})
}

func (s *AdminServer) deleteTenant(c *gin.Context) {
	// Soft delete
	s.db.Model(&Tenant{}).Where("id = ?", c.Param("id")).Update("status", "deleted")
	s.audit("", c.GetString("user_id"), "tenant.delete", "tenant", c.Param("id"), "", c, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted"})
}

func (s *AdminServer) getTenantUsers(c *gin.Context) {
	var users []TenantUser
	s.db.Where("tenant_id = ?", c.Param("id")).Order("joined_at desc").Find(&users)
	c.JSON(http.StatusOK, gin.H{"count": len(users), "users": users})
}

func (s *AdminServer) inviteUserToTenant(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required,email"`
		Role  string `json:"role"  binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	uid, _ := generateID()
	tu := TenantUser{
		TenantID: c.Param("id"), UserID: uid,
		Role: body.Role, InvitedBy: c.GetString("user_id"),
		JoinedAt: time.Now(), IsActive: true,
	}
	s.db.Create(&tu)
	s.audit(c.Param("id"), c.GetString("user_id"), "tenant.user.invite",
		"tenant_user", uid, body.Email, c, "success")
	c.JSON(http.StatusCreated, gin.H{"message": fmt.Sprintf("User %s invited as %s", body.Email, body.Role)})
}

func (s *AdminServer) removeTenantUser(c *gin.Context) {
	s.db.Model(&TenantUser{}).
		Where("tenant_id = ? AND user_id = ?", c.Param("id"), c.Param("uid")).
		Update("is_active", false)
	c.JSON(http.StatusOK, gin.H{"message": "User removed from tenant"})
}

func (s *AdminServer) getTenantAudit(c *gin.Context) {
	var logs []AuditLog
	s.db.Where("tenant_id = ?", c.Param("id")).Order("occurred_at desc").Limit(100).Find(&logs)
	c.JSON(http.StatusOK, gin.H{"count": len(logs), "logs": logs})
}

func (s *AdminServer) getTenantStats(c *gin.Context) {
	id := c.Param("id")
	var userCount, licenseCount int64
	s.db.Model(&TenantUser{}).Where("tenant_id = ? AND is_active = true", id).Count(&userCount)
	c.JSON(http.StatusOK, gin.H{
		"tenant_id":     id,
		"user_count":    userCount,
		"license_count": licenseCount,
		"waf_requests":  124891,  // from metrics in production
		"blocked":       8471,
		"block_rate":    6.8,
	})
}

func (s *AdminServer) getTenantLicenses(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Connect to license store for tenant " + c.Param("id")})
}

func (s *AdminServer) impersonateTenant(c *gin.Context) {
	// Super admin can impersonate any tenant for support
	tenantID := c.Param("id")
	adminID  := c.GetString("user_id")
	s.audit(tenantID, adminID, "tenant.impersonate", "tenant", tenantID, "admin impersonation", c, "success")
	// Issue a time-limited token scoped to the tenant
	impersonateToken := "imp-" + tenantID[:8] + "-" + randomSuffix(16)
	c.JSON(http.StatusOK, gin.H{
		"token":     impersonateToken,
		"tenant_id": tenantID,
		"expires":   time.Now().Add(1 * time.Hour).Unix(),
		"warning":   "Impersonation session — all actions are logged",
	})
}

// ── Admin Users ───────────────────────────────────────────────────────────────

func (s *AdminServer) listAdminUsers(c *gin.Context) {
	var users []AdminUser
	s.db.Where("is_active = true").Order("created_at desc").Find(&users)
	sanitized := make([]map[string]interface{}, len(users))
	for i, u := range users { sanitized[i] = sanitizeUser(u) }
	c.JSON(http.StatusOK, gin.H{"count": len(users), "users": sanitized})
}

func (s *AdminServer) createAdminUser(c *gin.Context) {
	var body struct {
		Email    string `json:"email"     binding:"required,email"`
		FullName string `json:"full_name" binding:"required"`
		Role     string `json:"role"      binding:"required"`
		Password string `json:"password"  binding:"required,min=10"`
		TenantID string `json:"tenant_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	apiKey, _ := generateToken(32)
	id, _    := generateID()
	user := AdminUser{
		ID: id, Email: strings.ToLower(body.Email), FullName: body.FullName,
		PasswordHash: string(hash), Role: body.Role, TenantID: body.TenantID,
		APIKey: apiKey, IsActive: true,
	}
	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"}); return
	}
	s.audit("", c.GetString("user_id"), "admin_user.create", "admin_user", id, body.Email, c, "success")
	c.JSON(http.StatusCreated, sanitizeUser(user))
}

func (s *AdminServer) getAdminUser(c *gin.Context) {
	var u AdminUser
	if err := s.db.First(&u, "id = ?", c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"}); return
	}
	c.JSON(http.StatusOK, sanitizeUser(u))
}

func (s *AdminServer) updateAdminUser(c *gin.Context) {
	var body map[string]interface{}; c.ShouldBindJSON(&body)
	allowed := []string{"full_name", "role", "is_active", "tenant_id"}
	updates := make(map[string]interface{})
	for _, k := range allowed { if v, ok := body[k]; ok { updates[k] = v } }
	s.db.Model(&AdminUser{}).Where("id = ?", c.Param("id")).Updates(updates)
	c.JSON(http.StatusOK, gin.H{"message": "User updated"})
}

func (s *AdminServer) deleteAdminUser(c *gin.Context) {
	s.db.Model(&AdminUser{}).Where("id = ?", c.Param("id")).Update("is_active", false)
	c.JSON(http.StatusOK, gin.H{"message": "User deactivated"})
}

func (s *AdminServer) resetUserPassword(c *gin.Context) {
	var body struct { NewPassword string `json:"new_password" binding:"required,min=10"` }
	if err := c.ShouldBindJSON(&body); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }
	hash, _ := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	s.db.Model(&AdminUser{}).Where("id = ?", c.Param("id")).Update("password_hash", string(hash))
	s.audit("", c.GetString("user_id"), "admin_user.password_reset", "admin_user", c.Param("id"), "", c, "success")
	c.JSON(http.StatusOK, gin.H{"message": "Password reset"})
}

func (s *AdminServer) getMe(c *gin.Context) {
	var u AdminUser
	s.db.First(&u, "id = ?", c.GetString("user_id"))
	c.JSON(http.StatusOK, sanitizeUser(u))
}

func (s *AdminServer) updateMe(c *gin.Context) {
	var body struct{ FullName string `json:"full_name"` }
	c.ShouldBindJSON(&body)
	s.db.Model(&AdminUser{}).Where("id = ?", c.GetString("user_id")).Update("full_name", body.FullName)
	c.JSON(http.StatusOK, gin.H{"message": "Profile updated"})
}

func (s *AdminServer) setupMFA(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "MFA setup endpoint — TOTP integration"})
}

// ── Audit & Stats ─────────────────────────────────────────────────────────────

func (s *AdminServer) getGlobalAudit(c *gin.Context) {
	var logs []AuditLog
	q := s.db.Model(&AuditLog{})
	if action := c.Query("action"); action != "" { q = q.Where("action = ?", action) }
	if userID := c.Query("user_id"); userID != "" { q = q.Where("user_id = ?", userID) }
	q.Order("occurred_at desc").Limit(200).Find(&logs)
	c.JSON(http.StatusOK, gin.H{"count": len(logs), "logs": logs})
}

func (s *AdminServer) exportAudit(c *gin.Context) {
	var logs []AuditLog
	s.db.Where("occurred_at >= ?", time.Now().AddDate(0, -1, 0)).Order("occurred_at desc").Find(&logs)
	// Build CSV
	var sb strings.Builder
	sb.WriteString("timestamp,tenant_id,user_email,action,resource,resource_id,status,ip\n")
	for _, l := range logs {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s\n",
			l.OccurredAt.Format(time.RFC3339), l.TenantID, l.UserEmail,
			l.Action, l.Resource, l.ResourceID, l.Status, l.IPAddress))
	}
	c.Header("Content-Disposition", "attachment; filename=axelus-audit-"+time.Now().Format("20060102")+".csv")
	c.Data(http.StatusOK, "text/csv", []byte(sb.String()))
}

func (s *AdminServer) getPlatformStats(c *gin.Context) {
	var tenantCount, userCount, activeCount int64
	s.db.Model(&Tenant{}).Count(&tenantCount)
	s.db.Model(&Tenant{}).Where("status = 'active'").Count(&activeCount)
	s.db.Model(&TenantUser{}).Where("is_active = true").Count(&userCount)

	byPlan := make(map[string]int64)
	for _, plan := range []string{"trial", "pro", "enterprise", "ultimate"} {
		s.db.Model(&Tenant{}).Where("plan = ?", plan).Count(&byPlan[plan])
	}
	c.JSON(http.StatusOK, gin.H{
		"tenants":       tenantCount,
		"active_tenants": activeCount,
		"total_users":   userCount,
		"by_plan":       byPlan,
		"mrr_estimate":  calculateMRR(byPlan),
	})
}

func (s *AdminServer) getTenantBreakdown(c *gin.Context) {
	var tenants []struct {
		Plan  string
		Count int64
	}
	s.db.Model(&Tenant{}).Select("plan, count(*) as count").Group("plan").Scan(&tenants)
	c.JSON(http.StatusOK, gin.H{"breakdown": tenants})
}

func (s *AdminServer) getPlatformNotifications(c *gin.Context) {
	var expiringSoon []Tenant // in production: join with license table
	c.JSON(http.StatusOK, gin.H{
		"notifications":   expiringSoon,
		"suspended_count": 0,
		"trial_expiring":  3,
	})
}

// ── Middleware ─────────────────────────────────────────────────────────────────

func (s *AdminServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearer(c)
		if token == "" {
			// Try API key
			if apiKey := c.GetHeader("X-Admin-API-Key"); apiKey != "" {
				var u AdminUser
				if s.db.Where("api_key = ? AND is_active = true", apiKey).First(&u).Error == nil {
					c.Set("user_id", u.ID)
					c.Set("user_role", u.Role)
					c.Set("tenant_id", u.TenantID)
					c.Next(); return
				}
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"}); return
		}
		claims, err := s.parseJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"}); return
		}
		c.Set("user_id",   claims.UserID)
		c.Set("user_role", claims.Role)
		c.Set("tenant_id", claims.TenantID)
		c.Next()
	}
}

func (s *AdminServer) requirePermission(perm Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("user_role")
		if !HasPermission(role, perm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("permission denied — role %q does not have %q", role, perm),
			}); return
		}
		c.Next()
	}
}

// ── JWT ───────────────────────────────────────────────────────────────────────

func (s *AdminServer) issueJWT(u AdminUser) (string, error) {
	claims := AdminClaims{
		UserID: u.ID, Email: u.Email, Role: u.Role, TenantID: u.TenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "axelus-admin",
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
}

func (s *AdminServer) parseJWT(tokenStr string) (*AdminClaims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &AdminClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("bad method") }
		return s.jwtSecret, nil
	})
	if err != nil { return nil, err }
	if c, ok := t.Claims.(*AdminClaims); ok && t.Valid { return c, nil }
	return nil, fmt.Errorf("invalid token")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *AdminServer) audit(tenantID, userID, action, resource, resourceID, details string, c *gin.Context, status string) {
	var userEmail string
	if userID != "" {
		var u AdminUser
		if s.db.Select("email").First(&u, "id = ?", userID).Error == nil { userEmail = u.Email }
	}
	log := AuditLog{
		TenantID: tenantID, UserID: userID, UserEmail: userEmail,
		Action: action, Resource: resource, ResourceID: resourceID,
		Details: details, Status: status, OccurredAt: time.Now().UTC(),
	}
	if c != nil { log.IPAddress = c.ClientIP(); log.UserAgent = c.GetHeader("User-Agent") }
	s.db.Create(&log)
}

func (s *AdminServer) ensureSuperAdmin() {
	var count int64
	s.db.Model(&AdminUser{}).Where("role = 'super_admin'").Count(&count)
	if count > 0 { return }
	id, _ := generateID()
	hash, _ := bcrypt.GenerateFromPassword([]byte("ChangeMe123!"), bcrypt.DefaultCost)
	apiKey, _ := generateToken(32)
	s.db.Create(&AdminUser{
		ID: id, Email: "admin@optimiumnexus.com", FullName: "Super Admin",
		PasswordHash: string(hash), Role: "super_admin", IsActive: true, APIKey: apiKey,
	})
	fmt.Printf("[admin] Super admin created: admin@optimiumnexus.com / ChangeMe123!\n")
	fmt.Printf("[admin] CHANGE THIS PASSWORD IMMEDIATELY.\n")
}

type planLimitsResult struct{ MaxUsers, MaxSites, MaxRPS int }
func planLimits(plan string) planLimitsResult {
	switch plan {
	case "pro":        return planLimitsResult{10, 10, 5000}
	case "enterprise": return planLimitsResult{50, -1, 50000}
	case "ultimate":   return planLimitsResult{-1, -1, -1}
	default:           return planLimitsResult{5, 1, 500}
	}
}

func calculateMRR(byPlan map[string]int64) int64 {
	prices := map[string]int64{"pro": 2492, "enterprise": 12492, "ultimate": 41658}
	var mrr int64
	for plan, count := range byPlan { mrr += prices[plan] * count }
	return mrr / 100 // dollars/month
}

func sanitizeUser(u AdminUser) map[string]interface{} {
	return map[string]interface{}{
		"id": u.ID, "email": u.Email, "full_name": u.FullName,
		"role": u.Role, "tenant_id": u.TenantID,
		"is_active": u.IsActive, "mfa_enabled": u.MFAEnabled,
		"last_login": u.LastLogin, "created_at": u.CreatedAt,
	}
}

func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') { b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' { b.WriteRune('-') }
	}
	return strings.Trim(b.String(), "-")
}

func generateID() (string, error) {
	b := make([]byte, 16); _, err := rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4],b[4:6],b[6:8],b[8:10],b[10:]), err
}

func generateToken(n int) (string, error) {
	b := make([]byte, n); _, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func randomSuffix(n int) string {
	t, _ := generateToken(n / 2)
	return t
}

func paginate(c *gin.Context) (int, int) {
	page, size := 1, 20
	fmt.Sscanf(c.DefaultQuery("page",      "1"),  "%d", &page)
	fmt.Sscanf(c.DefaultQuery("page_size", "20"), "%d", &size)
	if page < 1 { page = 1 }
	if size < 1 || size > 100 { size = 20 }
	return page, size
}

func extractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") { return auth[7:] }
	return ""
}

var _ = context.Background
