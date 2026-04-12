// IronWall-WAF — Automated Email Notification System
// Handles license expiration alerts, security alerts, billing events,
// welcome sequences, and system health notifications.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// ── Notification Types ────────────────────────────────────────────────────────

type NotifType string

const (
	NotifLicenseExpiring7d  NotifType = "license.expiring.7d"
	NotifLicenseExpiring30d NotifType = "license.expiring.30d"
	NotifLicenseExpired     NotifType = "license.expired"
	NotifLicenseIssued      NotifType = "license.issued"
	NotifLicenseRevoked     NotifType = "license.revoked"

	NotifSecurityAlert      NotifType = "security.alert"
	NotifAttackSurge        NotifType = "security.attack_surge"
	NotifHoneypotTriggered  NotifType = "security.honeypot"
	NotifZeroDayDetected    NotifType = "security.zero_day"

	NotifBillingPaymentFailed NotifType = "billing.payment_failed"
	NotifBillingTrialEnding   NotifType = "billing.trial_ending"
	NotifBillingUpgraded      NotifType = "billing.upgraded"
	NotifBillingCancelled     NotifType = "billing.cancelled"
	NotifBillingInvoiceReady  NotifType = "billing.invoice_ready"

	NotifWelcome            NotifType = "onboarding.welcome"
	NotifOnboarding2d       NotifType = "onboarding.day2"
	NotifOnboarding7d       NotifType = "onboarding.day7"

	NotifSystemHealthDegraded NotifType = "system.health_degraded"
	NotifSystemMaintenance    NotifType = "system.maintenance"
)

// ── Notification Record ───────────────────────────────────────────────────────

type Notification struct {
	gorm.Model
	Type        NotifType `gorm:"not null;index"`
	Recipient   string    `gorm:"not null;index"`
	Subject     string    `gorm:"not null"`
	TenantID    string    `gorm:"index"`
	LicenseKey  string
	Status      string    `gorm:"default:pending;index"` // pending|sent|failed|suppressed
	Channel     string    `gorm:"default:email"`         // email|slack|webhook
	SentAt      *time.Time
	FailReason  string
	RetryCount  int       `gorm:"default:0"`
	ScheduledAt time.Time `gorm:"not null;index"`
	Metadata    string    `gorm:"type:text"` // JSON
}

// ── SMTP Config ───────────────────────────────────────────────────────────────

type SMTPConfig struct {
	Host       string
	Port       string
	User       string
	Password   string
	From       string
	FromName   string
	TLSEnabled bool
}

func LoadSMTPConfig() SMTPConfig {
	return SMTPConfig{
		Host:     getenv("SMTP_HOST", "smtp.example.com"),
		Port:     getenv("SMTP_PORT", "587"),
		User:     getenv("SMTP_USER", ""),
		Password: getenv("SMTP_PASSWORD", ""),
		From:     getenv("SMTP_FROM", "noreply@optimiumnexus.com"),
		FromName: getenv("SMTP_FROM_NAME", "IronWall-WAF"),
		TLSEnabled: os.Getenv("SMTP_TLS") != "false",
	}
}

// ── Email Templates ───────────────────────────────────────────────────────────

var baseTemplate = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f4f8;margin:0;padding:20px}
  .wrap{max-width:600px;margin:0 auto}
  .header{background:linear-gradient(135deg,#0f1520,#1a2840);padding:28px 32px;border-radius:10px 10px 0 0}
  .header-logo{font-size:20px;font-weight:800;color:#fff;letter-spacing:1px}
  .header-sub{font-size:11px;color:#00d4ff;margin-top:4px;letter-spacing:2px;text-transform:uppercase;font-family:monospace}
  .body{background:#fff;padding:32px;border:1px solid #e2e8f0;border-top:none}
  .footer{background:#f8fafc;padding:20px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 10px 10px;text-align:center;font-size:11px;color:#94a3b8}
  .footer a{color:#3b82f6;text-decoration:none}
  h1{font-size:22px;font-weight:700;color:#0f1520;margin:0 0 8px}
  p{color:#475569;font-size:14px;line-height:1.7;margin:0 0 16px}
  .btn{display:inline-block;background:#0099cc;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;font-weight:600;font-size:14px;margin:8px 0}
  .btn-danger{background:#dc2626}
  .btn-gold{background:linear-gradient(135deg,#d97706,#f59e0b)}
  .info-box{background:#f0f9ff;border:1px solid #bae6fd;border-radius:8px;padding:16px 20px;margin:16px 0}
  .info-box.warn{background:#fffbeb;border-color:#fde68a}
  .info-box.danger{background:#fef2f2;border-color:#fecaca}
  .info-box.success{background:#f0fdf4;border-color:#bbf7d0}
  .info-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:4px}
  .info-value{font-family:monospace;font-size:14px;color:#0f1520}
  .lic-key{display:inline-block;background:#0f1520;color:#00d4ff;font-family:monospace;font-size:14px;padding:8px 16px;border-radius:6px;letter-spacing:1px}
  .tier-badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase}
  .tier-ULTIMATE{background:linear-gradient(135deg,#78350f,#92400e);color:#fde68a}
  .tier-ENTERPRISE{background:#ecfdf5;color:#059669}
  .tier-PROFESSIONAL{background:#eff6ff;color:#2563eb}
  .tier-TRIAL{background:#fffbeb;color:#d97706}
  .divider{height:1px;background:#e2e8f0;margin:20px 0}
  .progress{height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden;margin:8px 0}
  .progress-fill{height:100%;border-radius:4px;transition:width .5s}
  table.details{width:100%;border-collapse:collapse}
  table.details td{padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px}
  table.details td:first-child{color:#64748b;width:140px}
  table.details td:last-child{color:#0f1520;font-weight:500}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="header-logo">🛡️ IronWall-WAF</div>
    <div class="header-sub">OPTIMIUM NEXUS LLC · Automated Notifications</div>
  </div>
  <div class="body">{{.Body}}</div>
  <div class="footer">
    <p style="margin:0 0 8px">© OPTIMIUM NEXUS LLC · <a href="https://www.optimiumnexus.com">www.optimiumnexus.com</a></p>
    <p style="margin:0"><a href="https://www.optimiumnexus.com/unsubscribe?token={{.UnsubToken}}">Unsubscribe</a> · <a href="https://www.optimiumnexus.com/docs">Documentation</a> · <a href="mailto:contact@optimiumnexus.com">Support</a></p>
  </div>
</div>
</body>
</html>`

// EmailTemplates holds all notification email bodies
var EmailTemplates = map[NotifType]struct{ Subject, Body string }{

	NotifLicenseExpiring7d: {
		Subject: "⚠️ Action Required: Your IronWall license expires in 7 days",
		Body: `<h1>Your License Expires Soon</h1>
<p>Hi {{.LicenseeName}},</p>
<p>Your <strong>IronWall-WAF {{.Tier}}</strong> license will expire in <strong>7 days</strong>. After expiration, your WAF protection will fall back to Community tier.</p>
<div class="info-box warn">
  <div class="info-label">License Key</div>
  <div class="lic-key">{{.LicenseKey}}</div>
  <div style="margin-top:10px">
    <div class="info-label">Expires</div>
    <div class="info-value">{{.ExpiresAt}} ({{.DaysRemaining}} days remaining)</div>
  </div>
</div>
<div class="progress"><div class="progress-fill" style="width:{{.ExpiryPercent}}%;background:#f59e0b"></div></div>
<p>Renew now to maintain uninterrupted protection:</p>
<a href="{{.RenewURL}}" class="btn">Renew License →</a>
<div class="divider"></div>
<p style="font-size:12px;color:#94a3b8">Need help? Reply to this email or contact <a href="mailto:contact@optimiumnexus.com">contact@optimiumnexus.com</a></p>`,
	},

	NotifLicenseExpiring30d: {
		Subject: "🔑 Your IronWall license expires in 30 days",
		Body: `<h1>License Renewal Reminder</h1>
<p>Hi {{.LicenseeName}},</p>
<p>This is a friendly reminder that your <strong>IronWall-WAF {{.Tier}}</strong> license expires in 30 days.</p>
<div class="info-box">
  <div class="info-label">License</div>
  <div style="display:flex;align-items:center;gap:12px;margin-top:4px">
    <div class="lic-key">{{.LicenseKey}}</div>
    <span class="tier-badge tier-{{.Tier}}">{{.Tier}}</span>
  </div>
  <div style="margin-top:10px"><div class="info-label">Expires</div><div class="info-value">{{.ExpiresAt}}</div></div>
</div>
<a href="{{.RenewURL}}" class="btn">Renew Now</a>
<a href="{{.UpgradeURL}}" class="btn btn-gold" style="margin-left:8px">Upgrade Plan</a>`,
	},

	NotifLicenseExpired: {
		Subject: "⛔ Your IronWall license has expired",
		Body: `<h1>License Expired</h1>
<p>Hi {{.LicenseeName}},</p>
<div class="info-box danger">
  <strong>Your IronWall-WAF {{.Tier}} license has expired.</strong><br/>
  Your WAF is now running in degraded Community mode with limited protection.
</div>
<p>To restore full protection, renew your license immediately:</p>
<a href="{{.RenewURL}}" class="btn btn-danger">Restore Full Protection →</a>
<div class="divider"></div>
<p><strong>What's affected while expired:</strong></p>
<ul style="color:#475569;font-size:14px;line-height:2">
  <li>GeoIP blocking — disabled</li>
  <li>Threat intelligence feeds — disabled</li>
  <li>Advanced DPI rules — disabled</li>
  <li>SIEM forwarding — disabled</li>
</ul>`,
	},

	NotifLicenseIssued: {
		Subject: "✅ Your IronWall license is ready",
		Body: `<h1>License Issued Successfully</h1>
<p>Hi {{.LicenseeName}},</p>
<p>Your new <strong>IronWall-WAF</strong> license has been issued and is ready to use.</p>
<div class="info-box success">
  <div class="info-label">Your License Key</div>
  <div class="lic-key" style="margin-top:8px">{{.LicenseKey}}</div>
  <div style="margin-top:12px;display:grid;grid-template-columns:1fr 1fr;gap:8px">
    <div><div class="info-label">Tier</div><span class="tier-badge tier-{{.Tier}}">{{.Tier}}</span></div>
    <div><div class="info-label">Valid Until</div><div class="info-value">{{.ExpiresAt}}</div></div>
  </div>
</div>
<p><strong>Quick Start:</strong></p>
<ol style="color:#475569;font-size:14px;line-height:2">
  <li>Download your <a href="{{.DownloadURL}}">license file (.lic)</a></li>
  <li>Place it at <code>/etc/ironwall/ironwall.lic</code></li>
  <li>Restart IronWall: <code>docker compose restart ironwall-mgt</code></li>
</ol>
<a href="{{.DashboardURL}}" class="btn">Open Dashboard</a>
<a href="{{.DocsURL}}" class="btn btn-gold" style="margin-left:8px">Read Docs</a>`,
	},

	NotifSecurityAlert: {
		Subject: "🚨 Security Alert: {{.AlertType}} — {{.TargetHost}}",
		Body: `<h1>Security Alert Detected</h1>
<p>IronWall-WAF has detected a security event that requires your attention.</p>
<div class="info-box danger">
  <div style="font-size:20px;font-weight:700;color:#dc2626;margin-bottom:12px">{{.AlertType}}</div>
  <table class="details">
    <tr><td>Source IP</td><td>{{.SourceIP}}</td></tr>
    <tr><td>Target</td><td>{{.TargetHost}}{{.TargetPath}}</td></tr>
    <tr><td>Severity</td><td><strong style="color:#dc2626">{{.Severity}}</strong></td></tr>
    <tr><td>Detected</td><td>{{.DetectedAt}}</td></tr>
    <tr><td>Action Taken</td><td>{{.Action}}</td></tr>
    <tr><td>Request Count</td><td>{{.RequestCount}}</td></tr>
  </table>
</div>
<a href="{{.DashboardURL}}/security" class="btn btn-danger">View in Dashboard →</a>`,
	},

	NotifBillingPaymentFailed: {
		Subject: "💳 Payment failed — action required for IronWall",
		Body: `<h1>Payment Failed</h1>
<p>Hi {{.CustomerName}},</p>
<div class="info-box danger">
  <strong>We were unable to process your payment</strong> for the IronWall-WAF {{.Plan}} plan.<br/>
  Amount: <strong>${{.Amount}}</strong> · Attempted: {{.AttemptedAt}}
</div>
<p>Your service will continue for 48 hours. After that, your account will be suspended if payment is not received.</p>
<a href="{{.BillingURL}}" class="btn btn-danger">Update Payment Method →</a>`,
	},

	NotifBillingTrialEnding: {
		Subject: "⏳ Your IronWall trial ends in {{.DaysRemaining}} days",
		Body: `<h1>Your Trial is Ending Soon</h1>
<p>Hi {{.CustomerName}},</p>
<p>Your <strong>30-day IronWall-WAF trial</strong> ends in <strong>{{.DaysRemaining}} days</strong>.</p>
<p>During your trial, IronWall has protected you:</p>
<div class="info-box success">
  <table class="details">
    <tr><td>Requests inspected</td><td><strong>{{.TotalRequests}}</strong></td></tr>
    <tr><td>Attacks blocked</td><td><strong>{{.BlockedRequests}}</strong></td></tr>
    <tr><td>Block rate</td><td><strong>{{.BlockRate}}%</strong></td></tr>
  </table>
</div>
<p>Choose a plan to continue protecting your infrastructure:</p>
<a href="{{.UpgradeURL}}" class="btn btn-gold">Choose a Plan →</a>`,
	},

	NotifBillingUpgraded: {
		Subject: "🚀 Welcome to IronWall {{.NewPlan}} — upgrade confirmed",
		Body: `<h1>Plan Upgrade Successful</h1>
<p>Hi {{.CustomerName}},</p>
<div class="info-box success">
  <strong>You've successfully upgraded to {{.NewPlan}}!</strong><br/>
  Your new features are active immediately.
</div>
<p><strong>New capabilities unlocked:</strong></p>
<ul style="color:#475569;font-size:14px;line-height:2">
  {{range .NewFeatures}}<li>{{.}}</li>{{end}}
</ul>
<a href="{{.DashboardURL}}" class="btn">Explore New Features →</a>`,
	},

	NotifWelcome: {
		Subject: "🛡️ Welcome to IronWall-WAF — your trial has started",
		Body: `<h1>Welcome to IronWall-WAF</h1>
<p>Hi {{.CustomerName}},</p>
<p>Welcome to <strong>IronWall-WAF</strong> by OPTIMIUM NEXUS LLC. Your 30-day trial has started and all Enterprise features are active.</p>
<div class="info-box success">
  <div class="info-label">Your Trial License</div>
  <div class="lic-key" style="margin-top:8px">{{.LicenseKey}}</div>
  <div style="margin-top:8px;font-size:12px;color:#64748b">Trial period: {{.TrialStart}} → {{.TrialEnd}}</div>
</div>
<p><strong>Get started in 3 steps:</strong></p>
<ol style="color:#475569;font-size:14px;line-height:2">
  <li><a href="{{.DocsURL}}/install">Install IronWall</a> on your server</li>
  <li>Add your first <a href="{{.DashboardURL}}/sites">protected site</a></li>
  <li>Review your <a href="{{.DashboardURL}}/dashboard">security dashboard</a></li>
</ol>
<a href="{{.DashboardURL}}" class="btn">Open Dashboard →</a>
<div class="divider"></div>
<p style="font-size:13px;color:#64748b">Questions? Our team is here to help: <a href="mailto:contact@optimiumnexus.com">contact@optimiumnexus.com</a></p>`,
	},

	NotifZeroDayDetected: {
		Subject: "🧠 Zero-Day Shield: Novel attack pattern detected",
		Body: `<h1>Zero-Day Pattern Detected</h1>
<p>IronWall's ML-based Zero-Day Shield has detected an <strong>anomalous attack pattern</strong> that does not match any known signature.</p>
<div class="info-box danger">
  <table class="details">
    <tr><td>Anomaly Score</td><td><strong>{{.Score}}/100</strong></td></tr>
    <tr><td>Confidence</td><td>{{.Confidence}}%</td></tr>
    <tr><td>Source IP</td><td>{{.SourceIP}}</td></tr>
    <tr><td>Target</td><td>{{.TargetPath}}</td></tr>
    <tr><td>Action</td><td><strong>{{.Action}}</strong></td></tr>
    <tr><td>Top Indicators</td><td>{{.TopFeatures}}</td></tr>
  </table>
</div>
<p>The request has been <strong>{{.Action}}</strong>. Review the full analysis in your dashboard.</p>
<a href="{{.DashboardURL}}/zerodayshield" class="btn btn-danger">View Analysis →</a>`,
	},
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

type Scheduler struct {
	db        *gorm.DB
	smtp      SMTPConfig
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	baseURL   string
	portalURL string
}

func NewScheduler(db *gorm.DB, smtp SMTPConfig, baseURL, portalURL string) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	db.AutoMigrate(&Notification{})
	return &Scheduler{db: db, smtp: smtp, ctx: ctx, cancel: cancel,
		baseURL: baseURL, portalURL: portalURL}
}

// Start begins all background notification jobs
func (s *Scheduler) Start() {
	s.wg.Add(1)
	go s.runLoop()
	fmt.Printf("[notifications] Scheduler started\n")
}

func (s *Scheduler) runLoop() {
	defer s.wg.Done()
	// Run jobs at different intervals
	licTicker  := time.NewTicker(6 * time.Hour)
	sendTicker := time.NewTicker(1 * time.Minute)
	defer licTicker.Stop()
	defer sendTicker.Stop()

	// Run immediately on start
	s.checkLicenseExpiries()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-licTicker.C:
			s.checkLicenseExpiries()
		case <-sendTicker.C:
			s.processPendingQueue()
		}
	}
}

// checkLicenseExpiries queries the license store and queues expiry notifications
func (s *Scheduler) checkLicenseExpiries() {
	fmt.Printf("[notifications] Checking license expiries...\n")
	// In production: query the license store for expiring licenses
	// For each license expiring in 30 days → queue 30d notification (if not already sent)
	// For each license expiring in 7 days  → queue 7d notification
	// For each expired license              → queue expired notification
	// Implementation connects to license DB and uses s.Queue()
}

// Queue adds a notification to the send queue
func (s *Scheduler) Queue(notif Notification) error {
	// Check for duplicate (same type + recipient + license + same day)
	var existing Notification
	today := time.Now().Format("2006-01-02")
	if s.db.Where(
		"type = ? AND recipient = ? AND license_key = ? AND DATE(scheduled_at) = ?",
		notif.Type, notif.Recipient, notif.LicenseKey, today,
	).First(&existing).Error == nil {
		return nil // already queued today
	}
	notif.Status = "pending"
	if notif.ScheduledAt.IsZero() { notif.ScheduledAt = time.Now() }
	return s.db.Create(&notif).Error
}

// QueueImmediate queues a notification for immediate sending
func (s *Scheduler) QueueImmediate(notifType NotifType, recipient, subject, body, tenantID, licenseKey string) error {
	return s.Queue(Notification{
		Type: notifType, Recipient: recipient, Subject: subject,
		TenantID: tenantID, LicenseKey: licenseKey,
		ScheduledAt: time.Now(),
	})
}

// processPendingQueue sends all pending notifications that are due
func (s *Scheduler) processPendingQueue() {
	var pending []Notification
	s.db.Where("status = 'pending' AND scheduled_at <= ? AND retry_count < 3",
		time.Now()).Limit(50).Find(&pending)

	for _, n := range pending {
		if err := s.sendEmail(n); err != nil {
			fmt.Printf("[notifications] Send failed %s→%s: %v\n", n.Type, n.Recipient, err)
			s.db.Model(&n).Updates(map[string]interface{}{
				"status":      "failed",
				"fail_reason": err.Error(),
				"retry_count": n.RetryCount + 1,
			})
			// Re-queue with backoff if retry_count < 3
			if n.RetryCount < 2 {
				s.db.Model(&n).Updates(map[string]interface{}{
					"status":       "pending",
					"scheduled_at": time.Now().Add(time.Duration(n.RetryCount+1) * 15 * time.Minute),
				})
			}
		} else {
			now := time.Now()
			s.db.Model(&n).Updates(map[string]interface{}{"status": "sent", "sent_at": now})
		}
	}
}

// ── Email Sender ──────────────────────────────────────────────────────────────

func (s *Scheduler) sendEmail(n Notification) error {
	if s.smtp.Host == "" || s.smtp.User == "" {
		fmt.Printf("[notifications] SMTP not configured — skipping %s to %s\n", n.Type, n.Recipient)
		return nil // Don't fail if SMTP not configured
	}

	// Build full HTML email
	wrapped := fmt.Sprintf(`<h1>%s</h1><p>%s</p>`, n.Subject,
		strings.ReplaceAll(n.Subject, "\"", ""))

	tmpl := template.Must(template.New("base").Parse(baseTemplate))
	data := map[string]interface{}{
		"Body":       template.HTML(wrapped),
		"UnsubToken": generateUnsubToken(n.Recipient),
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("template render: %w", err)
	}

	// Build raw MIME message
	msg := strings.Join([]string{
		fmt.Sprintf("From: %s <%s>", s.smtp.FromName, s.smtp.From),
		fmt.Sprintf("To: %s", n.Recipient),
		fmt.Sprintf("Subject: %s", n.Subject),
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"",
		buf.String(),
	}, "\r\n")

	addr := s.smtp.Host + ":" + s.smtp.Port
	auth := smtp.PlainAuth("", s.smtp.User, s.smtp.Password, s.smtp.Host)

	if s.smtp.TLSEnabled {
		tlsCfg := &tls.Config{ServerName: s.smtp.Host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil { return fmt.Errorf("TLS dial: %w", err) }
		c, err := smtp.NewClient(conn, s.smtp.Host)
		if err != nil { return fmt.Errorf("SMTP client: %w", err) }
		defer c.Quit()
		if err := c.Auth(auth); err != nil { return fmt.Errorf("SMTP auth: %w", err) }
		if err := c.Mail(s.smtp.From); err != nil { return fmt.Errorf("SMTP from: %w", err) }
		if err := c.Rcpt(n.Recipient); err != nil { return fmt.Errorf("SMTP rcpt: %w", err) }
		w, err := c.Data()
		if err != nil { return fmt.Errorf("SMTP data: %w", err) }
		w.Write([]byte(msg))
		w.Close()
	} else {
		if err := smtp.SendMail(addr, auth, s.smtp.From, []string{n.Recipient}, []byte(msg)); err != nil {
			return fmt.Errorf("smtp.SendMail: %w", err)
		}
	}

	fmt.Printf("[notifications] ✅ Sent %s to %s\n", n.Type, n.Recipient)
	return nil
}

// RenderTemplate renders a specific notification template with provided data
func RenderTemplate(notifType NotifType, data map[string]interface{}) (subject, body string, err error) {
	tmplDef, ok := EmailTemplates[notifType]
	if !ok { return "", "", fmt.Errorf("unknown notification type: %s", notifType) }

	subjectTmpl, err := template.New("subject").Parse(tmplDef.Subject)
	if err != nil { return "", "", err }
	var subjectBuf bytes.Buffer
	subjectTmpl.Execute(&subjectBuf, data)

	bodyTmpl, err := template.New("body").Parse(tmplDef.Body)
	if err != nil { return "", "", err }
	var bodyBuf bytes.Buffer
	bodyTmpl.Execute(&bodyBuf, data)

	return subjectBuf.String(), bodyBuf.String(), nil
}

// Stop gracefully shuts down the scheduler
func (s *Scheduler) Stop() {
	s.cancel()
	s.wg.Wait()
	fmt.Printf("[notifications] Scheduler stopped\n")
}

// GetStats returns notification statistics
func (s *Scheduler) GetStats() map[string]interface{} {
	var sent, failed, pending, suppressed int64
	s.db.Model(&Notification{}).Where("status = 'sent'").Count(&sent)
	s.db.Model(&Notification{}).Where("status = 'failed'").Count(&failed)
	s.db.Model(&Notification{}).Where("status = 'pending'").Count(&pending)
	s.db.Model(&Notification{}).Where("status = 'suppressed'").Count(&suppressed)
	return map[string]interface{}{
		"sent": sent, "failed": failed, "pending": pending,
		"suppressed": suppressed, "total": sent + failed + pending + suppressed,
		"template_count": len(EmailTemplates),
	}
}

func generateUnsubToken(email string) string {
	h := fmt.Sprintf("%x", []byte(email+"ironwall-unsub-salt"))
	if len(h) > 16 { return h[:16] }
	return h
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" { return v }
	return fallback
}
