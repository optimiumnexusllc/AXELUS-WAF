// IronWall-WAF — Notification Preferences & Multi-Channel Dispatcher
// Handles per-tenant notification settings, channel routing,
// Slack/Teams/PagerDuty/webhook delivery with retry and dedup.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

// ── Channel Types ─────────────────────────────────────────────────────────────

type ChannelType string

const (
	ChannelEmail     ChannelType = "email"
	ChannelSlack     ChannelType = "slack"
	ChannelTeams     ChannelType = "teams"
	ChannelPagerDuty ChannelType = "pagerduty"
	ChannelWebhook   ChannelType = "webhook"
	ChannelSMS       ChannelType = "sms"
)

// ── Notification Preferences (per tenant) ────────────────────────────────────

type NotifPreference struct {
	gorm.Model
	TenantID        string      `gorm:"not null;uniqueIndex:tenant_event"`
	EventType       string      `gorm:"not null;uniqueIndex:tenant_event"` // "license.expiring.*", "security.*", etc.
	Enabled         bool        `gorm:"default:true"`
	Channels        string      `gorm:"type:text"` // JSON array of ChannelConfig
	MinSeverity     string      `gorm:"default:low"` // low|medium|high|critical
	Cooldown        int         `gorm:"default:3600"` // seconds between same-type alerts
	MaxPerDay       int         `gorm:"default:20"`
	Digest          bool        `gorm:"default:false"` // batch into digest instead of immediate
	DigestSchedule  string      `gorm:"default:0 8 * * *"` // cron
}

type ChannelConfig struct {
	Type    ChannelType `json:"type"`
	Enabled bool        `json:"enabled"`
	// Email
	Recipients []string `json:"recipients,omitempty"`
	// Slack
	SlackWebhookURL string `json:"slack_webhook_url,omitempty"`
	SlackChannel    string `json:"slack_channel,omitempty"`
	// Teams
	TeamsWebhookURL string `json:"teams_webhook_url,omitempty"`
	// PagerDuty
	PagerDutyKey    string `json:"pagerduty_integration_key,omitempty"`
	PagerDutySeverity string `json:"pagerduty_severity,omitempty"` // critical|error|warning|info
	// Generic Webhook
	WebhookURL    string            `json:"webhook_url,omitempty"`
	WebhookSecret string            `json:"webhook_secret,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`
	// SMS
	PhoneNumbers []string `json:"phone_numbers,omitempty"`
}

// ── Dispatch Request ──────────────────────────────────────────────────────────

type DispatchRequest struct {
	TenantID    string
	EventType   string
	Severity    string // low|medium|high|critical
	Title       string
	Body        string      // HTML (for email) or plain text
	PlainText   string      // fallback plain text
	Data        interface{} // structured data for webhook payloads
	Channels    []ChannelConfig
	Timestamp   time.Time
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

type Dispatcher struct {
	db     *gorm.DB
	client *http.Client
	ctx    context.Context
}

func NewDispatcher(db *gorm.DB) *Dispatcher {
	db.AutoMigrate(&NotifPreference{})
	return &Dispatcher{
		db:  db,
		ctx: context.Background(),
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Dispatch routes a notification to all configured channels
func (d *Dispatcher) Dispatch(req DispatchRequest) []DispatchResult {
	var results []DispatchResult
	for _, ch := range req.Channels {
		if !ch.Enabled { continue }
		var result DispatchResult
		switch ch.Type {
		case ChannelSlack:
			result = d.sendSlack(req, ch)
		case ChannelTeams:
			result = d.sendTeams(req, ch)
		case ChannelPagerDuty:
			result = d.sendPagerDuty(req, ch)
		case ChannelWebhook:
			result = d.sendWebhook(req, ch)
		default:
			result = DispatchResult{Channel: string(ch.Type), Status: "skipped", Error: "channel handled by email scheduler"}
		}
		results = append(results, result)
	}
	return results
}

type DispatchResult struct {
	Channel   string
	Status    string // sent|failed|skipped
	Error     string
	Duration  time.Duration
}

// ── Slack ─────────────────────────────────────────────────────────────────────

func (d *Dispatcher) sendSlack(req DispatchRequest, ch ChannelConfig) DispatchResult {
	start := time.Now()
	if ch.SlackWebhookURL == "" {
		return DispatchResult{Channel: "slack", Status: "failed", Error: "no webhook URL"}
	}

	color := severityColor(req.Severity)
	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"blocks": []map[string]interface{}{
					{
						"type": "header",
						"text": map[string]string{"type": "plain_text", "text": "🛡️ " + req.Title},
					},
					{
						"type": "section",
						"text": map[string]interface{}{
							"type": "mrkdwn",
							"text": req.PlainText,
						},
					},
					{
						"type": "context",
						"elements": []map[string]string{
							{"type": "mrkdwn", "text": fmt.Sprintf("*IronWall-WAF* · Tenant: `%s` · %s · Severity: *%s*",
								req.TenantID, req.Timestamp.Format("2006-01-02 15:04 UTC"), strings.ToUpper(req.Severity))},
						},
					},
					{
						"type": "actions",
						"elements": []map[string]interface{}{
							{
								"type":      "button",
								"text":      map[string]string{"type": "plain_text", "text": "View Dashboard"},
								"url":       "https://www.optimiumnexus.com/portal",
								"style":     "primary",
							},
						},
					},
				},
			},
		},
	}
	if ch.SlackChannel != "" { payload["channel"] = ch.SlackChannel }

	if err := d.postJSON(ch.SlackWebhookURL, payload, nil); err != nil {
		return DispatchResult{Channel: "slack", Status: "failed", Error: err.Error(), Duration: time.Since(start)}
	}
	return DispatchResult{Channel: "slack", Status: "sent", Duration: time.Since(start)}
}

// ── Microsoft Teams ───────────────────────────────────────────────────────────

func (d *Dispatcher) sendTeams(req DispatchRequest, ch ChannelConfig) DispatchResult {
	start := time.Now()
	if ch.TeamsWebhookURL == "" {
		return DispatchResult{Channel: "teams", Status: "failed", Error: "no webhook URL"}
	}

	// Teams Adaptive Card
	payload := map[string]interface{}{
		"type":        "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body": []map[string]interface{}{
						{
							"type":   "TextBlock",
							"size":   "medium",
							"weight": "bolder",
							"text":   "🛡️ IronWall-WAF Alert",
							"color":  teamsColor(req.Severity),
						},
						{
							"type": "TextBlock",
							"text": req.Title,
							"weight": "bolder",
						},
						{
							"type": "TextBlock",
							"text": req.PlainText,
							"wrap": true,
							"color": "default",
						},
						{
							"type": "FactSet",
							"facts": []map[string]string{
								{"title": "Tenant",    "value": req.TenantID},
								{"title": "Severity",  "value": strings.ToUpper(req.Severity)},
								{"title": "Time",      "value": req.Timestamp.Format("2006-01-02 15:04 UTC")},
								{"title": "Publisher", "value": "OPTIMIUM NEXUS LLC"},
							},
						},
					},
					"actions": []map[string]interface{}{
						{
							"type":  "Action.OpenUrl",
							"title": "View Dashboard",
							"url":   "https://www.optimiumnexus.com/portal",
						},
					},
				},
			},
		},
	}

	if err := d.postJSON(ch.TeamsWebhookURL, payload, nil); err != nil {
		return DispatchResult{Channel: "teams", Status: "failed", Error: err.Error(), Duration: time.Since(start)}
	}
	return DispatchResult{Channel: "teams", Status: "sent", Duration: time.Since(start)}
}

// ── PagerDuty ─────────────────────────────────────────────────────────────────

func (d *Dispatcher) sendPagerDuty(req DispatchRequest, ch ChannelConfig) DispatchResult {
	start := time.Now()
	if ch.PagerDutyKey == "" {
		return DispatchResult{Channel: "pagerduty", Status: "failed", Error: "no integration key"}
	}

	severity := ch.PagerDutySeverity
	if severity == "" { severity = pdSeverity(req.Severity) }

	// PagerDuty Events API v2
	payload := map[string]interface{}{
		"routing_key":  ch.PagerDutyKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("ironwall-%s-%s-%d", req.TenantID, req.EventType, req.Timestamp.Unix()/300), // 5-min dedup
		"payload": map[string]interface{}{
			"summary":   req.Title,
			"severity":  severity,
			"source":    fmt.Sprintf("IronWall-WAF / tenant:%s", req.TenantID),
			"timestamp": req.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"tenant_id":   req.TenantID,
				"event_type":  req.EventType,
				"severity":    req.Severity,
				"plain_text":  req.PlainText,
				"data":        req.Data,
				"publisher":   "OPTIMIUM NEXUS LLC",
				"portal":      "https://www.optimiumnexus.com/portal",
			},
		},
		"links": []map[string]string{
			{"href": "https://www.optimiumnexus.com/portal", "text": "IronWall Dashboard"},
		},
	}

	if err := d.postJSON("https://events.pagerduty.com/v2/enqueue", payload, nil); err != nil {
		return DispatchResult{Channel: "pagerduty", Status: "failed", Error: err.Error(), Duration: time.Since(start)}
	}
	return DispatchResult{Channel: "pagerduty", Status: "sent", Duration: time.Since(start)}
}

// ── Generic Webhook ───────────────────────────────────────────────────────────

func (d *Dispatcher) sendWebhook(req DispatchRequest, ch ChannelConfig) DispatchResult {
	start := time.Now()
	if ch.WebhookURL == "" {
		return DispatchResult{Channel: "webhook", Status: "failed", Error: "no webhook URL"}
	}

	payload := map[string]interface{}{
		"event_type":  req.EventType,
		"severity":    req.Severity,
		"title":       req.Title,
		"message":     req.PlainText,
		"tenant_id":   req.TenantID,
		"timestamp":   req.Timestamp.Format(time.RFC3339),
		"data":        req.Data,
		"publisher":   "OPTIMIUM NEXUS LLC",
		"portal_url":  "https://www.optimiumnexus.com/portal",
	}

	headers := map[string]string{"Content-Type": "application/json"}
	for k, v := range ch.WebhookHeaders { headers[k] = v }

	// HMAC signature for webhook verification
	if ch.WebhookSecret != "" {
		body, _ := json.Marshal(payload)
		mac := hmac.New(sha256.New, []byte(ch.WebhookSecret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		headers["X-IronWall-Signature"] = "sha256=" + sig
		headers["X-IronWall-Timestamp"] = req.Timestamp.Format(time.RFC3339)
	}

	if err := d.postJSON(ch.WebhookURL, payload, headers); err != nil {
		return DispatchResult{Channel: "webhook", Status: "failed", Error: err.Error(), Duration: time.Since(start)}
	}
	return DispatchResult{Channel: "webhook", Status: "sent", Duration: time.Since(start)}
}

// ── Preference Management ─────────────────────────────────────────────────────

// GetPreferences returns notification preferences for a tenant
func (d *Dispatcher) GetPreferences(tenantID string) ([]NotifPreference, error) {
	var prefs []NotifPreference
	err := d.db.Where("tenant_id = ?", tenantID).Find(&prefs).Error
	return prefs, err
}

// UpsertPreference creates or updates a notification preference
func (d *Dispatcher) UpsertPreference(pref NotifPreference) error {
	return d.db.Save(&pref).Error
}

// GetDefaultChannels returns the default channel config for a tenant based on plan
func (d *Dispatcher) GetDefaultChannels(plan string) []ChannelConfig {
	channels := []ChannelConfig{
		{Type: ChannelEmail, Enabled: true},
	}
	if plan == "enterprise" || plan == "ultimate" {
		channels = append(channels,
			ChannelConfig{Type: ChannelSlack, Enabled: false},
			ChannelConfig{Type: ChannelWebhook, Enabled: false},
		)
	}
	if plan == "ultimate" {
		channels = append(channels, ChannelConfig{Type: ChannelPagerDuty, Enabled: false})
	}
	return channels
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (d *Dispatcher) postJSON(url string, payload interface{}, headers map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil { return fmt.Errorf("marshal: %w", err) }

	req, err := http.NewRequestWithContext(d.ctx, "POST", url, bytes.NewReader(body))
	if err != nil { return fmt.Errorf("request: %w", err) }

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "IronWall-WAF/1.0 (OPTIMIUM NEXUS LLC)")
	for k, v := range headers { req.Header.Set(k, v) }

	resp, err := d.client.Do(req)
	if err != nil { return fmt.Errorf("http: %w", err) }
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return nil
}

func severityColor(s string) string {
	switch s {
	case "critical": return "#dc2626"
	case "high":     return "#f59e0b"
	case "medium":   return "#3b82f6"
	default:         return "#10b981"
	}
}

func teamsColor(s string) string {
	switch s {
	case "critical": return "attention"
	case "high":     return "warning"
	case "medium":   return "accent"
	default:         return "good"
	}
}

func pdSeverity(s string) string {
	switch s {
	case "critical": return "critical"
	case "high":     return "error"
	case "medium":   return "warning"
	default:         return "info"
	}
}
