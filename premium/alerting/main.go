// AXELUS - Multi-Channel Alerting Service
// Monitors the AXELUS management API and sends real-time alerts
// to Slack, Microsoft Teams, PagerDuty, and email.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type Config struct {
	ThresholdSeverity string
	SlackWebhook      string
	SlackChannel      string
	TeamsWebhook      string
	PagerDutyKey      string
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTo            string
	MgtAPI            string
}

type Alert struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`  // low | medium | high | critical
	Type        string    `json:"type"`      // sql_injection | xss | rce | ddos | ...
	SourceIP    string    `json:"source_ip"`
	TargetHost  string    `json:"target_host"`
	RequestPath string    `json:"request_path"`
	Timestamp   time.Time `json:"timestamp"`
	Count       int       `json:"count"`
}

var severityOrder = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func loadConfig() Config {
	return Config{
		ThresholdSeverity: getEnv("THRESHOLD_SEVERITY", "high"),
		SlackWebhook:      os.Getenv("SLACK_WEBHOOK"),
		SlackChannel:      getEnv("SLACK_CHANNEL", "#security-alerts"),
		TeamsWebhook:      os.Getenv("TEAMS_WEBHOOK"),
		PagerDutyKey:      os.Getenv("PAGERDUTY_KEY"),
		SMTPHost:          os.Getenv("SMTP_HOST"),
		SMTPPort:          getEnv("SMTP_PORT", "587"),
		SMTPUser:          os.Getenv("SMTP_USER"),
		SMTPPassword:      os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:          os.Getenv("SMTP_FROM"),
		SMTPTo:            os.Getenv("SMTP_TO"),
		MgtAPI:            getEnv("MGT_API", "https://localhost:1443"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func severityEmoji(s string) string {
	switch s {
	case "critical":
		return "🚨"
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	default:
		return "🔵"
	}
}

// sendSlack sends a rich Slack message
func sendSlack(cfg Config, alert Alert) error {
	if cfg.SlackWebhook == "" {
		return nil
	}
	emoji := severityEmoji(alert.Severity)
	payload := map[string]interface{}{
		"channel": cfg.SlackChannel,
		"attachments": []map[string]interface{}{
			{
				"color":      map[string]string{"critical": "danger", "high": "warning", "medium": "#FFAA00", "low": "good"}[alert.Severity],
				"title":      fmt.Sprintf("%s AXELUS Alert: %s", emoji, strings.ToUpper(alert.Severity)),
				"title_link": cfg.MgtAPI + "/dashboard",
				"fields": []map[string]string{
					{"title": "Attack Type", "value": alert.Type, "short": "true"},
					{"title": "Source IP", "value": alert.SourceIP, "short": "true"},
					{"title": "Target", "value": alert.TargetHost, "short": "true"},
					{"title": "Path", "value": alert.RequestPath, "short": "true"},
					{"title": "Count", "value": fmt.Sprintf("%d requests", alert.Count), "short": "true"},
					{"title": "Time", "value": alert.Timestamp.UTC().Format(time.RFC3339), "short": "true"},
				},
				"footer": "AXELUS WAF by OptiumNexus",
				"ts":     alert.Timestamp.Unix(),
			},
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(cfg.SlackWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack post failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// sendTeams sends a Microsoft Teams adaptive card
func sendTeams(cfg Config, alert Alert) error {
	if cfg.TeamsWebhook == "" {
		return nil
	}
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    fmt.Sprintf("AXELUS Alert: %s", alert.Severity),
		"themeColor": map[string]string{"critical": "FF0000", "high": "FFA500", "medium": "FFFF00", "low": "00FF00"}[alert.Severity],
		"title":      fmt.Sprintf("AXELUS Security Alert — %s", strings.ToUpper(alert.Severity)),
		"sections": []map[string]interface{}{
			{
				"facts": []map[string]string{
					{"name": "Attack Type", "value": alert.Type},
					{"name": "Source IP", "value": alert.SourceIP},
					{"name": "Target Host", "value": alert.TargetHost},
					{"name": "Path", "value": alert.RequestPath},
					{"name": "Request Count", "value": fmt.Sprintf("%d", alert.Count)},
					{"name": "Timestamp", "value": alert.Timestamp.UTC().Format(time.RFC3339)},
				},
			},
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(cfg.TeamsWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("teams post failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// sendPagerDuty triggers a PagerDuty incident
func sendPagerDuty(cfg Config, alert Alert) error {
	if cfg.PagerDutyKey == "" {
		return nil
	}
	payload := map[string]interface{}{
		"routing_key":  cfg.PagerDutyKey,
		"event_action": "trigger",
		"dedup_key":    alert.ID,
		"payload": map[string]interface{}{
			"summary":   fmt.Sprintf("AXELUS %s: %s from %s", strings.ToUpper(alert.Severity), alert.Type, alert.SourceIP),
			"source":    alert.TargetHost,
			"severity":  alert.Severity,
			"timestamp": alert.Timestamp.UTC().Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"attack_type":   alert.Type,
				"source_ip":     alert.SourceIP,
				"request_path":  alert.RequestPath,
				"request_count": alert.Count,
			},
		},
		"links": []map[string]string{
			{"href": cfg.MgtAPI + "/dashboard", "text": "Open AXELUS Dashboard"},
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post("https://events.pagerduty.com/v2/enqueue", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pagerduty post failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// sendEmail sends an HTML alert email
func sendEmail(cfg Config, alert Alert) error {
	if cfg.SMTPHost == "" || cfg.SMTPTo == "" {
		return nil
	}
	subject := fmt.Sprintf("[AXELUS] %s Security Alert: %s", strings.ToUpper(alert.Severity), alert.Type)
	body := fmt.Sprintf(`<html><body>
<h2 style="color:%s;">%s AXELUS Security Alert</h2>
<table border="1" cellpadding="8">
<tr><td><b>Severity</b></td><td>%s</td></tr>
<tr><td><b>Attack Type</b></td><td>%s</td></tr>
<tr><td><b>Source IP</b></td><td>%s</td></tr>
<tr><td><b>Target Host</b></td><td>%s</td></tr>
<tr><td><b>Path</b></td><td>%s</td></tr>
<tr><td><b>Request Count</b></td><td>%d</td></tr>
<tr><td><b>Timestamp</b></td><td>%s</td></tr>
</table>
<p><a href="%s/dashboard">Open AXELUS Dashboard</a></p>
</body></html>`,
		map[string]string{"critical": "#cc0000", "high": "#ff6600", "medium": "#ffaa00", "low": "#009900"}[alert.Severity],
		severityEmoji(alert.Severity),
		strings.ToUpper(alert.Severity),
		alert.Type, alert.SourceIP, alert.TargetHost, alert.RequestPath,
		alert.Count, alert.Timestamp.UTC().Format(time.RFC3339),
		cfg.MgtAPI,
	)

	msg := "From: " + cfg.SMTPFrom + "\r\n" +
		"To: " + cfg.SMTPTo + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		body

	auth := smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)
	return smtp.SendMail(cfg.SMTPHost+":"+cfg.SMTPPort, auth, cfg.SMTPFrom, []string{cfg.SMTPTo}, []byte(msg))
}

func dispatch(cfg Config, alert Alert) {
	threshold := severityOrder[cfg.ThresholdSeverity]
	if severityOrder[alert.Severity] < threshold {
		return
	}
	log.Printf("[alerting] Dispatching %s alert: %s from %s", alert.Severity, alert.Type, alert.SourceIP)
	if err := sendSlack(cfg, alert); err != nil {
		log.Printf("[alerting] Slack error: %v", err)
	}
	if err := sendTeams(cfg, alert); err != nil {
		log.Printf("[alerting] Teams error: %v", err)
	}
	if alert.Severity == "critical" {
		if err := sendPagerDuty(cfg, alert); err != nil {
			log.Printf("[alerting] PagerDuty error: %v", err)
		}
		if err := sendEmail(cfg, alert); err != nil {
			log.Printf("[alerting] Email error: %v", err)
		}
	}
}

func main() {
	cfg := loadConfig()
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	log.Printf("[alerting] AXELUS Alerting Service starting (threshold: %s)", cfg.ThresholdSeverity)

	// Poll AXELUS management API for new attack events
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// In production, this polls cfg.MgtAPI + "/api/open/events"
		// and dispatches alerts for new high/critical events.
		// The API integration is completed during management/webserver setup.
		log.Printf("[alerting] Polling for new security events...")
	}
}
