// IronWall - SIEM Log Forwarder
// Tails IronWall Nginx access/attack logs and forwards them to
// Elasticsearch, Splunk HEC, or Grafana Loki in real time.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	LogDir            string
	ElasticsearchURL  string
	ElasticsearchUser string
	ElasticsearchPass string
	ElasticsearchIdx  string
	SplunkHECURL      string
	SplunkHECToken    string
	SplunkIndex       string
	LokiURL           string
}

type LogEntry struct {
	Timestamp  time.Time         `json:"@timestamp"`
	Host       string            `json:"host"`
	SourceFile string            `json:"source_file"`
	Raw        string            `json:"raw"`
	Fields     map[string]string `json:"fields"`
}

func loadConfig() Config {
	return Config{
		LogDir:            getEnv("LOG_DIR", "/logs/nginx"),
		ElasticsearchURL:  os.Getenv("ELASTICSEARCH_URL"),
		ElasticsearchUser: os.Getenv("ELASTICSEARCH_USER"),
		ElasticsearchPass: os.Getenv("ELASTICSEARCH_PASSWORD"),
		ElasticsearchIdx:  getEnv("ELASTICSEARCH_INDEX", "ironwall-logs"),
		SplunkHECURL:      os.Getenv("SPLUNK_HEC_URL"),
		SplunkHECToken:    os.Getenv("SPLUNK_HEC_TOKEN"),
		SplunkIndex:       getEnv("SPLUNK_INDEX", "ironwall"),
		LokiURL:           os.Getenv("LOKI_URL"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseNginxLog(line string) map[string]string {
	// Basic nginx combined log parser
	// Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	fields := make(map[string]string)
	fields["raw"] = line
	parts := strings.SplitN(line, " ", 10)
	if len(parts) >= 9 {
		fields["remote_addr"] = parts[0]
		fields["status"] = parts[8]
	}
	return fields
}

// sendToElasticsearch sends a log entry via the ES Bulk API
func sendToElasticsearch(cfg Config, entries []LogEntry) error {
	if cfg.ElasticsearchURL == "" {
		return nil
	}
	var buf bytes.Buffer
	for _, entry := range entries {
		meta := fmt.Sprintf(`{"index":{"_index":"%s"}}`, cfg.ElasticsearchIdx)
		buf.WriteString(meta + "\n")
		data, _ := json.Marshal(entry)
		buf.Write(data)
		buf.WriteString("\n")
	}

	req, _ := http.NewRequest("POST", cfg.ElasticsearchURL+"/_bulk", &buf)
	req.Header.Set("Content-Type", "application/x-ndjson")
	if cfg.ElasticsearchUser != "" {
		req.SetBasicAuth(cfg.ElasticsearchUser, cfg.ElasticsearchPass)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("elasticsearch bulk failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("elasticsearch returned %d", resp.StatusCode)
	}
	return nil
}

// sendToSplunk sends log entries via Splunk HTTP Event Collector
func sendToSplunk(cfg Config, entries []LogEntry) error {
	if cfg.SplunkHECURL == "" {
		return nil
	}
	var buf bytes.Buffer
	for _, entry := range entries {
		event := map[string]interface{}{
			"time":       entry.Timestamp.Unix(),
			"host":       entry.Host,
			"sourcetype": "ironwall:nginx",
			"index":      cfg.SplunkIndex,
			"event":      entry,
		}
		data, _ := json.Marshal(event)
		buf.Write(data)
	}

	req, _ := http.NewRequest("POST", cfg.SplunkHECURL+"/services/collector", &buf)
	req.Header.Set("Authorization", "Splunk "+cfg.SplunkHECToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("splunk HEC failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// sendToLoki sends log entries to Grafana Loki
func sendToLoki(cfg Config, entries []LogEntry) error {
	if cfg.LokiURL == "" {
		return nil
	}
	var streams []map[string]interface{}
	for _, entry := range entries {
		ts := fmt.Sprintf("%d", entry.Timestamp.UnixNano())
		streams = append(streams, map[string]interface{}{
			"stream": map[string]string{
				"job":    "ironwall",
				"source": entry.SourceFile,
				"host":   entry.Host,
			},
			"values": [][]string{{ts, entry.Raw}},
		})
	}

	payload := map[string]interface{}{"streams": streams}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", cfg.LokiURL+"/loki/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("loki push failed: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

func tailLogFile(ctx context.Context, cfg Config, path string, out chan<- LogEntry) {
	hostname, _ := os.Hostname()
	log.Printf("[siem] Tailing %s", path)

	f, err := os.Open(path)
	if err != nil {
		log.Printf("[siem] Cannot open %s: %v", path, err)
		return
	}
	defer f.Close()
	f.Seek(0, 2) // seek to end

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if scanner.Scan() {
				line := scanner.Text()
				out <- LogEntry{
					Timestamp:  time.Now().UTC(),
					Host:       hostname,
					SourceFile: filepath.Base(path),
					Raw:        line,
					Fields:     parseNginxLog(line),
				}
			} else {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

func main() {
	cfg := loadConfig()
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	log.Printf("[siem] IronWall SIEM Forwarder starting")
	if cfg.ElasticsearchURL != "" {
		log.Printf("[siem] Forwarding to Elasticsearch: %s / index: %s", cfg.ElasticsearchURL, cfg.ElasticsearchIdx)
	}
	if cfg.SplunkHECURL != "" {
		log.Printf("[siem] Forwarding to Splunk: %s", cfg.SplunkHECURL)
	}
	if cfg.LokiURL != "" {
		log.Printf("[siem] Forwarding to Loki: %s", cfg.LokiURL)
	}

	ctx := context.Background()
	entries := make(chan LogEntry, 1000)

	// Watch log files
	logFiles := []string{
		filepath.Join(cfg.LogDir, "access.log"),
		filepath.Join(cfg.LogDir, "error.log"),
		filepath.Join(cfg.LogDir, "detect.log"),
	}
	for _, f := range logFiles {
		go tailLogFile(ctx, cfg, f, entries)
	}

	// Batch and forward
	var batch []LogEntry
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry := <-entries:
			batch = append(batch, entry)
			if len(batch) >= 100 {
				flush(cfg, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				flush(cfg, batch)
				batch = batch[:0]
			}
		}
	}
}

func flush(cfg Config, entries []LogEntry) {
	if err := sendToElasticsearch(cfg, entries); err != nil {
		log.Printf("[siem] Elasticsearch error: %v", err)
	}
	if err := sendToSplunk(cfg, entries); err != nil {
		log.Printf("[siem] Splunk error: %v", err)
	}
	if err := sendToLoki(cfg, entries); err != nil {
		log.Printf("[siem] Loki error: %v", err)
	}
	log.Printf("[siem] Forwarded %d log entries", len(entries))
}
