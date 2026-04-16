// AXELUS - Threat Intelligence Feed Syncer
// Syncs IP reputation feeds from AbuseIPDB, Emerging Threats, and custom sources
// into Redis and the AXELUS management API for real-time blocking.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisKeyPrefix    = "axelus:threat-intel:"
	redisIPSetKey     = "axelus:blocked-ips"
	abuseIPDBEndpoint = "https://api.abuseipdb.com/api/v2/blacklist"
)

var (
	ctx = context.Background()
	rdb *redis.Client
)

type Config struct {
	AbuseIPDBKey         string
	EmergingThreatsKey   string
	CustomFeeds          []string
	UpdateIntervalSecs   int
	RedisAddr            string
	RedisPassword        string
	MgtAPI               string
}

type SyncStats struct {
	TotalIPs      int
	NewIPs        int
	RemovedIPs    int
	Sources       []string
	LastUpdated   time.Time
	DurationMs    int64
}

func loadConfig() Config {
	interval, _ := strconv.Atoi(getEnv("UPDATE_INTERVAL", "3600"))
	customFeeds := []string{}
	if feeds := os.Getenv("CUSTOM_FEEDS"); feeds != "" {
		for _, f := range strings.Split(feeds, ",") {
			if f = strings.TrimSpace(f); f != "" {
				customFeeds = append(customFeeds, f)
			}
		}
	}
	return Config{
		AbuseIPDBKey:       getEnv("ABUSEIPDB_KEY", ""),
		EmergingThreatsKey: getEnv("EMERGING_THREATS_KEY", ""),
		CustomFeeds:        customFeeds,
		UpdateIntervalSecs: interval,
		RedisAddr:          getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:      getEnv("REDIS_PASSWORD", ""),
		MgtAPI:             getEnv("MGT_API", "https://localhost:1443"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func initRedis(cfg Config) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       0,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("[threat-intel] Failed to connect to Redis: %v", err)
	}
	log.Printf("[threat-intel] Connected to Redis at %s", cfg.RedisAddr)
}

func fetchAbuseIPDB(apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, nil
	}
	req, _ := http.NewRequest("GET", abuseIPDBEndpoint, nil)
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	q := req.URL.Query()
	q.Add("confidenceMinimum", "90")
	q.Add("limit", "50000")
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Data []struct {
			IPAddress string `json:"ipAddress"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("AbuseIPDB decode failed: %w", err)
	}

	ips := make([]string, 0, len(result.Data))
	for _, entry := range result.Data {
		ips = append(ips, entry.IPAddress)
	}
	log.Printf("[threat-intel] AbuseIPDB: fetched %d IPs", len(ips))
	return ips, nil
}

func fetchPlainTextFeed(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip CIDR or inline comments
		parts := strings.Fields(line)
		if len(parts) > 0 {
			ips = append(ips, parts[0])
		}
	}
	log.Printf("[threat-intel] Feed %s: fetched %d IPs", url, len(ips))
	return ips, nil
}

func syncToRedis(allIPs []string) (int, int, error) {
	pipe := rdb.Pipeline()
	newKey := redisIPSetKey + ":new"

	// Build new set
	for _, ip := range allIPs {
		pipe.SAdd(ctx, newKey, ip)
	}
	pipe.Expire(ctx, newKey, 48*time.Hour)

	// Atomic swap
	pipe.Rename(ctx, newKey, redisIPSetKey)
	pipe.Expire(ctx, redisIPSetKey, 48*time.Hour)

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return 0, 0, fmt.Errorf("redis sync failed: %w", err)
	}

	count, _ := rdb.SCard(ctx, redisIPSetKey).Result()

	// Store metadata
	meta := map[string]interface{}{
		"last_updated": time.Now().Unix(),
		"total_ips":    count,
	}
	metaJSON, _ := json.Marshal(meta)
	rdb.Set(ctx, redisKeyPrefix+"metadata", metaJSON, 48*time.Hour)

	return int(count), len(allIPs), nil
}

func runSync(cfg Config) SyncStats {
	start := time.Now()
	stats := SyncStats{LastUpdated: start}
	var allIPs []string

	// AbuseIPDB
	if ips, err := fetchAbuseIPDB(cfg.AbuseIPDBKey); err != nil {
		log.Printf("[threat-intel] AbuseIPDB error: %v", err)
	} else if len(ips) > 0 {
		allIPs = append(allIPs, ips...)
		stats.Sources = append(stats.Sources, "abuseipdb")
	}

	// Custom feeds
	for _, feedURL := range cfg.CustomFeeds {
		if ips, err := fetchPlainTextFeed(feedURL); err != nil {
			log.Printf("[threat-intel] Custom feed %s error: %v", feedURL, err)
		} else {
			allIPs = append(allIPs, ips...)
			stats.Sources = append(stats.Sources, feedURL)
		}
	}

	// Deduplicate
	seen := make(map[string]struct{}, len(allIPs))
	deduped := allIPs[:0]
	for _, ip := range allIPs {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			deduped = append(deduped, ip)
		}
	}

	total, newCount, err := syncToRedis(deduped)
	if err != nil {
		log.Printf("[threat-intel] Redis sync error: %v", err)
	}

	stats.TotalIPs = total
	stats.NewIPs = newCount
	stats.DurationMs = time.Since(start).Milliseconds()

	log.Printf("[threat-intel] Sync complete: %d unique IPs from %d sources in %dms",
		stats.TotalIPs, len(stats.Sources), stats.DurationMs)
	return stats
}

func main() {
	cfg := loadConfig()
	initRedis(cfg)

	// Custom HTTP client that skips TLS verification for internal mgt API
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	log.Printf("[threat-intel] AXELUS Threat Intelligence Syncer starting")
	log.Printf("[threat-intel] Update interval: %ds", cfg.UpdateIntervalSecs)

	// Initial sync
	runSync(cfg)

	// Periodic sync
	ticker := time.NewTicker(time.Duration(cfg.UpdateIntervalSecs) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		runSync(cfg)
	}
}
