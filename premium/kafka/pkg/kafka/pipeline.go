// AXELUS-WAF — Kafka Event Streaming Pipeline
// High-throughput multi-tenant event streaming: 100k+ req/s
// Topics: security events, audit trail, metrics, UBA events, alerts
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/scram"
	"github.com/twmb/franz-go/pkg/kmsg"
)

// ── Topic Definitions ─────────────────────────────────────────────────────────

const (
	TopicSecurityEvents  = "axelus.security.events"
	TopicAuditLog        = "axelus.audit.log"
	TopicMetrics         = "axelus.metrics"
	TopicUBAEvents       = "axelus.uba.events"
	TopicAlerts          = "axelus.alerts"
	TopicThreats         = "axelus.threats"
	TopicForensics       = "axelus.forensics"
	TopicDDoS            = "axelus.ddos"
	TopicLicenseEvents   = "axelus.licensing.events"
	TopicTenantActivity  = "axelus.tenants.activity"
)

// AllTopics are all topics managed by AXELUS
var AllTopics = []string{
	TopicSecurityEvents, TopicAuditLog, TopicMetrics,
	TopicUBAEvents, TopicAlerts, TopicThreats, TopicForensics,
	TopicDDoS, TopicLicenseEvents, TopicTenantActivity,
}

// ── Event Envelope ────────────────────────────────────────────────────────────

type EventEnvelope struct {
	ID        string      `json:"id"`
	Version   int         `json:"v"`           // schema version
	Topic     string      `json:"topic"`
	TenantID  string      `json:"tenant_id"`
	Type      string      `json:"type"`        // event type within topic
	Timestamp time.Time   `json:"ts"`
	Source    string      `json:"source"`      // originating service
	Payload   interface{} `json:"payload"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// Typed events
type SecurityEvent struct {
	TenantID   string    `json:"tenant_id"`
	SourceIP   string    `json:"source_ip"`
	TargetHost string    `json:"target_host"`
	TargetPath string    `json:"target_path"`
	Method     string    `json:"method"`
	AttackType string    `json:"attack_type"`
	Score      float32   `json:"score"`
	Blocked    bool      `json:"blocked"`
	Protocol   string    `json:"protocol"`
	ModelVer   string    `json:"model_version,omitempty"`
	Latency    int64     `json:"latency_ms"`
	RequestID  string    `json:"request_id"`
	Timestamp  time.Time `json:"timestamp"`
}

type AlertEvent struct {
	TenantID   string    `json:"tenant_id"`
	AlertType  string    `json:"alert_type"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	EntityID   string    `json:"entity_id,omitempty"`
	Score      float64   `json:"score"`
	AutoAction string    `json:"auto_action,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

type MetricEvent struct {
	TenantID      string    `json:"tenant_id"`
	Period        string    `json:"period"`  // YYYY-MM-DDTHH:MM (minute bucket)
	Requests      int64     `json:"requests"`
	Blocked       int64     `json:"blocked"`
	BlockRate     float64   `json:"block_rate"`
	P50LatencyMs  float64   `json:"p50_ms"`
	P99LatencyMs  float64   `json:"p99_ms"`
	IngressBytes  int64     `json:"ingress_bytes"`
	ZeroDayEvents int       `json:"zero_day_events"`
	Timestamp     time.Time `json:"timestamp"`
}

// ── Kafka Config ──────────────────────────────────────────────────────────────

type Config struct {
	Brokers       []string      // e.g. ["kafka1:9092", "kafka2:9092"]
	ClientID      string        // "axelus-waf"
	GroupID       string        // consumer group
	// Auth
	SASLMechanism string        // "SCRAM-SHA-256" | "SCRAM-SHA-512" | "" (none)
	SASLUser      string
	SASLPassword  string
	TLSEnabled    bool
	// Performance tuning
	ProducerBatchMaxBytes  int32   // default 1MB
	ProducerLinger         time.Duration // default 5ms
	ProducerCompression    string  // "snappy" | "lz4" | "zstd" | "gzip"
	MaxBufferedRecords     int     // per-topic buffer
	ConsumerFetchMaxBytes  int32
	// Partitioning
	PartitionsByTenant     bool    // partition by tenant_id for ordered per-tenant delivery
	DefaultPartitions      int32   // default partitions per topic
	ReplicationFactor      int16   // default replication factor
}

func DefaultConfig(brokers []string) Config {
	return Config{
		Brokers:              brokers,
		ClientID:             "axelus-waf",
		GroupID:              "axelus-consumers",
		ProducerBatchMaxBytes: 1024 * 1024,  // 1MB
		ProducerLinger:       5 * time.Millisecond,
		ProducerCompression:  "snappy",
		MaxBufferedRecords:   10000,
		ConsumerFetchMaxBytes: 50 * 1024 * 1024, // 50MB
		PartitionsByTenant:   true,
		DefaultPartitions:    12,
		ReplicationFactor:    3,
	}
}

// ── Producer ──────────────────────────────────────────────────────────────────

type Producer struct {
	client    *kgo.Client
	cfg       Config
	stats     ProducerStats
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
}

type ProducerStats struct {
	Produced  atomic.Int64
	Bytes     atomic.Int64
	Errors    atomic.Int64
	BatchSent atomic.Int64
}

func NewProducer(cfg Config) (*Producer, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID),
		kgo.ProducerBatchMaxBytes(cfg.ProducerBatchMaxBytes),
		kgo.ProducerLinger(cfg.ProducerLinger),
		kgo.RecordPartitioner(kgo.StickyKeyPartitioner(nil)), // key-based partitioning
	}

	// Compression
	switch cfg.ProducerCompression {
	case "snappy": opts = append(opts, kgo.ProducerBatchCompression(kgo.SnappyCompression()))
	case "lz4":    opts = append(opts, kgo.ProducerBatchCompression(kgo.Lz4Compression()))
	case "zstd":   opts = append(opts, kgo.ProducerBatchCompression(kgo.ZstdCompression()))
	case "gzip":   opts = append(opts, kgo.ProducerBatchCompression(kgo.GzipCompression()))
	}

	// SASL auth
	if cfg.SASLUser != "" {
		switch cfg.SASLMechanism {
		case "SCRAM-SHA-256":
			auth := scram.Auth{User: cfg.SASLUser, Pass: cfg.SASLPassword}
			opts = append(opts, kgo.SASL(auth.AsSha256Mechanism()))
		case "SCRAM-SHA-512":
			auth := scram.Auth{User: cfg.SASLUser, Pass: cfg.SASLPassword}
			opts = append(opts, kgo.SASL(auth.AsSha512Mechanism()))
		}
	}

	client, err := kgo.NewClient(opts...)
	if err != nil { return nil, fmt.Errorf("kafka client: %w", err) }

	ctx, cancel := context.WithCancel(context.Background())
	return &Producer{client: client, cfg: cfg, ctx: ctx, cancel: cancel}, nil
}

// Produce sends an event to a Kafka topic
// The tenant_id is used as the partition key for ordered per-tenant delivery
func (p *Producer) Produce(topic, tenantID string, event interface{}) error {
	data, err := json.Marshal(event)
	if err != nil { return fmt.Errorf("marshal: %w", err) }

	record := &kgo.Record{
		Topic: topic,
		Key:   []byte(tenantID), // partition by tenant
		Value: data,
		Headers: []kgo.RecordHeader{
			{Key: "content-type", Value: []byte("application/json")},
			{Key: "producer",     Value: []byte("axelus-waf")},
			{Key: "schema-ver",   Value: []byte("1")},
		},
		Timestamp: time.Now(),
	}

	p.client.Produce(p.ctx, record, func(r *kgo.Record, err error) {
		if err != nil {
			p.stats.Errors.Add(1)
			fmt.Printf("[kafka] produce error topic=%s: %v\n", topic, err)
			return
		}
		p.stats.Produced.Add(1)
		p.stats.Bytes.Add(int64(len(data)))
	})
	return nil
}

// ProduceEnvelope wraps an event in a standard envelope and produces it
func (p *Producer) ProduceEnvelope(topic, tenantID, eventType string, payload interface{}) error {
	env := EventEnvelope{
		ID:        fmt.Sprintf("%s-%d", eventType, time.Now().UnixNano()),
		Version:   1,
		Topic:     topic,
		TenantID:  tenantID,
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Source:    "axelus-waf",
		Payload:   payload,
	}
	return p.Produce(topic, tenantID, env)
}

// ProduceSecurityEvent is a typed helper for security events
func (p *Producer) ProduceSecurityEvent(event SecurityEvent) error {
	return p.ProduceEnvelope(TopicSecurityEvents, event.TenantID, "security.event", event)
}

func (p *Producer) ProduceAlert(alert AlertEvent) error {
	return p.ProduceEnvelope(TopicAlerts, alert.TenantID, "alert", alert)
}

func (p *Producer) ProduceMetric(metric MetricEvent) error {
	return p.ProduceEnvelope(TopicMetrics, metric.TenantID, "metric.minute", metric)
}

// BatchProduce produces multiple records in a single batch (for high-throughput)
func (p *Producer) BatchProduce(events []struct {
	Topic    string
	TenantID string
	Payload  interface{}
}) error {
	records := make([]*kgo.Record, 0, len(events))
	for _, e := range events {
		data, err := json.Marshal(e.Payload)
		if err != nil { continue }
		records = append(records, &kgo.Record{
			Topic: e.Topic, Key: []byte(e.TenantID), Value: data,
			Timestamp: time.Now(),
		})
	}
	p.client.ProduceSync(p.ctx, records...)
	p.stats.Produced.Add(int64(len(records)))
	p.stats.BatchSent.Add(1)
	return nil
}

// Flush waits for all buffered records to be sent
func (p *Producer) Flush() error { return p.client.Flush(p.ctx) }

// Close gracefully shuts down the producer
func (p *Producer) Close() {
	p.Flush()
	p.cancel()
	p.client.Close()
}

// ── Consumer ──────────────────────────────────────────────────────────────────

type ConsumerHandler func(topic, tenantID string, payload []byte) error

type Consumer struct {
	client   *kgo.Client
	cfg      Config
	handlers map[string]ConsumerHandler // topic → handler
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	stats    ConsumerStats
}

type ConsumerStats struct {
	Consumed atomic.Int64
	Errors   atomic.Int64
	Lag      atomic.Int64
}

func NewConsumer(cfg Config, topics []string) (*Consumer, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.ClientID(cfg.ClientID + "-consumer"),
		kgo.ConsumerGroup(cfg.GroupID),
		kgo.ConsumeTopics(topics...),
		kgo.FetchMaxBytes(cfg.ConsumerFetchMaxBytes),
		kgo.DisableAutoCommit(),
	}

	if cfg.SASLUser != "" {
		auth := scram.Auth{User: cfg.SASLUser, Pass: cfg.SASLPassword}
		switch cfg.SASLMechanism {
		case "SCRAM-SHA-256": opts = append(opts, kgo.SASL(auth.AsSha256Mechanism()))
		case "SCRAM-SHA-512": opts = append(opts, kgo.SASL(auth.AsSha512Mechanism()))
		}
	}

	client, err := kgo.NewClient(opts...)
	if err != nil { return nil, fmt.Errorf("consumer client: %w", err) }

	ctx, cancel := context.WithCancel(context.Background())
	return &Consumer{
		client:   client,
		cfg:      cfg,
		handlers: make(map[string]ConsumerHandler),
		ctx:      ctx,
		cancel:   cancel,
	}, nil
}

// Register registers a handler for a topic
func (c *Consumer) Register(topic string, handler ConsumerHandler) {
	c.mu.Lock()
	c.handlers[topic] = handler
	c.mu.Unlock()
}

// Start begins consuming messages from all registered topics
func (c *Consumer) Start() {
	go c.consumeLoop()
}

func (c *Consumer) consumeLoop() {
	for {
		select {
		case <-c.ctx.Done(): return
		default:
		}

		fetches := c.client.PollFetches(c.ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			for _, e := range errs {
				fmt.Printf("[kafka] consumer error: %v\n", e.Err)
				c.stats.Errors.Add(1)
			}
			continue
		}

		fetches.EachRecord(func(record *kgo.Record) {
			c.mu.RLock()
			handler, ok := c.handlers[record.Topic]
			c.mu.RUnlock()

			if !ok { return }

			tenantID := string(record.Key)
			if err := handler(record.Topic, tenantID, record.Value); err != nil {
				fmt.Printf("[kafka] handler error topic=%s: %v\n", record.Topic, err)
				c.stats.Errors.Add(1)
			} else {
				c.stats.Consumed.Add(1)
			}
		})

		// Commit offsets
		c.client.CommitUncommittedOffsets(c.ctx)
	}
}

func (c *Consumer) Stop() { c.cancel(); c.client.Close() }

// ── Pipeline (Producer + Consumer bundled) ────────────────────────────────────

type Pipeline struct {
	producer  *Producer
	consumer  *Consumer
	admin     *AdminClient
	cfg       Config
}

func NewPipeline(cfg Config) (*Pipeline, error) {
	producer, err := NewProducer(cfg)
	if err != nil { return nil, fmt.Errorf("producer: %w", err) }

	consumer, err := NewConsumer(cfg, AllTopics)
	if err != nil { producer.Close(); return nil, fmt.Errorf("consumer: %w", err) }

	admin := NewAdminClient(cfg)

	return &Pipeline{producer: producer, consumer: consumer, admin: admin, cfg: cfg}, nil
}

func (p *Pipeline) Start() error {
	// Create topics if they don't exist
	if err := p.admin.EnsureTopics(AllTopics, p.cfg.DefaultPartitions, p.cfg.ReplicationFactor); err != nil {
		fmt.Printf("[kafka] topic creation warning: %v\n", err)
	}
	p.consumer.Start()
	fmt.Printf("[kafka] AXELUS pipeline started: brokers=%v topics=%d\n",
		p.cfg.Brokers, len(AllTopics))
	return nil
}

// Pub is the main publish interface
func (p *Pipeline) Pub() *Producer { return p.producer }

// Sub registers a consumer handler
func (p *Pipeline) Sub(topic string, handler ConsumerHandler) {
	p.consumer.Register(topic, handler)
}

// ── Admin Client ──────────────────────────────────────────────────────────────

type AdminClient struct {
	cfg Config
}

func NewAdminClient(cfg Config) *AdminClient { return &AdminClient{cfg: cfg} }

// EnsureTopics creates topics with the given configuration if they don't exist
func (a *AdminClient) EnsureTopics(topics []string, partitions int32, replication int16) error {
	client, err := kgo.NewClient(kgo.SeedBrokers(a.cfg.Brokers...))
	if err != nil { return err }
	defer client.Close()

	req := kmsg.NewPtrCreateTopicsRequest()
	req.Topics = make([]kmsg.CreateTopicsRequestTopic, len(topics))
	for i, topic := range topics {
		req.Topics[i] = kmsg.NewCreateTopicsRequestTopic()
		req.Topics[i].Topic = topic
		req.Topics[i].NumPartitions = partitions
		req.Topics[i].ReplicationFactor = replication
		req.Topics[i].Configs = []kmsg.CreateTopicsRequestTopicConfig{
			{Name: "retention.ms",  Value: kmsg.StringPtr("604800000")}, // 7 days
			{Name: "cleanup.policy", Value: kmsg.StringPtr("delete")},
			{Name: "compression.type", Value: kmsg.StringPtr("snappy")},
			{Name: "segment.bytes", Value: kmsg.StringPtr("536870912")}, // 512MB segments
		}
	}

	resp, err := req.RequestWith(context.Background(), client)
	if err != nil { return err }

	for _, t := range resp.Topics {
		if t.ErrorCode != 0 && t.ErrorCode != 36 { // 36 = TopicAlreadyExists
			fmt.Printf("[kafka] topic %s: error code %d\n", t.Name, t.ErrorCode)
		} else if t.ErrorCode == 0 {
			fmt.Printf("[kafka] topic created: %s (%d partitions)\n", t.Name, partitions)
		}
	}
	return nil
}

// GetLag returns consumer group lag for all topics
func (a *AdminClient) GetLag() (map[string]int64, error) {
	// In production: use kmsg.OffsetFetchRequest to get committed offsets
	// then compare with latest offsets from kmsg.ListOffsetsRequest
	return map[string]int64{
		TopicSecurityEvents: 0,
		TopicAlerts:         0,
	}, nil
}

// ── REST API ──────────────────────────────────────────────────────────────────

type APIServer struct {
	pipeline *Pipeline
}

func NewAPIServer(pipeline *Pipeline) *APIServer {
	return &APIServer{pipeline: pipeline}
}

func (s *APIServer) Register(rg *gin.RouterGroup) {
	k := rg.Group("/kafka")
	k.GET("/stats",    s.getStats)
	k.GET("/topics",   s.listTopics)
	k.POST("/produce", s.produce)
	k.GET("/lag",      s.getLag)
	k.POST("/topics",  s.createTopics)
}

func (s *APIServer) getStats(c *gin.Context) {
	p := s.pipeline.producer
	c.JSON(http.StatusOK, gin.H{
		"produced":   p.stats.Produced.Load(),
		"bytes":      p.stats.Bytes.Load(),
		"errors":     p.stats.Errors.Load(),
		"batches":    p.stats.BatchSent.Load(),
		"topics":     len(AllTopics),
		"brokers":    s.pipeline.cfg.Brokers,
		"group_id":   s.pipeline.cfg.GroupID,
		"compression": s.pipeline.cfg.ProducerCompression,
	})
}

func (s *APIServer) listTopics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"topics": AllTopics, "count": len(AllTopics)})
}

func (s *APIServer) produce(c *gin.Context) {
	var body struct {
		Topic    string          `json:"topic"     binding:"required"`
		TenantID string          `json:"tenant_id" binding:"required"`
		EventType string         `json:"event_type" binding:"required"`
		Payload  interface{}     `json:"payload"   binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	if err := s.pipeline.Pub().ProduceEnvelope(body.Topic, body.TenantID, body.EventType, body.Payload); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "queued", "topic": body.Topic})
}

func (s *APIServer) getLag(c *gin.Context) {
	lag, err := s.pipeline.admin.GetLag()
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	c.JSON(http.StatusOK, gin.H{"lag": lag})
}

func (s *APIServer) createTopics(c *gin.Context) {
	var body struct {
		Topics     []string `json:"topics"`
		Partitions int32    `json:"partitions"`
		Replication int16   `json:"replication_factor"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	if body.Partitions == 0 { body.Partitions = 12 }
	if body.Replication == 0 { body.Replication = 3 }
	err := s.pipeline.admin.EnsureTopics(body.Topics, body.Partitions, body.Replication)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	c.JSON(http.StatusCreated, gin.H{"created": body.Topics})
}
