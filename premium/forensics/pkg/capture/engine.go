// AXELUS-WAF — Forensics & PCAP Capture Engine
// Full packet capture with ring buffer, session reconstruction,
// attack timeline, and cryptographic evidence packaging.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package capture

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ── PCAP Global Header ────────────────────────────────────────────────────────

const (
	PCAPMagicNumber  = 0xa1b2c3d4
	PCAPVersionMajor = 2
	PCAPVersionMinor = 4
	PCAPSnapLen      = 65535
	PCAPLinkTypeEth  = 1
	PCAPLinkTypeRaw  = 101
)

// ── Packet ────────────────────────────────────────────────────────────────────

type Packet struct {
	Timestamp   time.Time
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    string // TCP|UDP|ICMP
	Payload     []byte
	Direction   Direction
	SessionID   string
	ThreatScore int
	Tags        []string
}

type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

// ── Session ───────────────────────────────────────────────────────────────────

type Session struct {
	ID          string
	ClientIP    string
	ClientPort  uint16
	ServerIP    string
	ServerPort  uint16
	Protocol    string
	StartTime   time.Time
	EndTime     time.Time
	Packets     []Packet
	BytesSent   int64
	BytesRecv   int64
	ThreatScore int
	Blocked     bool
	AttackType  string
	RequestCount int
}

func (s *Session) Duration() time.Duration {
	if s.EndTime.IsZero() { return time.Since(s.StartTime) }
	return s.EndTime.Sub(s.StartTime)
}

// ── Ring Buffer ───────────────────────────────────────────────────────────────

// RingBuffer is a fixed-size circular packet buffer with O(1) write.
// When full, oldest packets are overwritten (ring behaviour).
type RingBuffer struct {
	mu       sync.RWMutex
	packets  []Packet
	head     int64 // next write position
	size     int64 // buffer capacity
	count    int64 // total written (monotonic)
}

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		packets: make([]Packet, capacity),
		size:    int64(capacity),
	}
}

func (rb *RingBuffer) Write(p Packet) {
	rb.mu.Lock()
	idx := atomic.AddInt64(&rb.head, 1) - 1
	rb.packets[idx%rb.size] = p
	atomic.AddInt64(&rb.count, 1)
	rb.mu.Unlock()
}

// Read returns the last n packets from the ring buffer
func (rb *RingBuffer) Read(n int) []Packet {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	total := atomic.LoadInt64(&rb.count)
	if int64(n) > total { n = int(total) }
	result := make([]Packet, n)
	head := atomic.LoadInt64(&rb.head)
	for i := 0; i < n; i++ {
		idx := (head - int64(n) + int64(i)) % rb.size
		if idx < 0 { idx += rb.size }
		result[i] = rb.packets[idx]
	}
	return result
}

// ReadBySession returns all buffered packets for a given session ID
func (rb *RingBuffer) ReadBySession(sessionID string) []Packet {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	var result []Packet
	for i := int64(0); i < rb.size; i++ {
		p := rb.packets[i]
		if p.SessionID == sessionID { result = append(result, p) }
	}
	return result
}

// ── Capture Engine ────────────────────────────────────────────────────────────

type Config struct {
	Interface     string        // Network interface (e.g., "eth0") or "any"
	SnapLen       int           // Max bytes per packet
	BPFFilter     string        // Berkeley Packet Filter expression
	RingSize      int           // Ring buffer capacity (packets)
	StorePath     string        // Directory for PCAP files
	MaxFileSizeMB int           // Rotate PCAP file at this size
	RetentionDays int           // Delete PCAP files older than N days
	CaptureMode   CaptureMode
	ThreatOnly    bool          // Only capture packets flagged as threats
}

type CaptureMode string

const (
	CaptureFull    CaptureMode = "full"    // All packets
	CaptureSession CaptureMode = "session" // Complete sessions only
	CaptureThreat  CaptureMode = "threat"  // Threat-flagged packets only
	CaptureHeader  CaptureMode = "header"  // Headers only, no body (GDPR mode)
)

type Engine struct {
	cfg         Config
	ring        *RingBuffer
	sessions    sync.Map // sessionID → *Session
	writers     sync.Map // filename → *PCAPWriter
	stats       Stats
	ctx         context.Context
	cancel      context.CancelFunc
	onCapture   func(Packet)  // hook for real-time analysis
	onSession   func(Session) // hook on session close
}

type Stats struct {
	PacketsCaptured   int64
	PacketsDropped    int64
	BytesCaptured     int64
	SessionsTracked   int64
	ThreatPackets     int64
	PCAPFilesWritten  int64
	CurrentBandwidth  int64 // bytes/sec
}

func New(cfg Config) *Engine {
	if cfg.RingSize == 0    { cfg.RingSize = 100_000 }
	if cfg.SnapLen == 0     { cfg.SnapLen = 65535 }
	if cfg.RetentionDays == 0 { cfg.RetentionDays = 30 }
	if cfg.MaxFileSizeMB == 0 { cfg.MaxFileSizeMB = 256 }
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		cfg:    cfg,
		ring:   NewRingBuffer(cfg.RingSize),
		ctx:    ctx,
		cancel: cancel,
	}
}

// IngestPacket is called by the WAF proxy layer to feed packets to the engine.
// In production, this is called from Tengine's Lua module via Go plugin or gRPC.
func (e *Engine) IngestPacket(p Packet) {
	if e.cfg.ThreatOnly && p.ThreatScore < 30 { return }

	atomic.AddInt64(&e.stats.PacketsCaptured, 1)
	atomic.AddInt64(&e.stats.BytesCaptured, int64(len(p.Payload)))
	if p.ThreatScore >= 60 { atomic.AddInt64(&e.stats.ThreatPackets, 1) }

	// Ring buffer
	e.ring.Write(p)

	// Session tracking
	if p.SessionID != "" {
		e.trackSession(p)
	}

	// Write to PCAP file
	if e.cfg.StorePath != "" {
		go e.writePCAP(p)
	}

	// Real-time hook
	if e.onCapture != nil {
		go e.onCapture(p)
	}
}

func (e *Engine) trackSession(p Packet) {
	raw, _ := e.sessions.LoadOrStore(p.SessionID, &Session{
		ID:        p.SessionID,
		ClientIP:  p.SrcIP.String(),
		ClientPort: p.SrcPort,
		ServerIP:  p.DstIP.String(),
		ServerPort: p.DstPort,
		Protocol:  p.Protocol,
		StartTime: p.Timestamp,
	})
	sess := raw.(*Session)
	sess.Packets = append(sess.Packets, p)
	if p.Direction == DirectionInbound {
		sess.BytesSent += int64(len(p.Payload))
	} else {
		sess.BytesRecv += int64(len(p.Payload))
	}
	if p.ThreatScore > sess.ThreatScore { sess.ThreatScore = p.ThreatScore }
}

// CloseSession finalises a session and triggers the session hook
func (e *Engine) CloseSession(sessionID string) *Session {
	raw, ok := e.sessions.LoadAndDelete(sessionID)
	if !ok { return nil }
	sess := raw.(*Session)
	sess.EndTime = time.Now()
	atomic.AddInt64(&e.stats.SessionsTracked, 1)
	if e.onSession != nil { go e.onSession(*sess) }
	return sess
}

// ── PCAP Writer ───────────────────────────────────────────────────────────────

type PCAPWriter struct {
	mu      sync.Mutex
	f       *os.File
	path    string
	written int64
}

func newPCAPWriter(path string) (*PCAPWriter, error) {
	f, err := os.Create(path)
	if err != nil { return nil, err }
	w := &PCAPWriter{f: f, path: path}
	if err := w.writeGlobalHeader(); err != nil {
		f.Close(); return nil, err
	}
	return w, nil
}

func (w *PCAPWriter) writeGlobalHeader() error {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:],  PCAPMagicNumber)
	binary.LittleEndian.PutUint16(buf[4:],  PCAPVersionMajor)
	binary.LittleEndian.PutUint16(buf[6:],  PCAPVersionMinor)
	binary.LittleEndian.PutUint32(buf[8:],  0) // thiszone
	binary.LittleEndian.PutUint32(buf[12:], 0) // sigfigs
	binary.LittleEndian.PutUint32(buf[16:], PCAPSnapLen)
	binary.LittleEndian.PutUint32(buf[20:], PCAPLinkTypeRaw)
	_, err := w.f.Write(buf)
	w.written += 24
	return err
}

func (w *PCAPWriter) WritePacket(p Packet) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	payload := p.Payload
	if len(payload) > PCAPSnapLen { payload = payload[:PCAPSnapLen] }

	// PCAP record header (16 bytes)
	rec := make([]byte, 16)
	ts := p.Timestamp.Unix()
	usec := int64(p.Timestamp.Nanosecond()) / 1000
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts))
	binary.LittleEndian.PutUint32(rec[4:], uint32(usec))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(payload)))

	if _, err := w.f.Write(rec); err != nil { return err }
	if _, err := w.f.Write(payload); err != nil { return err }
	w.written += int64(16 + len(payload))
	return nil
}

func (w *PCAPWriter) Close() error { return w.f.Close() }
func (w *PCAPWriter) Size() int64  { return w.written }

func (e *Engine) writePCAP(p Packet) {
	// Rotate by date + threat level
	var prefix string
	if p.ThreatScore >= 60 { prefix = "threat" } else { prefix = "traffic" }
	filename := filepath.Join(e.cfg.StorePath,
		fmt.Sprintf("%s-%s.pcap", prefix, p.Timestamp.UTC().Format("2006-01-02")))

	raw, _ := e.writers.LoadOrStore(filename, (*PCAPWriter)(nil))
	var writer *PCAPWriter

	if raw == nil {
		var err error
		writer, err = newPCAPWriter(filename)
		if err != nil { return }
		e.writers.Store(filename, writer)
		atomic.AddInt64(&e.stats.PCAPFilesWritten, 1)
	} else {
		writer = raw.(*PCAPWriter)
		if writer == nil { return }
		// Rotate if too large
		if writer.Size() > int64(e.cfg.MaxFileSizeMB)*1024*1024 {
			writer.Close()
			rotated := filename + fmt.Sprintf(".%d", time.Now().Unix())
			os.Rename(filename, rotated)
			writer, _ = newPCAPWriter(filename)
			if writer == nil { return }
			e.writers.Store(filename, writer)
		}
	}
	writer.WritePacket(p)
}

// ── PCAP Export ───────────────────────────────────────────────────────────────

// ExportSession exports a complete session as a PCAP file
func (e *Engine) ExportSession(sessionID, destPath string) error {
	packets := e.ring.ReadBySession(sessionID)
	if len(packets) == 0 { return fmt.Errorf("no packets found for session %s", sessionID) }

	w, err := newPCAPWriter(destPath)
	if err != nil { return err }
	defer w.Close()

	for _, p := range packets {
		if err := w.WritePacket(p); err != nil { return err }
	}
	return nil
}

// ExportTimeRange exports all packets in a time range as PCAP
func (e *Engine) ExportTimeRange(start, end time.Time, destPath string, threatOnly bool) (int, error) {
	all := e.ring.Read(e.ring.size())
	w, err := newPCAPWriter(destPath)
	if err != nil { return 0, err }
	defer w.Close()

	count := 0
	for _, p := range all {
		if p.Timestamp.Before(start) || p.Timestamp.After(end) { continue }
		if threatOnly && p.ThreatScore < 30 { continue }
		w.WritePacket(p)
		count++
	}
	return count, nil
}

// Cleanup removes PCAP files older than RetentionDays
func (e *Engine) Cleanup() error {
	cutoff := time.Now().AddDate(0, 0, -e.cfg.RetentionDays)
	return filepath.Walk(e.cfg.StorePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() { return nil }
		if filepath.Ext(path) == ".pcap" && info.ModTime().Before(cutoff) {
			os.Remove(path)
		}
		return nil
	})
}

func (rb *RingBuffer) size() int { return int(rb.size) }

// GetStats returns capture statistics
func (e *Engine) GetStats() Stats { return e.stats }

// SetOnCapture sets a real-time packet callback
func (e *Engine) SetOnCapture(fn func(Packet)) { e.onCapture = fn }

// SetOnSession sets a session-close callback
func (e *Engine) SetOnSession(fn func(Session)) { e.onSession = fn }

// Stop gracefully shuts down the capture engine
func (e *Engine) Stop() {
	e.cancel()
	e.writers.Range(func(_, v interface{}) bool {
		if w, ok := v.(*PCAPWriter); ok && w != nil { w.Close() }
		return true
	})
}

// HexDump returns a formatted hex dump of a payload (for UI display)
func HexDump(data []byte, maxBytes int) string {
	if len(data) > maxBytes { data = data[:maxBytes] }
	return hex.Dump(data)
}
