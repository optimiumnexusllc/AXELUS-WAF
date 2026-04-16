// AXELUS-WAF — Forensics Analyzer
// Reconstructs attack timelines, correlates sessions, builds evidence packages.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package analyzer

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/optimiumnexusllc/axelus/premium/forensics/pkg/capture"
)

// ── Attack Event ──────────────────────────────────────────────────────────────

type AttackEvent struct {
	ID          string             `json:"id"`
	Timestamp   time.Time          `json:"timestamp"`
	AttackType  string             `json:"attack_type"`
	Severity    string             `json:"severity"`
	SourceIP    string             `json:"source_ip"`
	SourceCountry string           `json:"source_country,omitempty"`
	TargetHost  string             `json:"target_host"`
	TargetPath  string             `json:"target_path"`
	Method      string             `json:"method"`
	StatusCode  int                `json:"status_code"`
	Blocked     bool               `json:"blocked"`
	SessionID   string             `json:"session_id"`
	Payload     string             `json:"payload_snippet"` // sanitised
	PayloadHash string             `json:"payload_hash"`    // SHA-256
	RuleIDs     []string           `json:"rule_ids"`
	CVSS        float64            `json:"cvss,omitempty"`
	CVE         string             `json:"cve,omitempty"`
	MITREPhase  string             `json:"mitre_phase,omitempty"`
	Packets     []capture.Packet   `json:"-"` // raw packets
}

// ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

var MITREMapping = map[string]string{
	"sql_injection":       "T1190 — Exploit Public-Facing Application",
	"xss":                 "T1059.007 — JavaScript Execution",
	"rce":                 "T1190 + T1059 — Exploit + Execution",
	"path_traversal":      "T1083 — File and Directory Discovery",
	"ssrf":                "T1090 — Proxy / Internal Network Pivot",
	"deserialization":     "T1190 — Exploit Public-Facing Application",
	"xxe":                 "T1190 — XML External Entity",
	"ssti":                "T1190 + T1059 — Template Injection + Execution",
	"ddos":                "T1498 — Network Denial of Service",
	"brute_force":         "T1110 — Brute Force",
	"credential_stuffing": "T1110.004 — Credential Stuffing",
	"honeypot_trigger":    "T1595 — Active Scanning",
	"bot_scan":            "T1595.001 — Scanning IP Blocks",
}

// ── Timeline ──────────────────────────────────────────────────────────────────

type Timeline struct {
	ID         string        `json:"id"`
	SourceIP   string        `json:"source_ip"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   string        `json:"duration"`
	Events     []AttackEvent `json:"events"`
	Summary    Summary       `json:"summary"`
	ThreatActor ThreatActor  `json:"threat_actor"`
}

type Summary struct {
	TotalEvents     int                `json:"total_events"`
	BlockedEvents   int                `json:"blocked_events"`
	UniqueTargets   []string           `json:"unique_targets"`
	AttackTypes     map[string]int     `json:"attack_types"`
	MaxSeverity     string             `json:"max_severity"`
	TotalPayloadKB  float64            `json:"total_payload_kb"`
	RequestsPerMin  float64            `json:"requests_per_min"`
	MITREPhases     []string           `json:"mitre_phases"`
}

type ThreatActor struct {
	IP           string    `json:"ip"`
	Country      string    `json:"country,omitempty"`
	ASN          string    `json:"asn,omitempty"`
	IsVPN        bool      `json:"is_vpn"`
	IsTor        bool      `json:"is_tor"`
	RiskScore    int       `json:"risk_score"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	TotalAttacks int       `json:"total_attacks"`
}

// ── Analyzer ──────────────────────────────────────────────────────────────────

type Analyzer struct {
	storePath string
}

func New(storePath string) *Analyzer {
	os.MkdirAll(storePath, 0750)
	return &Analyzer{storePath: storePath}
}

// BuildTimeline constructs an attack timeline from a set of events
func (a *Analyzer) BuildTimeline(events []AttackEvent) *Timeline {
	if len(events) == 0 { return nil }

	// Sort by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	ip := events[0].SourceIP
	start := events[0].Timestamp
	end := events[len(events)-1].Timestamp
	dur := end.Sub(start)

	// Build summary
	summary := Summary{
		TotalEvents: len(events),
		AttackTypes: make(map[string]int),
	}
	targetSet := make(map[string]bool)
	mitreSet  := make(map[string]bool)
	var totalBytes int64
	severityOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	maxSev := "low"

	for _, ev := range events {
		if ev.Blocked { summary.BlockedEvents++ }
		targetSet[ev.TargetHost] = true
		summary.AttackTypes[ev.AttackType]++
		if sev := severityOrder[ev.Severity]; sev > severityOrder[maxSev] { maxSev = ev.Severity }
		totalBytes += int64(len(ev.Payload))
		if m, ok := MITREMapping[ev.AttackType]; ok { mitreSet[m] = true }
	}
	for t := range targetSet  { summary.UniqueTargets = append(summary.UniqueTargets, t) }
	for m := range mitreSet   { summary.MITREPhases = append(summary.MITREPhases, m) }
	summary.MaxSeverity    = maxSev
	summary.TotalPayloadKB = float64(totalBytes) / 1024.0
	if dur.Minutes() > 0 {
		summary.RequestsPerMin = float64(len(events)) / dur.Minutes()
	}

	tl := &Timeline{
		ID:        fmt.Sprintf("tl-%s-%d", strings.ReplaceAll(ip, ".", "-"), start.Unix()),
		SourceIP:  ip,
		StartTime: start,
		EndTime:   end,
		Duration:  formatDuration(dur),
		Events:    events,
		Summary:   summary,
		ThreatActor: ThreatActor{
			IP:           ip,
			FirstSeen:    start,
			LastSeen:     end,
			TotalAttacks: len(events),
		},
	}

	// Persist timeline
	a.saveTimeline(tl)
	return tl
}

// AnalyzeSession performs deep analysis on a captured session
func (a *Analyzer) AnalyzeSession(sess capture.Session) []AttackEvent {
	var events []AttackEvent
	for _, pkt := range sess.Packets {
		if pkt.ThreatScore < 30 { continue }

		payload := string(pkt.Payload)
		h := sha256.Sum256(pkt.Payload)
		snippet := payload
		if len(snippet) > 500 { snippet = snippet[:500] + "..." }

		attackType := classifyPayload(payload)
		severity := scoreToseverity(pkt.ThreatScore)

		event := AttackEvent{
			ID:          fmt.Sprintf("ev-%x", h[:4]),
			Timestamp:   pkt.Timestamp,
			AttackType:  attackType,
			Severity:    severity,
			SourceIP:    pkt.SrcIP.String(),
			TargetPath:  "/",
			Method:      "GET",
			Blocked:     pkt.ThreatScore >= 60,
			SessionID:   sess.ID,
			Payload:     snippet,
			PayloadHash: fmt.Sprintf("%x", h),
			MITREPhase:  MITREMapping[attackType],
		}
		events = append(events, event)
	}
	return events
}

// ── Evidence Package ──────────────────────────────────────────────────────────

// EvidencePackage is a cryptographically-sealed archive of forensic evidence
type EvidencePackage struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	IncidentID  string    `json:"incident_id"`
	Description string    `json:"description"`
	Files       []EvidenceFile `json:"files"`
	SHA256      string    `json:"sha256"`   // hash of the zip
	ChainOfCustody []CustodyEntry `json:"chain_of_custody"`
}

type EvidenceFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Type   string `json:"type"` // pcap|json|csv|log
}

type CustodyEntry struct {
	Action    string    `json:"action"` // created|accessed|transferred
	Actor     string    `json:"actor"`
	Timestamp time.Time `json:"timestamp"`
	Notes     string    `json:"notes"`
}

// PackageEvidence creates a sealed ZIP evidence package
func (a *Analyzer) PackageEvidence(
	incidentID, description, createdBy string,
	timeline *Timeline,
	pcapPaths []string,
	extraFiles map[string][]byte,
) (*EvidencePackage, string, error) {

	pkg := &EvidencePackage{
		ID:          fmt.Sprintf("ev-pkg-%s-%d", incidentID, time.Now().Unix()),
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
		IncidentID:  incidentID,
		Description: description,
		ChainOfCustody: []CustodyEntry{{
			Action: "created", Actor: createdBy,
			Timestamp: time.Now().UTC(),
			Notes: fmt.Sprintf("Evidence package created for incident %s", incidentID),
		}},
	}

	zipPath := filepath.Join(a.storePath, pkg.ID+".zip")
	zipFile, err := os.Create(zipPath)
	if err != nil { return nil, "", err }
	defer zipFile.Close()

	zw := zip.NewWriter(zipFile)

	// Write timeline JSON
	if timeline != nil {
		tlData, _ := json.MarshalIndent(timeline, "", "  ")
		addToZip(zw, "timeline.json", tlData, pkg)
	}

	// Write manifest
	manifestData, _ := json.MarshalIndent(map[string]interface{}{
		"incident_id": incidentID,
		"created_at":  pkg.CreatedAt,
		"created_by":  createdBy,
		"description": description,
		"publisher":   "OPTIMIUM NEXUS LLC",
		"tool":        "AXELUS-WAF Forensics Engine v1.0",
		"website":     "https://www.optimiumnexus.com",
	}, "", "  ")
	addToZip(zw, "manifest.json", manifestData, pkg)

	// Write PCAP files
	for _, pcapPath := range pcapPaths {
		data, err := os.ReadFile(pcapPath)
		if err != nil { continue }
		addToZip(zw, filepath.Base(pcapPath), data, pkg)
	}

	// Write extra files (logs, reports, etc.)
	for name, data := range extraFiles {
		addToZip(zw, name, data, pkg)
	}

	// Write CSV of events
	if timeline != nil {
		csv := buildEventCSV(timeline.Events)
		addToZip(zw, "events.csv", []byte(csv), pkg)
	}

	zw.Close()

	// Compute package hash
	zipData, _ := os.ReadFile(zipPath)
	h := sha256.Sum256(zipData)
	pkg.SHA256 = fmt.Sprintf("%x", h)

	// Save package manifest
	pkgData, _ := json.MarshalIndent(pkg, "", "  ")
	os.WriteFile(zipPath+".manifest.json", pkgData, 0640)

	return pkg, zipPath, nil
}

func addToZip(zw *zip.Writer, name string, data []byte, pkg *EvidencePackage) {
	w, err := zw.Create(name)
	if err != nil { return }
	w.Write(data)
	h := sha256.Sum256(data)
	pkg.Files = append(pkg.Files, EvidenceFile{
		Name:   name,
		Size:   int64(len(data)),
		SHA256: fmt.Sprintf("%x", h),
		Type:   filepath.Ext(name)[1:],
	})
}

// ── Session Replay ────────────────────────────────────────────────────────────

// ReplaySession reconstructs the HTTP conversation from captured packets
func (a *Analyzer) ReplaySession(packets []capture.Packet) *SessionReplay {
	replay := &SessionReplay{
		StartTime: packets[0].Timestamp,
		EndTime:   packets[len(packets)-1].Timestamp,
	}
	for _, p := range packets {
		entry := ReplayEntry{
			Timestamp: p.Timestamp,
			Direction: string(p.Direction),
			Length:    len(p.Payload),
			HexDump:   capture.HexDump(p.Payload, 256),
			Printable: printablePayload(p.Payload),
		}
		if p.Direction == capture.DirectionInbound {
			replay.Requests = append(replay.Requests, entry)
		} else {
			replay.Responses = append(replay.Responses, entry)
		}
		replay.TotalBytes += int64(len(p.Payload))
	}
	return replay
}

type SessionReplay struct {
	StartTime  time.Time
	EndTime    time.Time
	Requests   []ReplayEntry
	Responses  []ReplayEntry
	TotalBytes int64
}

type ReplayEntry struct {
	Timestamp time.Time
	Direction string
	Length    int
	HexDump   string
	Printable string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (a *Analyzer) saveTimeline(tl *Timeline) {
	data, _ := json.MarshalIndent(tl, "", "  ")
	path := filepath.Join(a.storePath, tl.ID+".json")
	os.WriteFile(path, data, 0640)
}

func classifyPayload(payload string) string {
	pl := strings.ToLower(payload)
	switch {
	case strings.Contains(pl, "union") && strings.Contains(pl, "select"): return "sql_injection"
	case strings.Contains(pl, "<script") || strings.Contains(pl, "javascript:"): return "xss"
	case strings.Contains(pl, "/bin/") || strings.Contains(pl, "cmd.exe"): return "rce"
	case strings.Contains(pl, "../") || strings.Contains(pl, "..\\"):     return "path_traversal"
	case strings.Contains(pl, "169.254.169.254") || strings.Contains(pl, "localhost"): return "ssrf"
	case strings.Contains(pl, "<!entity") || strings.Contains(pl, "<!doctype"): return "xxe"
	case strings.Contains(pl, "{{") && strings.Contains(pl, "}}"): return "ssti"
	case strings.Contains(pl, "$where") || strings.Contains(pl, "$ne"): return "nosql_injection"
	case strings.Contains(pl, "ro0ab"):  return "deserialization"
	default: return "unknown"
	}
}

func scoreToseverity(score int) string {
	switch {
	case score >= 90: return "critical"
	case score >= 70: return "high"
	case score >= 50: return "medium"
	default:          return "low"
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute { return fmt.Sprintf("%ds", int(d.Seconds())) }
	if d < time.Hour   { return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60) }
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func printablePayload(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 { sb.WriteByte(b) } else { sb.WriteByte('.') }
		if sb.Len() > 512 { sb.WriteString("..."); break }
	}
	return sb.String()
}

func buildEventCSV(events []AttackEvent) string {
	var sb strings.Builder
	sb.WriteString("timestamp,attack_type,severity,source_ip,target_host,target_path,blocked,payload_hash,mitre\n")
	for _, ev := range events {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%v,%s,%q\n",
			ev.Timestamp.Format(time.RFC3339),
			ev.AttackType, ev.Severity,
			ev.SourceIP, ev.TargetHost, ev.TargetPath,
			ev.Blocked, ev.PayloadHash, ev.MITREPhase))
	}
	return sb.String()
}

var _ = io.Copy // keep import
