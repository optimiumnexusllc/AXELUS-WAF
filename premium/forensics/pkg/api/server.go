// IronWall-WAF — Forensics REST API
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/optimiumnexusllc/ironwall/premium/forensics/pkg/analyzer"
	"github.com/optimiumnexusllc/ironwall/premium/forensics/pkg/capture"
)

type Server struct {
	engine   *capture.Engine
	analyzer *analyzer.Analyzer
	storePath string
}

func New(eng *capture.Engine, an *analyzer.Analyzer, storePath string) *Server {
	return &Server{engine: eng, analyzer: an, storePath: storePath}
}

func (s *Server) Register(rg *gin.RouterGroup) {
	f := rg.Group("/forensics")

	// Live capture stats
	f.GET("/stats",         s.getStats)
	f.GET("/packets/live",  s.getLivePackets)

	// Sessions
	f.GET("/sessions",           s.listSessions)
	f.GET("/sessions/:id",       s.getSession)
	f.GET("/sessions/:id/pcap",  s.downloadSessionPCAP)
	f.GET("/sessions/:id/replay",s.replaySession)
	f.POST("/sessions/:id/close",s.closeSession)

	// Timelines
	f.GET("/timelines",          s.listTimelines)
	f.POST("/timelines",         s.buildTimeline)
	f.GET("/timelines/:id",      s.getTimeline)

	// Evidence packages
	f.POST("/evidence",          s.createEvidencePackage)
	f.GET("/evidence/:id",       s.downloadEvidence)
	f.GET("/evidence/:id/manifest", s.getEvidenceManifest)

	// PCAP file management
	f.GET("/pcap/files",         s.listPCAPFiles)
	f.GET("/pcap/files/:name",   s.downloadPCAP)
	f.DELETE("/pcap/cleanup",    s.cleanupOldPCAPs)

	// Search & filter
	f.POST("/search",            s.searchEvents)
}

// GET /forensics/stats
func (s *Server) getStats(c *gin.Context) {
	stats := s.engine.GetStats()
	c.JSON(http.StatusOK, gin.H{
		"packets_captured":  stats.PacketsCaptured,
		"packets_dropped":   stats.PacketsDropped,
		"bytes_captured":    stats.BytesCaptured,
		"bytes_human":       humanBytes(stats.BytesCaptured),
		"sessions_tracked":  stats.SessionsTracked,
		"threat_packets":    stats.ThreatPackets,
		"pcap_files":        stats.PCAPFilesWritten,
		"ring_buffer_used":  s.engine.RingUsed(),
	})
}

// GET /forensics/packets/live?limit=100&threat_only=true
func (s *Server) getLivePackets(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit > 1000 { limit = 1000 }
	threatOnly := c.Query("threat_only") == "true"

	packets := s.engine.ReadRecent(limit)
	if threatOnly {
		var filtered []capture.Packet
		for _, p := range packets {
			if p.ThreatScore >= 30 { filtered = append(filtered, p) }
		}
		packets = filtered
	}

	// Sanitise payload for API response
	type PacketView struct {
		Timestamp   time.Time `json:"timestamp"`
		SrcIP       string    `json:"src_ip"`
		DstIP       string    `json:"dst_ip"`
		SrcPort     uint16    `json:"src_port"`
		DstPort     uint16    `json:"dst_port"`
		Protocol    string    `json:"protocol"`
		Direction   string    `json:"direction"`
		PayloadLen  int       `json:"payload_bytes"`
		ThreatScore int       `json:"threat_score"`
		Tags        []string  `json:"tags"`
		SessionID   string    `json:"session_id"`
		HexSnippet  string    `json:"hex_snippet,omitempty"`
	}

	views := make([]PacketView, 0, len(packets))
	for _, p := range packets {
		v := PacketView{
			Timestamp:   p.Timestamp,
			SrcIP:       p.SrcIP.String(),
			DstIP:       p.DstIP.String(),
			SrcPort:     p.SrcPort,
			DstPort:     p.DstPort,
			Protocol:    p.Protocol,
			Direction:   string(p.Direction),
			PayloadLen:  len(p.Payload),
			ThreatScore: p.ThreatScore,
			Tags:        p.Tags,
			SessionID:   p.SessionID,
		}
		if p.ThreatScore >= 60 && len(p.Payload) > 0 {
			v.HexSnippet = capture.HexDump(p.Payload, 64)
		}
		views = append(views, v)
	}
	c.JSON(http.StatusOK, gin.H{"count": len(views), "packets": views})
}

// GET /forensics/sessions
func (s *Server) listSessions(c *gin.Context) {
	sessions := s.engine.ListSessions()
	c.JSON(http.StatusOK, gin.H{"count": len(sessions), "sessions": sessions})
}

// GET /forensics/sessions/:id
func (s *Server) getSession(c *gin.Context) {
	sess := s.engine.GetSession(c.Param("id"))
	if sess == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, sess)
}

// GET /forensics/sessions/:id/pcap → download .pcap file
func (s *Server) downloadSessionPCAP(c *gin.Context) {
	id := c.Param("id")
	dest := filepath.Join(s.storePath, fmt.Sprintf("session-%s.pcap", id))
	if err := s.engine.ExportSession(id, dest); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.FileAttachment(dest, fmt.Sprintf("ironwall-session-%s.pcap", id))
}

// GET /forensics/sessions/:id/replay
func (s *Server) replaySession(c *gin.Context) {
	id := c.Param("id")
	packets := s.engine.GetSessionPackets(id)
	if len(packets) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no packets for session"})
		return
	}
	replay := s.analyzer.ReplaySession(packets)
	c.JSON(http.StatusOK, replay)
}

// POST /forensics/sessions/:id/close
func (s *Server) closeSession(c *gin.Context) {
	sess := s.engine.CloseSession(c.Param("id"))
	if sess == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}
	c.JSON(http.StatusOK, sess)
}

// GET /forensics/timelines
func (s *Server) listTimelines(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(s.storePath, "tl-*.json"))
	c.JSON(http.StatusOK, gin.H{"count": len(files), "timelines": files})
}

// POST /forensics/timelines
func (s *Server) buildTimeline(c *gin.Context) {
	var body struct {
		Events []analyzer.AttackEvent `json:"events"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tl := s.analyzer.BuildTimeline(body.Events)
	if tl == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no events provided"})
		return
	}
	c.JSON(http.StatusCreated, tl)
}

// GET /forensics/timelines/:id
func (s *Server) getTimeline(c *gin.Context) {
	path := filepath.Join(s.storePath, c.Param("id")+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "timeline not found"})
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}

// POST /forensics/evidence
func (s *Server) createEvidencePackage(c *gin.Context) {
	var body struct {
		IncidentID  string                 `json:"incident_id" binding:"required"`
		Description string                 `json:"description"`
		CreatedBy   string                 `json:"created_by"`
		Events      []analyzer.AttackEvent `json:"events"`
		PCAPPaths   []string               `json:"pcap_paths"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var tl *analyzer.Timeline
	if len(body.Events) > 0 { tl = s.analyzer.BuildTimeline(body.Events) }

	pkg, zipPath, err := s.analyzer.PackageEvidence(
		body.IncidentID, body.Description, body.CreatedBy,
		tl, body.PCAPPaths, nil,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"package":   pkg,
		"zip_path":  zipPath,
		"download":  fmt.Sprintf("/api/open/forensics/evidence/%s", pkg.ID),
	})
}

// GET /forensics/evidence/:id → download zip
func (s *Server) downloadEvidence(c *gin.Context) {
	id := c.Param("id")
	path := filepath.Join(s.storePath, id+".zip")
	if _, err := os.Stat(path); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "evidence package not found"})
		return
	}
	c.FileAttachment(path, id+".zip")
}

// GET /forensics/evidence/:id/manifest
func (s *Server) getEvidenceManifest(c *gin.Context) {
	path := filepath.Join(s.storePath, c.Param("id")+".zip.manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "manifest not found"})
		return
	}
	c.Data(http.StatusOK, "application/json", data)
}

// GET /forensics/pcap/files
func (s *Server) listPCAPFiles(c *gin.Context) {
	files, _ := filepath.Glob(filepath.Join(s.storePath, "*.pcap"))
	type FileInfo struct {
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		SizeHuman string  `json:"size_human"`
		ModTime time.Time `json:"modified"`
	}
	var infos []FileInfo
	for _, f := range files {
		if stat, err := os.Stat(f); err == nil {
			infos = append(infos, FileInfo{
				Name:      filepath.Base(f),
				Size:      stat.Size(),
				SizeHuman: humanBytes(stat.Size()),
				ModTime:   stat.ModTime(),
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"count": len(infos), "files": infos})
}

// GET /forensics/pcap/files/:name
func (s *Server) downloadPCAP(c *gin.Context) {
	name := filepath.Base(c.Param("name")) // sanitise path
	path := filepath.Join(s.storePath, name)
	if _, err := os.Stat(path); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}
	c.FileAttachment(path, name)
}

// DELETE /forensics/pcap/cleanup
func (s *Server) cleanupOldPCAPs(c *gin.Context) {
	if err := s.engine.Cleanup(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "old PCAP files cleaned up"})
}

// POST /forensics/search
func (s *Server) searchEvents(c *gin.Context) {
	var body struct {
		SourceIP   string    `json:"source_ip"`
		AttackType string    `json:"attack_type"`
		Severity   string    `json:"severity"`
		Since      time.Time `json:"since"`
		Until      time.Time `json:"until"`
		Limit      int       `json:"limit"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Limit == 0 || body.Limit > 1000 { body.Limit = 100 }
	c.JSON(http.StatusOK, gin.H{"message": "search endpoint — connect to event store"})
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit { return fmt.Sprintf("%d B", b) }
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit { div *= unit; exp++ }
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
