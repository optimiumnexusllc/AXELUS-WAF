// AXELUS-WAF — Compliance REST API & Report Generator
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package engine

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// ── REST API ──────────────────────────────────────────────────────────────────

type ComplianceAPI struct {
	engine   *AssessmentEngine
	library  *ControlLibrary
	monitor  *ComplianceMonitor
}

func NewComplianceAPI(engine *AssessmentEngine, library *ControlLibrary, monitor *ComplianceMonitor) *ComplianceAPI {
	return &ComplianceAPI{engine: engine, library: library, monitor: monitor}
}

func (a *ComplianceAPI) Register(rg *gin.RouterGroup) {
	c := rg.Group("/compliance")

	// Standards
	c.GET("/standards",                 a.listStandards)
	c.GET("/standards/:id/controls",    a.listControls)
	c.GET("/controls/:id",              a.getControl)

	// Assessment
	c.POST("/assess",                   a.runAssessment)
	c.POST("/assess/all",               a.runAllAssessments)
	c.GET("/reports",                   a.listReports)
	c.GET("/reports/:id",               a.getReport)
	c.GET("/reports/:id/html",          a.getReportHTML)
	c.GET("/reports/:id/export",        a.exportReport)

	// Gap analysis
	c.GET("/gaps/:tenant_id",           a.getGapAnalysis)
	c.GET("/dashboard/:tenant_id",      a.getDashboard)

	// Exceptions
	c.POST("/exceptions",               a.createException)
	c.GET("/exceptions/:tenant_id",     a.listExceptions)
	c.DELETE("/exceptions/:id",         a.revokeException)

	// Health
	c.GET("/health",                    a.health)
}

func (a *ComplianceAPI) listStandards(c *gin.Context) {
	type StandardInfo struct {
		ID           StandardID `json:"id"`
		Name         string     `json:"name"`
		ControlCount int        `json:"control_count"`
		Category     string     `json:"category"`
		Region       string     `json:"region"`
	}
	counts := a.library.Count()
	standards := []StandardInfo{
		{StdPCIDSS,   "PCI DSS v4.0",         counts[StdPCIDSS],   "Payment Security", "Global"},
		{StdISO27001, "ISO/IEC 27001:2022",    counts[StdISO27001], "ISMS",             "Global"},
		{StdSOC2,     "SOC 2 Type II",         counts[StdSOC2],     "Trust Services",   "US"},
		{StdNISTCSF,  "NIST CSF 2.0",          counts[StdNISTCSF],  "Cybersecurity",    "US/Global"},
		{StdGDPR,     "GDPR",                  counts[StdGDPR],     "Privacy",          "EU"},
		{StdHIPAA,    "HIPAA Security Rule",    counts[StdHIPAA],    "Healthcare",       "US"},
		{StdCISv8,    "CIS Controls v8",        counts[StdCISv8],    "Best Practices",   "Global"},
		{StdNIS2,     "NIS2 Directive",         counts[StdNIS2],     "Critical Infra",   "EU"},
		{StdOWASP,    "OWASP Top 10 (2021)",    counts[StdOWASP],    "Web Security",     "Global"},
		{StdFedRAMP,  "FedRAMP High",           counts[StdFedRAMP],  "Government",       "US"},
	}
	total := 0
	for _, s := range standards { total += s.ControlCount }
	c.JSON(http.StatusOK, gin.H{
		"standards": standards,
		"count":     len(standards),
		"total_controls": total,
		"publisher": "OPTIMIUM NEXUS LLC — AXELUS-WAF Compliance Engine",
	})
}

func (a *ComplianceAPI) listControls(c *gin.Context) {
	std := StandardID(c.Param("id"))
	controls := a.library.GetByStandard(std)
	if len(controls) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Standard not found: " + string(std)}); return
	}

	// Filter by category/severity
	cat := c.Query("category")
	sev := c.Query("severity")
	automated := c.Query("automated")

	filtered := controls[:0]
	for _, ctrl := range controls {
		if cat != "" && ctrl.Category != cat { continue }
		if sev != "" && string(ctrl.Severity) != sev { continue }
		if automated == "true" && !ctrl.Automated { continue }
		if automated == "false" && ctrl.Automated { continue }
		filtered = append(filtered, ctrl)
	}

	c.JSON(http.StatusOK, gin.H{
		"standard": string(std),
		"count":    len(filtered),
		"controls": filtered,
	})
}

func (a *ComplianceAPI) getControl(c *gin.Context) {
	ctrl, ok := a.library.Get(c.Param("id"))
	if !ok { c.JSON(http.StatusNotFound, gin.H{"error": "Control not found"}); return }
	c.JSON(http.StatusOK, ctrl)
}

func (a *ComplianceAPI) runAssessment(c *gin.Context) {
	var body struct {
		TenantID   string     `json:"tenant_id"   binding:"required"`
		StandardID StandardID `json:"standard_id" binding:"required"`
		AssessedBy string     `json:"assessed_by"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	if body.AssessedBy == "" { body.AssessedBy = c.GetHeader("X-User-ID") }

	report, err := a.engine.Assess(body.TenantID, body.StandardID, body.AssessedBy)
	if err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return }

	c.JSON(http.StatusCreated, gin.H{
		"report_id":           report.ID,
		"standard":            report.StandardName,
		"overall_score":       report.OverallScore,
		"certification_ready": report.CertificationReady,
		"compliant":           report.CompliantCount,
		"partial":             report.PartialCount,
		"non_compliant":       report.NonCompliantCount,
		"critical_findings":   report.CriticalFindings,
		"generated_at":        report.GeneratedAt,
		"next_audit":          report.NextAuditDate,
		"report":              report,
	})
}

func (a *ComplianceAPI) runAllAssessments(c *gin.Context) {
	var body struct {
		TenantID string `json:"tenant_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}

	allStds := []StandardID{
		StdPCIDSS, StdISO27001, StdSOC2, StdNISTCSF, StdGDPR,
		StdHIPAA, StdCISv8, StdNIS2, StdOWASP, StdFedRAMP,
	}
	type Summary struct {
		StandardID  StandardID `json:"standard_id"`
		Name        string     `json:"name"`
		Score       float64    `json:"score"`
		Status      string     `json:"status"`
		Compliant   int        `json:"compliant"`
		NonCompliant int       `json:"non_compliant"`
		Critical    int        `json:"critical_findings"`
		ReportID    string     `json:"report_id"`
	}

	summaries := make([]Summary, 0, len(allStds))
	overallAvg := 0.0

	for _, std := range allStds {
		report, err := a.engine.Assess(body.TenantID, std, "auto")
		if err != nil { continue }
		status := "attention_required"
		if report.CertificationReady { status = "certification_ready" }
		summaries = append(summaries, Summary{
			StandardID:   std,
			Name:         report.StandardName,
			Score:        report.OverallScore,
			Status:       status,
			Compliant:    report.CompliantCount,
			NonCompliant: report.NonCompliantCount,
			Critical:     report.CriticalFindings,
			ReportID:     report.ID,
		})
		overallAvg += report.OverallScore
	}

	if len(summaries) > 0 { overallAvg /= float64(len(summaries)) }

	c.JSON(http.StatusCreated, gin.H{
		"tenant_id":      body.TenantID,
		"assessed_at":    time.Now(),
		"standards_count": len(summaries),
		"overall_average": fmt.Sprintf("%.1f", overallAvg),
		"summaries":      summaries,
	})
}

func (a *ComplianceAPI) listReports(c *gin.Context) {
	tenantID := c.Query("tenant_id")
	std      := c.Query("standard_id")
	_ = tenantID; _ = std
	// In production: query DB
	c.JSON(http.StatusOK, gin.H{"message": "Connect to PostgreSQL for report history"})
}

func (a *ComplianceAPI) getReport(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Report " + c.Param("id") + " — connect to PostgreSQL"})
}

func (a *ComplianceAPI) getReportHTML(c *gin.Context) {
	// Generate sample HTML report
	html := generateSampleHTMLReport()
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

func (a *ComplianceAPI) exportReport(c *gin.Context) {
	c.Header("Content-Disposition", "attachment; filename=axelus-compliance-report-"+c.Param("id")+".json")
	c.JSON(http.StatusOK, gin.H{"report_id": c.Param("id"), "export_format": "json"})
}

func (a *ComplianceAPI) getGapAnalysis(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	std := StandardID(c.Query("standard_id"))
	if std == "" { std = StdPCIDSS }

	controls := a.library.GetByStandard(std)
	type Gap struct {
		ControlID   string          `json:"control_id"`
		Title       string          `json:"title"`
		Severity    ControlSeverity `json:"severity"`
		WAFFeature  string          `json:"waf_feature"`
		Priority    int             `json:"priority"`
	}
	gaps := make([]Gap, 0)
	for _, ctrl := range controls {
		if !ctrl.Automated {
			gaps = append(gaps, Gap{
				ControlID:  ctrl.ID,
				Title:      ctrl.Title,
				Severity:   ctrl.Severity,
				WAFFeature: ctrl.WAFFeature,
				Priority:   severityPriority(ctrl.Severity),
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"tenant_id":  tenantID,
		"standard":   string(std),
		"gap_count":  len(gaps),
		"gaps":       gaps,
		"generated_at": time.Now(),
	})
}

func (a *ComplianceAPI) getDashboard(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	counts := a.library.Count()
	c.JSON(http.StatusOK, gin.H{
		"tenant_id":   tenantID,
		"standards":   len(counts),
		"total_controls": func() int { n := 0; for _, v := range counts { n += v }; return n }(),
		"coverage_summary": gin.H{
			"pci_dss":   counts[StdPCIDSS],
			"iso_27001": counts[StdISO27001],
			"soc2":      counts[StdSOC2],
			"nist_csf":  counts[StdNISTCSF],
			"gdpr":      counts[StdGDPR],
			"hipaa":     counts[StdHIPAA],
			"cis_v8":    counts[StdCISv8],
			"nis2":      counts[StdNIS2],
			"owasp":     counts[StdOWASP],
			"fedramp":   counts[StdFedRAMP],
		},
		"engine": "AXELUS-WAF Compliance Engine v1.0 — OPTIMIUM NEXUS LLC",
	})
}

func (a *ComplianceAPI) createException(c *gin.Context) {
	var ex ComplianceException
	if err := c.ShouldBindJSON(&ex); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	ex.IsActive = true
	if a.engine.db != nil { a.engine.db.Create(&ex) }
	c.JSON(http.StatusCreated, gin.H{"exception": ex, "message": "Exception created — will be reflected in next assessment"})
}

func (a *ComplianceAPI) listExceptions(c *gin.Context) {
	var exceptions []ComplianceException
	if a.engine.db != nil {
		a.engine.db.Where("tenant_id = ? AND is_active = true", c.Param("tenant_id")).Find(&exceptions)
	}
	c.JSON(http.StatusOK, gin.H{"count": len(exceptions), "exceptions": exceptions})
}

func (a *ComplianceAPI) revokeException(c *gin.Context) {
	if a.engine.db != nil {
		a.engine.db.Model(&ComplianceException{}).Where("id = ?", c.Param("id")).Update("is_active", false)
	}
	c.JSON(http.StatusOK, gin.H{"message": "Exception revoked"})
}

func (a *ComplianceAPI) health(c *gin.Context) {
	counts := a.library.Count()
	total := 0
	for _, v := range counts { total += v }
	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"standards":      len(counts),
		"total_controls": total,
		"engine_version": "1.0.0",
		"publisher":      "OPTIMIUM NEXUS LLC",
	})
}

// ── HTML Report Template ──────────────────────────────────────────────────────

const reportHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>{{.StandardName}} Compliance Report — {{.TenantID}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f4f8;color:#1a2840;font-size:13px;line-height:1.6}
.page{max-width:1000px;margin:0 auto;padding:32px 24px}
.header{background:linear-gradient(135deg,#07090f,#0d1428);color:#fff;padding:32px 36px;border-radius:12px;margin-bottom:28px;position:relative;overflow:hidden}
.header::after{content:'';position:absolute;top:-20px;right:-20px;width:180px;height:180px;border:40px solid rgba(0,200,255,.06);border-radius:50%}
.logo{font-size:22px;font-weight:700;font-family:monospace;letter-spacing:2px;color:#00c8ff;margin-bottom:4px}
.logo-sub{font-size:10px;letter-spacing:3px;color:#4aa8d8;margin-bottom:24px}
h1{font-size:24px;font-weight:700;margin-bottom:6px}
.meta{color:#aac;font-size:12px}
.score-hero{display:grid;grid-template-columns:auto 1fr;gap:24px;align-items:center;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:20px 24px;margin-top:20px}
.score-num{font-size:64px;font-weight:700;font-family:monospace;color:#00c8ff;line-height:1}
.score-label{font-size:11px;letter-spacing:2px;color:#4aa8d8;margin-bottom:4px}
.badge{display:inline-block;padding:4px 14px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1px}
.badge-pass{background:rgba(0,230,118,.15);color:#00e676;border:1px solid rgba(0,230,118,.3)}
.badge-warn{background:rgba(255,145,0,.15);color:#ff9100;border:1px solid rgba(255,145,0,.3)}
.badge-fail{background:rgba(255,23,68,.15);color:#ff1744;border:1px solid rgba(255,23,68,.3)}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}
.card{background:#fff;border-radius:10px;padding:16px;border:1px solid #dde6f0;text-align:center}
.card-num{font-size:32px;font-weight:700;font-family:monospace;margin-bottom:4px}
.card-label{font-size:10px;letter-spacing:1.5px;color:#7a8fa8;text-transform:uppercase}
.green{color:#00994d}.orange{color:#cc7700}.red{color:#cc1133}.blue{color:#1155aa}.gray{color:#5a7a9a}
.section{background:#fff;border-radius:10px;padding:20px 24px;border:1px solid #dde6f0;margin-bottom:20px}
h2{font-size:14px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#1a2840;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid #f0f4f8}
.control-row{display:grid;grid-template-columns:130px 1fr 80px 100px 60px;gap:10px;padding:10px 0;border-bottom:1px solid #f0f4f8;align-items:center}
.control-row:last-child{border:none}
.ctrl-id{font-family:monospace;font-size:11px;font-weight:700;color:#1155aa}
.ctrl-title{font-size:12px;color:#1a2840}
.ctrl-cat{font-size:10px;color:#7a8fa8}
.status-pill{display:inline-block;padding:3px 10px;border-radius:10px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.s-compliant{background:#ecfdf5;color:#059669}
.s-partial{background:#fffbeb;color:#d97706}
.s-non_compliant{background:#fef2f2;color:#dc2626}
.s-not_applicable{background:#f8fafc;color:#94a3b8}
.s-unknown{background:#f1f5f9;color:#64748b}
.progress{height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden;margin-top:4px}
.pfill{height:100%;border-radius:3px}
.sev-badge{display:inline-block;font-size:8px;padding:2px 6px;border-radius:3px;font-weight:700;letter-spacing:.5px}
.sev-critical{background:#fef2f2;color:#dc2626}
.sev-high{background:#fffbeb;color:#d97706}
.sev-medium{background:#eff6ff;color:#2563eb}
.sev-low{background:#f0fdf4;color:#059669}
.xref{font-size:9px;color:#94a3b8;font-family:monospace}
.finding-box{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 16px;margin-top:8px}
.finding-title{font-weight:600;color:#dc2626;font-size:12px}
.finding-desc{font-size:11px;color:#7f1d1d;margin-top:3px}
.rem-box{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px 16px;margin-top:6px}
.rem-title{font-weight:600;color:#1d4ed8;font-size:11px}
.rem-step{font-size:11px;color:#1e3a5f;padding:2px 0;display:flex;gap:6px}
.footer{text-align:center;padding:24px;color:#94a3b8;font-size:11px;border-top:1px solid #e2e8f0;margin-top:32px}
.summary-bar{height:20px;display:flex;border-radius:10px;overflow:hidden;margin-bottom:12px}
.bar-c{background:#059669}.bar-p{background:#d97706}.bar-n{background:#dc2626}.bar-na{background:#e2e8f0}
@media print{body{background:#fff}.page{padding:20px}}
</style>
</head>
<body>
<div class="page">

<div class="header">
  <div class="logo">AXELUS</div>
  <div class="logo-sub">WEB APPLICATION FIREWALL — OPTIMIUM NEXUS LLC</div>
  <h1>{{.StandardName}}</h1>
  <div style="font-size:15px;color:#aac;margin-bottom:16px">Compliance Assessment Report</div>
  <div class="meta">Tenant: {{.TenantID}} &nbsp;·&nbsp; Period: {{.Period}} &nbsp;·&nbsp; Generated: {{.GeneratedAt}} &nbsp;·&nbsp; Auditor: {{.Auditor}}</div>

  <div class="score-hero">
    <div>
      <div class="score-label">Overall Score</div>
      <div class="score-num">{{printf "%.0f" .OverallScore}}</div>
      <div style="color:#4aa8d8;font-size:12px">/ 100</div>
    </div>
    <div>
      <div style="margin-bottom:10px">
        {{if .CertificationReady}}
          <span class="badge badge-pass">CERTIFICATION READY</span>
        {{else}}
          <span class="badge badge-warn">ATTENTION REQUIRED</span>
        {{end}}
      </div>
      <div style="color:#ccc;font-size:12px;line-height:1.8">
        {{.ExecutiveSummary}}
      </div>
    </div>
  </div>
</div>

<div class="cards">
  <div class="card"><div class="card-num green">{{.CompliantCount}}</div><div class="card-label">Compliant</div></div>
  <div class="card"><div class="card-num orange">{{.PartialCount}}</div><div class="card-label">Partial</div></div>
  <div class="card"><div class="card-num red">{{.NonCompliantCount}}</div><div class="card-label">Non-Compliant</div></div>
  <div class="card"><div class="card-num gray">{{.NACount}}</div><div class="card-label">N/A</div></div>
  <div class="card"><div class="card-num blue">{{.TotalControls}}</div><div class="card-label">Total Controls</div></div>
</div>

<div class="section">
  <h2>Control Compliance Overview</h2>
  {{$total := .TotalControls}}
  <div class="summary-bar">
    <div class="bar-c" style="width:{{pct .CompliantCount $total}}%"></div>
    <div class="bar-p" style="width:{{pct .PartialCount $total}}%"></div>
    <div class="bar-n" style="width:{{pct .NonCompliantCount $total}}%"></div>
    <div class="bar-na" style="flex:1"></div>
  </div>
  <div style="display:flex;gap:20px;font-size:11px;color:#64748b">
    <span><span style="color:#059669">■</span> Compliant ({{printf "%.0f" (pct .CompliantCount $total)}}%)</span>
    <span><span style="color:#d97706">■</span> Partial ({{printf "%.0f" (pct .PartialCount $total)}}%)</span>
    <span><span style="color:#dc2626">■</span> Non-Compliant ({{printf "%.0f" (pct .NonCompliantCount $total)}}%)</span>
    <span><span style="color:#94a3b8">■</span> N/A</span>
  </div>
</div>

{{if .Results}}
<div class="section">
  <h2>Control Assessment Results</h2>
  <div style="font-size:10px;color:#94a3b8;display:grid;grid-template-columns:130px 1fr 80px 100px 60px;gap:10px;padding:4px 0;margin-bottom:4px">
    <span>CONTROL ID</span><span>TITLE</span><span>CATEGORY</span><span>STATUS</span><span>SCORE</span>
  </div>
  {{range .Results}}
  <div class="control-row">
    <div>
      <div class="ctrl-id">{{.ControlID}}</div>
    </div>
    <div>
      <div class="ctrl-title"></div>
      {{if .Findings}}
      {{range .Findings}}
      <div class="finding-box">
        <div class="finding-title">{{.Title}}</div>
        <div class="finding-desc">{{.Description}}</div>
      </div>
      {{end}}
      {{end}}
      {{if .Remediation}}
      <div class="rem-box">
        <div class="rem-title">Remediation Steps (Est. {{.Remediation.EstDays}} days):</div>
        {{range .Remediation.Steps}}
        <div class="rem-step"><span>→</span><span>{{.}}</span></div>
        {{end}}
      </div>
      {{end}}
    </div>
    <div></div>
    <div><span class="status-pill s-{{.Status}}">{{.Status}}</span></div>
    <div style="font-family:monospace;font-weight:700;{{if ge .Score 90.0}}color:#059669{{else if ge .Score 60.0}}color:#d97706{{else}}color:#dc2626{{end}}">{{printf "%.0f" .Score}}</div>
  </div>
  {{end}}
</div>
{{end}}

<div class="footer">
  <strong>AXELUS-WAF</strong> Compliance Assessment Report &nbsp;·&nbsp; {{.StandardName}} &nbsp;·&nbsp;
  Generated {{.GeneratedAt}} by OPTIMIUM NEXUS LLC Automated Audit Engine<br/>
  This report is confidential. Next assessment due: {{.NextAuditDate}}<br/>
  <a href="https://www.optimiumnexus.com" style="color:#3b82f6">www.optimiumnexus.com</a> &nbsp;·&nbsp;
  <a href="mailto:contact@optimiumnexus.com" style="color:#3b82f6">contact@optimiumnexus.com</a>
</div>
</div>
</body>
</html>`

// GenerateHTMLReport produces a full HTML compliance report
func GenerateHTMLReport(report *ComplianceReport) (string, error) {
	funcMap := template.FuncMap{
		"pct": func(a, b int) float64 {
			if b == 0 { return 0 }
			return float64(a) / float64(b) * 100
		},
		"scoreColor": func(score float64) string {
			if score >= 90 { return "#059669" }
			if score >= 60 { return "#d97706" }
			return "#dc2626"
		},
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportHTMLTemplate)
	if err != nil { return "", fmt.Errorf("template parse: %w", err) }

	data := struct {
		*ComplianceReport
		GeneratedAt   string
		NextAuditDate string
	}{
		ComplianceReport: report,
		GeneratedAt:      report.GeneratedAt.Format("2006-01-02 15:04 UTC"),
		NextAuditDate:    report.NextAuditDate.Format("2006-01-02"),
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil { return "", err }
	return buf.String(), nil
}

func generateSampleHTMLReport() string {
	report := &ComplianceReport{
		TenantID:         "demo-tenant",
		StandardName:     "PCI DSS v4.0",
		StandardID:       StdPCIDSS,
		GeneratedAt:      time.Now().UTC(),
		AssessedBy:       "auto",
		Period:           time.Now().AddDate(0,-3,0).Format("2006-01-02") + " to " + time.Now().Format("2006-01-02"),
		OverallScore:     87.5,
		CompliantCount:   14,
		PartialCount:     2,
		NonCompliantCount: 1,
		NACount:          0,
		TotalControls:    17,
		CriticalFindings: 0,
		HighFindings:     1,
		MediumFindings:   1,
		LowFindings:      0,
		CertificationReady: true,
		NextAuditDate:    time.Now().AddDate(0,3,0),
		Auditor:          "AXELUS-WAF Automated Audit Engine v1.0",
		ExecutiveSummary: "PCI DSS v4.0 assessment for demo-tenant completed. Overall score: 88/100. 14 compliant, 2 partial, 1 non-compliant out of 17 controls. 0 critical findings. Certification status: CERTIFICATION READY.",
	}
	html, err := GenerateHTMLReport(report)
	if err != nil { return "<html><body>Error generating report</body></html>" }
	return html
}

// StandardsBreakdownText returns a human-readable summary of all standards
func StandardsBreakdownText(lib *ControlLibrary) string {
	counts := lib.Count()
	var sb strings.Builder
	sb.WriteString("AXELUS-WAF Compliance Coverage:\n")
	for std, count := range counts {
		sb.WriteString(fmt.Sprintf("  %-20s %d controls\n", standardName(std), count))
	}
	return sb.String()
}
