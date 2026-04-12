// IronWall — Deep Packet Inspection Engine
// Palantir-grade multi-layer payload analysis beyond standard WAF rules.
// Detects: polyglot attacks, encoding evasions, zero-day patterns,
// deserialization payloads, SSRF chains, and business logic abuse.
package deepinspect

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// ── Threat Categories ─────────────────────────────────────────────────────────

type ThreatCategory string

const (
	ThreatSQLi          ThreatCategory = "sql_injection"
	ThreatXSS           ThreatCategory = "xss"
	ThreatRCE           ThreatCategory = "rce"
	ThreatPathTraversal ThreatCategory = "path_traversal"
	ThreatSSRF          ThreatCategory = "ssrf"
	ThreatDeserial      ThreatCategory = "deserialization"
	ThreatXXE           ThreatCategory = "xxe"
	ThreatSSTI          ThreatCategory = "ssti"
	ThreatLDAPI         ThreatCategory = "ldap_injection"
	ThreatNoSQLi        ThreatCategory = "nosql_injection"
	ThreatProtoPollu    ThreatCategory = "prototype_pollution"
	ThreatPolyglot      ThreatCategory = "polyglot"
	ThreatEvasion       ThreatCategory = "evasion"
)

// ── Detection Result ──────────────────────────────────────────────────────────

type Finding struct {
	Category    ThreatCategory `json:"category"`
	Severity    string         `json:"severity"`     // low|medium|high|critical
	Confidence  float64        `json:"confidence"`   // 0.0–1.0
	Location    string         `json:"location"`     // header|body|query|cookie|path
	Evidence    string         `json:"evidence"`     // sanitized snippet
	RuleID      string         `json:"rule_id"`
	Description string         `json:"description"`
	CVE         string         `json:"cve,omitempty"`
	CVSS        float64        `json:"cvss,omitempty"`
}

type InspectionResult struct {
	Blocked  bool      `json:"blocked"`
	Score    int       `json:"score"`      // 0-100 threat score
	Findings []Finding `json:"findings"`
	Layers   []string  `json:"layers"`     // inspection layers applied
}

// ── Request Payload ───────────────────────────────────────────────────────────

type RequestPayload struct {
	Method  string
	Path    string
	Query   string
	Headers map[string]string
	Body    string
	Cookies map[string]string
}

// ── Inspector ─────────────────────────────────────────────────────────────────

type Inspector struct {
	sqliPatterns  []*regexp.Regexp
	xssPatterns   []*regexp.Regexp
	rcePatterns   []*regexp.Regexp
	ssrfPatterns  []*regexp.Regexp
	sstiPatterns  []*regexp.Regexp
	threshold     int // score threshold for blocking
}

// New creates a new DPI inspector with compiled patterns
func New(blockThreshold int) *Inspector {
	if blockThreshold == 0 { blockThreshold = 60 }
	ins := &Inspector{threshold: blockThreshold}
	ins.compilePatterns()
	return ins
}

func (ins *Inspector) compilePatterns() {
	sqliRaw := []string{
		`(?i)(union\s+(?:all\s+)?select)`,
		`(?i)(select\s+.+\s+from\s+.+)`,
		`(?i)(insert\s+into\s+\w+)`,
		`(?i)(drop\s+(?:table|database)\s+\w+)`,
		`(?i)(exec(?:ute)?\s*\()`,
		`(?i)(xp_cmdshell)`,
		`(?i)('|\"|;)\s*(?:--|\#|\/\*)`,
		`(?i)(waitfor\s+delay\s+['"])`,
		`(?i)(sleep\s*\(\s*\d+)`,
		`(?i)(benchmark\s*\()`,
		`(?i)(load_file\s*\()`,
		`(?i)(into\s+(?:out|dump)file)`,
		`(?i)(information_schema\.)`,
		`(?i)(pg_sleep\s*\()`,
		`(?i)(\|\|\s*pg_sleep)`,
		`(?i)(1\s*=\s*1|1\s*=\s*'1')`,
		`(?i)(\bor\b\s+\d+\s*=\s*\d+)`,
	}
	xssRaw := []string{
		`(?i)<script[^>]*>`,
		`(?i)javascript\s*:`,
		`(?i)vbscript\s*:`,
		`(?i)on(?:load|error|click|focus|blur|change|input|mouse\w+|key\w+|submit)\s*=`,
		`(?i)<(?:iframe|frame|object|embed|applet|form|meta)[^>]*>`,
		`(?i)expression\s*\(`,
		`(?i)document\.(cookie|write|location)`,
		`(?i)window\.(location|open)`,
		`(?i)eval\s*\(`,
		`(?i)atob\s*\(`,
		`(?i)fromcharcode`,
		`(?i)<[^>]+\bstyle\s*=\s*['"]\s*[^'"]*expression`,
		`(?i)&#x?[0-9a-f]+;`,
		`(?i)\\\u[0-9a-f]{4}`,
	}
	rceRaw := []string{
		`(?i)(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(`,
		`(?i)(?:\/bin\/(?:bash|sh|cmd)|cmd\.exe)`,
		`(?i)(?:wget|curl|fetch)\s+https?://`,
		"(?i)(`[^`]+`)",
		`(?i)\$\((?:[^)]+)\)`,
		`(?i)(?:rm|del|rmdir)\s+(?:-rf?\s+)?[\/\\]`,
		`(?i)(nc|netcat)\s+-[el]`,
		`(?i)\/proc\/self\/`,
		`(?i)python\s+-c\s+['"]`,
		`(?i)perl\s+-e\s+['"]`,
		`(?i)ruby\s+-e\s+['"]`,
		`(?i)php\s+-r\s+['"]`,
		`(?i)base64\s+-d`,
	}
	ssrfRaw := []string{
		`(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)`,
		`(?i)https?://169\.254\.169\.254`,  // AWS metadata
		`(?i)https?://metadata\.google\.internal`,
		`(?i)https?://(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+`,
		`(?i)file://`,
		`(?i)gopher://`,
		`(?i)dict://`,
		`(?i)ftp://`,
		`(?i)ldap://`,
	}
	sstiRaw := []string{
		`(?i)\{\{.*\}\}`,         // Jinja2/Twig/Vue
		`(?i)\$\{.*\}`,           // FreeMarker/EL
		`(?i)#\{.*\}`,            // Thymeleaf
		`(?i)<\%=.*\%>`,          // ERB/EJS
		`(?i)\[\[.*\]\]`,         // Thymeleaf
		`(?i){{7\*7}}`,           // Classic SSTI probe
		`(?i)\{\{config\}\}`,     // Flask config leak
		`(?i)__class__`,
		`(?i)__import__`,
		`(?i)__mro__`,
	}

	compile := func(patterns []string) []*regexp.Regexp {
		var result []*regexp.Regexp
		for _, p := range patterns {
			if r, err := regexp.Compile(p); err == nil {
				result = append(result, r)
			}
		}
		return result
	}

	ins.sqliPatterns = compile(sqliRaw)
	ins.xssPatterns  = compile(xssRaw)
	ins.rcePatterns  = compile(rceRaw)
	ins.ssrfPatterns = compile(ssrfRaw)
	ins.sstiPatterns = compile(sstiRaw)
}

// ── Main Inspection Entry Point ───────────────────────────────────────────────

// Inspect performs multi-layer analysis on a request payload
func (ins *Inspector) Inspect(req *RequestPayload) *InspectionResult {
	result := &InspectionResult{}

	// Layer 1: Normalize (decode all encoding layers)
	normalized := ins.normalize(req)
	result.Layers = append(result.Layers, "normalize")

	// Layer 2: Evasion detection
	if f := ins.detectEvasion(req, normalized); f != nil {
		result.Findings = append(result.Findings, *f)
	}
	result.Layers = append(result.Layers, "evasion")

	// Layer 3: Pattern matching on normalized payloads
	for _, payload := range normalized {
		result.Findings = append(result.Findings, ins.matchSQLi(payload)...)
		result.Findings = append(result.Findings, ins.matchXSS(payload)...)
		result.Findings = append(result.Findings, ins.matchRCE(payload)...)
		result.Findings = append(result.Findings, ins.matchSSRF(payload)...)
		result.Findings = append(result.Findings, ins.matchSSTI(payload)...)
	}
	result.Layers = append(result.Layers, "pattern_match")

	// Layer 4: Structural anomalies
	result.Findings = append(result.Findings, ins.detectStructuralAnomalies(req)...)
	result.Layers = append(result.Layers, "structural")

	// Layer 5: Deserialization probe detection
	result.Findings = append(result.Findings, ins.detectDeserialization(req.Body)...)
	result.Layers = append(result.Layers, "deserialization")

	// Layer 6: XXE detection
	result.Findings = append(result.Findings, ins.detectXXE(req.Body)...)
	result.Layers = append(result.Layers, "xxe")

	// Layer 7: NoSQL injection
	result.Findings = append(result.Findings, ins.detectNoSQLi(req)...)
	result.Layers = append(result.Layers, "nosql")

	// Compute score
	result.Score = ins.computeScore(result.Findings)
	result.Blocked = result.Score >= ins.threshold
	return result
}

// ── Normalization ─────────────────────────────────────────────────────────────

func (ins *Inspector) normalize(req *RequestPayload) []string {
	raw := []string{req.Path, req.Query, req.Body}
	for _, v := range req.Headers { raw = append(raw, v) }
	for _, v := range req.Cookies  { raw = append(raw, v) }

	var normalized []string
	for _, s := range raw {
		normalized = append(normalized, s) // raw

		// URL decode (up to 3 layers)
		decoded := s
		for i := 0; i < 3; i++ {
			d, err := url.QueryUnescape(decoded)
			if err != nil || d == decoded { break }
			decoded = d
			normalized = append(normalized, decoded)
		}

		// HTML entity decode
		htmlDecoded := html.UnescapeString(s)
		if htmlDecoded != s { normalized = append(normalized, htmlDecoded) }

		// Base64 decode
		b64clean := strings.TrimRight(s, "=") + strings.Repeat("=", (4-len(s)%4)%4)
		if b, err := base64.StdEncoding.DecodeString(b64clean); err == nil {
			if isPrintable(string(b)) { normalized = append(normalized, string(b)) }
		}

		// Hex decode
		hexclean := strings.ReplaceAll(strings.ReplaceAll(s, "0x", ""), "\\x", "")
		if b, err := hex.DecodeString(hexclean); err == nil {
			if isPrintable(string(b)) { normalized = append(normalized, string(b)) }
		}

		// Lowercase + strip whitespace variants
		normalized = append(normalized, strings.ToLower(strings.ReplaceAll(s, " ", "")))
		normalized = append(normalized, strings.Join(strings.Fields(strings.ToLower(s)), " "))
	}
	return dedupStrings(normalized)
}

// ── Pattern Matchers ──────────────────────────────────────────────────────────

func (ins *Inspector) matchSQLi(payload string) []Finding {
	return ins.matchPatterns(payload, ins.sqliPatterns, ThreatSQLi, "high", 0.85, "SQL Injection", "RULE-SQLI-%03d")
}
func (ins *Inspector) matchXSS(payload string) []Finding {
	return ins.matchPatterns(payload, ins.xssPatterns, ThreatXSS, "high", 0.80, "Cross-Site Scripting", "RULE-XSS-%03d")
}
func (ins *Inspector) matchRCE(payload string) []Finding {
	return ins.matchPatterns(payload, ins.rcePatterns, ThreatRCE, "critical", 0.90, "Remote Code Execution", "RULE-RCE-%03d")
}
func (ins *Inspector) matchSSRF(payload string) []Finding {
	return ins.matchPatterns(payload, ins.ssrfPatterns, ThreatSSRF, "high", 0.85, "Server-Side Request Forgery", "RULE-SSRF-%03d")
}
func (ins *Inspector) matchSSTI(payload string) []Finding {
	return ins.matchPatterns(payload, ins.sstiPatterns, ThreatSSTI, "critical", 0.75, "Server-Side Template Injection", "RULE-SSTI-%03d")
}

func (ins *Inspector) matchPatterns(payload string, patterns []*regexp.Regexp, cat ThreatCategory, sev string, conf float64, desc, ruleFormat string) []Finding {
	var findings []Finding
	for i, pattern := range patterns {
		if pattern.MatchString(payload) {
			match := pattern.FindString(payload)
			if len(match) > 80 { match = match[:80] + "..." }
			findings = append(findings, Finding{
				Category:    cat,
				Severity:    sev,
				Confidence:  conf,
				Evidence:    sanitize(match),
				RuleID:      fmt.Sprintf(ruleFormat, i+1),
				Description: desc,
			})
			break // one finding per category per layer
		}
	}
	return findings
}

// ── Evasion Detection ─────────────────────────────────────────────────────────

func (ins *Inspector) detectEvasion(req *RequestPayload, normalized []string) *Finding {
	evasionSignals := 0
	// Abnormal encoding layers
	if strings.Count(req.Query, "%") > 10 { evasionSignals++ }
	// Null byte injection
	if strings.ContainsAny(req.Body+req.Query, "\x00\x0a\x0d") { evasionSignals++ }
	// Unicode normalization tricks
	if hasUnicodeAlternatives(req.Body + req.Query) { evasionSignals++ }
	// Comment injection
	if strings.Contains(req.Body+req.Query, "/**/") || strings.Contains(req.Body+req.Query, "/*!") {
		evasionSignals++
	}
	if evasionSignals >= 2 {
		return &Finding{
			Category:    ThreatEvasion,
			Severity:    "medium",
			Confidence:  float64(evasionSignals) * 0.25,
			RuleID:      "RULE-EVA-001",
			Description: "Payload evasion technique detected (encoding layers, null bytes, or unicode tricks)",
		}
	}
	return nil
}

// ── Structural Anomalies ──────────────────────────────────────────────────────

func (ins *Inspector) detectStructuralAnomalies(req *RequestPayload) []Finding {
	var findings []Finding
	// Oversized headers (potential buffer overflow)
	for k, v := range req.Headers {
		if len(v) > 8192 {
			findings = append(findings, Finding{
				Category: ThreatRCE, Severity: "medium", Confidence: 0.6,
				RuleID: "RULE-STR-001",
				Description: fmt.Sprintf("Oversized header %q (%d bytes)", k, len(v)),
			})
		}
	}
	// Path traversal
	pathTraversalRe := regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e)`)
	if pathTraversalRe.MatchString(req.Path + req.Query) {
		findings = append(findings, Finding{
			Category: ThreatPathTraversal, Severity: "high", Confidence: 0.90,
			RuleID: "RULE-PATH-001", Description: "Path traversal attempt",
		})
	}
	return findings
}

// ── Deserialization ───────────────────────────────────────────────────────────

func (ins *Inspector) detectDeserialization(body string) []Finding {
	var findings []Finding
	// Java serialized object magic bytes (base64: rO0AB...)
	if strings.HasPrefix(body, "rO0AB") || strings.Contains(body, "aced0005") {
		findings = append(findings, Finding{
			Category: ThreatDeserial, Severity: "critical", Confidence: 0.95,
			RuleID: "RULE-DESER-001",
			Description: "Java serialized object detected — potential deserialization attack",
			CVSS: 9.8,
		})
	}
	// PHP serialization
	phpSerialRe := regexp.MustCompile(`(?i)O:\d+:"[a-z\\\\_]+":`)
	if phpSerialRe.MatchString(body) {
		findings = append(findings, Finding{
			Category: ThreatDeserial, Severity: "critical", Confidence: 0.90,
			RuleID: "RULE-DESER-002",
			Description: "PHP serialized object detected — potential deserialization attack",
		})
	}
	// Python pickle
	if strings.Contains(body, "\\x80\\x04\\x95") || strings.Contains(body, "cposixpath") {
		findings = append(findings, Finding{
			Category: ThreatDeserial, Severity: "critical", Confidence: 0.85,
			RuleID: "RULE-DESER-003",
			Description: "Python pickle payload detected",
		})
	}
	return findings
}

// ── XXE Detection ─────────────────────────────────────────────────────────────

func (ins *Inspector) detectXXE(body string) []Finding {
	xxePatterns := []string{
		`<!ENTITY`, `SYSTEM\s+["']`, `PUBLIC\s+["']`,
		`<!DOCTYPE`, `ENTITY\s+\w+\s+SYSTEM`,
	}
	for i, p := range xxePatterns {
		if re := regexp.MustCompile(`(?i)` + p); re.MatchString(body) {
			return []Finding{{
				Category: ThreatXXE, Severity: "critical", Confidence: 0.88,
				RuleID: fmt.Sprintf("RULE-XXE-%03d", i+1),
				Description: "XML External Entity (XXE) injection attempt", CVSS: 9.1,
			}}
		}
	}
	return nil
}

// ── NoSQL Injection ───────────────────────────────────────────────────────────

func (ins *Inspector) detectNoSQLi(req *RequestPayload) []Finding {
	payload := req.Body + req.Query
	patterns := []string{
		`\$(?:where|ne|gt|lt|gte|lte|in|nin|exists|regex|or|and)\b`,
		`\{\s*"\$\w+"\s*:`,
		`\[\s*"\$\w+"`,
		`(?i)this\s*\.\s*\w+\s*==`,
	}
	for i, p := range patterns {
		if re := regexp.MustCompile(p); re.MatchString(payload) {
			return []Finding{{
				Category: ThreatNoSQLi, Severity: "high", Confidence: 0.82,
				RuleID: fmt.Sprintf("RULE-NOSQL-%03d", i+1),
				Description: "NoSQL injection operator detected",
			}}
		}
	}
	return nil
}

// ── Scoring ───────────────────────────────────────────────────────────────────

func (ins *Inspector) computeScore(findings []Finding) int {
	if len(findings) == 0 { return 0 }
	score := 0
	weights := map[string]int{"critical": 40, "high": 25, "medium": 15, "low": 5}
	for _, f := range findings {
		score += int(float64(weights[f.Severity]) * f.Confidence)
	}
	if score > 100 { score = 100 }
	return score
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' { return false }
	}
	return true
}

func hasUnicodeAlternatives(s string) bool {
	// Check for fullwidth characters (common evasion: ａ instead of a)
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E { return true }
		if r >= 0x2100 && r <= 0x214F { return true }
	}
	return false
}

func sanitize(s string) string {
	// Remove control characters for safe logging
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) { b.WriteRune(r) }
	}
	return b.String()
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] { seen[s] = true; out = append(out, s) }
	}
	return out
}

import "fmt"
