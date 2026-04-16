// AXELUS-WAF — Zero-Day Shield: ML-Based Anomaly Scoring Engine
// Detects novel, previously-unseen attack patterns by scoring requests
// against behavioral baselines rather than known signatures.
// Uses: Isolation Forest + statistical z-scoring + entropy analysis.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package scorer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ── Feature Vector ────────────────────────────────────────────────────────────

// FeatureVector encodes a single HTTP request as a numeric feature set
// for anomaly scoring. All values normalised to [0,1] range.
type FeatureVector struct {
	// Structural features
	PathLength       float64 // Normalised URL path length
	QueryLength      float64 // Normalised query string length
	BodyLength       float64 // Normalised body size
	HeaderCount      float64 // Number of HTTP headers
	ParamCount       float64 // Number of query/body parameters

	// Entropy features
	PathEntropy      float64 // Shannon entropy of the URL path
	QueryEntropy     float64 // Shannon entropy of query values
	BodyEntropy      float64 // Shannon entropy of body
	UAEntropy        float64 // User-agent string entropy

	// Character distribution features
	SpecialCharRatio float64 // Ratio of special chars in payload
	DigitRatio       float64 // Ratio of digits
	UpperCaseRatio   float64 // Ratio of uppercase letters
	NonASCIIRatio    float64 // Ratio of non-ASCII characters

	// Structural anomaly features
	NestedBrackets   float64 // Depth of bracket nesting (injection indicator)
	QuoteBalance     float64 // Imbalance of quotes (0=balanced)
	SemicolonCount   float64 // Semicolons (multi-statement indicator)
	CommentPatterns  float64 // SQL/HTML comment presence
	EncodingLayers   float64 // Estimated URL encoding layers

	// Behavioural features
	RequestsPerMin   float64 // Request rate from this IP (last 1 min)
	UniquePathsRatio float64 // Unique paths / total requests ratio
	ErrorRate        float64 // Recent 4xx/5xx error rate

	// Temporal features
	HourOfDay        float64 // 0-23 normalised
	DayOfWeek        float64 // 0-6 normalised
	IsNightTime      float64 // 1 if between 01:00-05:00 UTC
}

// ToSlice converts the feature vector to a float64 slice for ML models
func (fv *FeatureVector) ToSlice() []float64 {
	return []float64{
		fv.PathLength, fv.QueryLength, fv.BodyLength, fv.HeaderCount, fv.ParamCount,
		fv.PathEntropy, fv.QueryEntropy, fv.BodyEntropy, fv.UAEntropy,
		fv.SpecialCharRatio, fv.DigitRatio, fv.UpperCaseRatio, fv.NonASCIIRatio,
		fv.NestedBrackets, fv.QuoteBalance, fv.SemicolonCount, fv.CommentPatterns, fv.EncodingLayers,
		fv.RequestsPerMin, fv.UniquePathsRatio, fv.ErrorRate,
		fv.HourOfDay, fv.DayOfWeek, fv.IsNightTime,
	}
}

const FeatureDim = 24

// ── Request Input ─────────────────────────────────────────────────────────────

type RequestInput struct {
	IP         string
	Method     string
	Path       string
	Query      string
	Body       string
	Headers    map[string]string
	UserAgent  string
	Timestamp  time.Time
}

// ── Anomaly Score ─────────────────────────────────────────────────────────────

type AnomalyScore struct {
	Score          float64        // 0.0–1.0 (1.0 = most anomalous)
	Level          AnomalyLevel
	Features       FeatureVector
	TopFeatures    []FeatureContrib // Which features drove the score
	IsZeroDay      bool
	Confidence     float64        // Model confidence 0.0–1.0
	BaselineDeviation float64     // How far from baseline (z-score)
	Explanation    string
}

type AnomalyLevel string

const (
	LevelNormal    AnomalyLevel = "normal"
	LevelSuspect   AnomalyLevel = "suspect"   // 0.5–0.7
	LevelAnomaly   AnomalyLevel = "anomaly"   // 0.7–0.85
	LevelZeroDay   AnomalyLevel = "zero_day"  // 0.85–1.0
)

type FeatureContrib struct {
	Feature    string
	Value      float64
	Deviation  float64 // Standard deviations from baseline mean
	Weight     float64 // Contribution to final score
}

// ── Baseline Statistics ────────────────────────────────────────────────────────

type BaselineStats struct {
	Mean   [FeatureDim]float64
	StdDev [FeatureDim]float64
	Min    [FeatureDim]float64
	Max    [FeatureDim]float64
	Count  int64
}

var featureNames = [FeatureDim]string{
	"path_length", "query_length", "body_length", "header_count", "param_count",
	"path_entropy", "query_entropy", "body_entropy", "ua_entropy",
	"special_char_ratio", "digit_ratio", "uppercase_ratio", "non_ascii_ratio",
	"nested_brackets", "quote_balance", "semicolon_count", "comment_patterns", "encoding_layers",
	"requests_per_min", "unique_paths_ratio", "error_rate",
	"hour_of_day", "day_of_week", "is_night",
}

// ── Isolation Forest (lightweight pure-Go implementation) ─────────────────────

type IsolationTree struct {
	left, right *IsolationTree
	splitFeature int
	splitValue   float64
	size         int
	isLeaf       bool
}

type IsolationForest struct {
	trees     []*IsolationTree
	numTrees  int
	maxDepth  int
	subsample int
}

func NewIsolationForest(numTrees, maxDepth, subsample int) *IsolationForest {
	if numTrees == 0  { numTrees = 100 }
	if maxDepth == 0  { maxDepth = 8 }
	if subsample == 0 { subsample = 256 }
	return &IsolationForest{
		numTrees:  numTrees,
		maxDepth:  maxDepth,
		subsample: subsample,
	}
}

// Fit trains the isolation forest on a dataset of feature vectors
func (f *IsolationForest) Fit(data [][]float64) {
	f.trees = make([]*IsolationTree, f.numTrees)
	for i := 0; i < f.numTrees; i++ {
		sample := subsampleData(data, f.subsample)
		f.trees[i] = buildTree(sample, 0, f.maxDepth)
	}
}

func buildTree(data [][]float64, depth, maxDepth int) *IsolationTree {
	node := &IsolationTree{size: len(data)}
	if depth >= maxDepth || len(data) <= 1 {
		node.isLeaf = true
		return node
	}
	// Pick random feature and split value
	dim := len(data[0])
	feat := pseudoRandInt(depth+len(data)) % dim
	minV, maxV := data[0][feat], data[0][feat]
	for _, row := range data {
		if row[feat] < minV { minV = row[feat] }
		if row[feat] > maxV { maxV = row[feat] }
	}
	if minV == maxV { node.isLeaf = true; return node }

	split := minV + (maxV-minV)*0.5 // midpoint split
	node.splitFeature = feat
	node.splitValue   = split

	var left, right [][]float64
	for _, row := range data {
		if row[feat] < split { left = append(left, row) } else { right = append(right, row) }
	}
	node.left  = buildTree(left,  depth+1, maxDepth)
	node.right = buildTree(right, depth+1, maxDepth)
	return node
}

// PathLength returns the average isolation path length for a sample
func (f *IsolationForest) PathLength(x []float64) float64 {
	if len(f.trees) == 0 { return 0 }
	total := 0.0
	for _, tree := range f.trees {
		total += pathLength(tree, x, 0)
	}
	return total / float64(len(f.trees))
}

func pathLength(node *IsolationTree, x []float64, depth int) float64 {
	if node.isLeaf || node == nil {
		return float64(depth) + avgPathLength(node.size)
	}
	if x[node.splitFeature] < node.splitValue {
		return pathLength(node.left, x, depth+1)
	}
	return pathLength(node.right, x, depth+1)
}

// AnomalyScore returns a normalised anomaly score [0,1]
func (f *IsolationForest) AnomalyScore(x []float64) float64 {
	pl := f.PathLength(x)
	c  := avgPathLength(f.subsample)
	if c == 0 { return 0 }
	score := math.Pow(2, -pl/c)
	// Normalise: 0.5 = average, >0.7 = anomalous
	normalised := (score - 0.3) / 0.7
	if normalised < 0 { return 0 }
	if normalised > 1 { return 1 }
	return normalised
}

func avgPathLength(n int) float64 {
	if n <= 1 { return 0 }
	fn := float64(n)
	return 2*(math.Log(fn-1)+0.5772156649) - 2*(fn-1)/fn
}

func subsampleData(data [][]float64, n int) [][]float64 {
	if len(data) <= n { return data }
	result := make([][]float64, n)
	step := len(data) / n
	for i := 0; i < n; i++ { result[i] = data[i*step] }
	return result
}

func pseudoRandInt(seed int) int {
	seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5
	if seed < 0 { seed = -seed }
	return seed
}

// ── Anomaly Scorer ─────────────────────────────────────────────────────────────

type Scorer struct {
	mu          sync.RWMutex
	forest      *IsolationForest
	baseline    BaselineStats
	trained     bool
	trainBuffer [][]float64    // accumulate samples before training
	config      ScorerConfig
	ipStats     sync.Map        // IP → *IPStats
}

type ScorerConfig struct {
	ZeroDayThreshold float64  // Score above this = zero-day (default 0.85)
	AnomalyThreshold float64  // Score above this = anomaly (default 0.70)
	SuspectThreshold float64  // Score above this = suspect (default 0.50)
	MinTrainSamples  int      // Minimum samples before model is live
	NumTrees         int
	MaxDepth         int
	Subsample        int
}

type IPStats struct {
	mu           sync.Mutex
	reqCount     int64
	errCount     int64
	uniquePaths  map[string]struct{}
	lastMinute   []time.Time
}

func NewScorer(cfg ScorerConfig) *Scorer {
	if cfg.ZeroDayThreshold == 0 { cfg.ZeroDayThreshold = 0.85 }
	if cfg.AnomalyThreshold == 0 { cfg.AnomalyThreshold = 0.70 }
	if cfg.SuspectThreshold == 0 { cfg.SuspectThreshold = 0.50 }
	if cfg.MinTrainSamples == 0  { cfg.MinTrainSamples = 500 }
	return &Scorer{
		config: cfg,
		forest: NewIsolationForest(cfg.NumTrees, cfg.MaxDepth, cfg.Subsample),
	}
}

// Score evaluates a request and returns an anomaly assessment
func (s *Scorer) Score(req RequestInput) *AnomalyScore {
	fv := s.extractFeatures(req)
	vec := fv.ToSlice()

	// Accumulate training data during warm-up
	s.mu.Lock()
	if !s.trained {
		s.trainBuffer = append(s.trainBuffer, vec)
		if len(s.trainBuffer) >= s.config.MinTrainSamples {
			s.trainModel()
		}
		s.mu.Unlock()
		return &AnomalyScore{
			Score:       0,
			Level:       LevelNormal,
			Features:    fv,
			Confidence:  0,
			Explanation: "Model warming up — collecting baseline",
		}
	}
	s.mu.Unlock()

	// Score against trained model
	s.mu.RLock()
	isoScore := s.forest.AnomalyScore(vec)
	zScore   := s.zScore(vec)
	s.mu.RUnlock()

	// Combined score: 60% isolation forest + 40% z-score deviation
	combined := 0.6*isoScore + 0.4*clamp01(zScore/5.0)

	level := LevelNormal
	isZeroDay := false
	switch {
	case combined >= s.config.ZeroDayThreshold:
		level = LevelZeroDay; isZeroDay = true
	case combined >= s.config.AnomalyThreshold:
		level = LevelAnomaly
	case combined >= s.config.SuspectThreshold:
		level = LevelSuspect
	}

	// Identify top contributing features
	top := s.topContributors(vec, 5)

	explanation := s.explain(combined, top)

	// Update baseline with normal traffic (rolling)
	if combined < s.config.SuspectThreshold {
		s.mu.Lock()
		s.trainBuffer = append(s.trainBuffer, vec)
		if len(s.trainBuffer) > 5000 { // periodic retraining
			s.trainModel()
		}
		s.mu.Unlock()
	}

	return &AnomalyScore{
		Score:             combined,
		Level:             level,
		Features:          fv,
		TopFeatures:       top,
		IsZeroDay:         isZeroDay,
		Confidence:        math.Min(float64(s.baseline.Count)/1000.0, 1.0),
		BaselineDeviation: zScore,
		Explanation:       explanation,
	}
}

// ── Feature Extraction ────────────────────────────────────────────────────────

func (s *Scorer) extractFeatures(req RequestInput) FeatureVector {
	fv := FeatureVector{}
	payload := req.Path + req.Query + req.Body

	fv.PathLength    = clamp01(float64(len(req.Path)) / 500.0)
	fv.QueryLength   = clamp01(float64(len(req.Query)) / 2000.0)
	fv.BodyLength    = clamp01(float64(len(req.Body)) / 50000.0)
	fv.HeaderCount   = clamp01(float64(len(req.Headers)) / 30.0)

	// Parameter count
	params := 0
	for _, c := range req.Query { if c == '&' || c == '=' { params++ } }
	for _, c := range req.Body  { if c == '&' || c == '=' { params++ } }
	fv.ParamCount = clamp01(float64(params) / 50.0)

	// Entropy
	fv.PathEntropy  = normaliseEntropy(shannonEntropy(req.Path))
	fv.QueryEntropy = normaliseEntropy(shannonEntropy(req.Query))
	fv.BodyEntropy  = normaliseEntropy(shannonEntropy(req.Body))
	fv.UAEntropy    = normaliseEntropy(shannonEntropy(req.UserAgent))

	// Character analysis
	fv.SpecialCharRatio = charRatio(payload, isSpecial)
	fv.DigitRatio       = charRatio(payload, unicode.IsDigit)
	fv.UpperCaseRatio   = charRatio(payload, unicode.IsUpper)
	fv.NonASCIIRatio    = charRatio(payload, func(r rune) bool { return r > 127 })

	// Structural anomalies
	fv.NestedBrackets  = clamp01(float64(maxNesting(payload)) / 10.0)
	fv.QuoteBalance    = quoteImbalance(payload)
	fv.SemicolonCount  = clamp01(float64(strings.Count(payload, ";")) / 10.0)
	hasComment := strings.Contains(payload, "--") || strings.Contains(payload, "/*") ||
		strings.Contains(payload, "<!--")
	if hasComment { fv.CommentPatterns = 1.0 }
	fv.EncodingLayers  = clamp01(float64(strings.Count(req.Query, "%25")) / 3.0)

	// Behavioural features from IP stats
	stats := s.getIPStats(req.IP)
	if stats != nil {
		now := req.Timestamp
		stats.mu.Lock()
		// Count requests in last minute
		cutoff := now.Add(-time.Minute)
		recent := stats.lastMinute[:0]
		for _, t := range stats.lastMinute {
			if t.After(cutoff) { recent = append(recent, t) }
		}
		recent = append(recent, now)
		stats.lastMinute = recent
		stats.reqCount++
		stats.uniquePaths[req.Path] = struct{}{}
		ratePerMin := float64(len(recent))
		totalReqs  := float64(stats.reqCount)
		uniquePaths := float64(len(stats.uniquePaths))
		errRate     := float64(stats.errCount) / math.Max(totalReqs, 1)
		stats.mu.Unlock()

		fv.RequestsPerMin   = clamp01(ratePerMin / 300.0)  // 300 req/min = max
		fv.UniquePathsRatio = clamp01(uniquePaths / math.Max(totalReqs, 1))
		fv.ErrorRate        = clamp01(errRate)
	}

	// Temporal
	t := req.Timestamp.UTC()
	fv.HourOfDay  = float64(t.Hour()) / 23.0
	fv.DayOfWeek  = float64(t.Weekday()) / 6.0
	if t.Hour() >= 1 && t.Hour() <= 5 { fv.IsNightTime = 1.0 }

	return fv
}

func (s *Scorer) getIPStats(ip string) *IPStats {
	v, _ := s.ipStats.LoadOrStore(ip, &IPStats{
		uniquePaths: make(map[string]struct{}),
	})
	return v.(*IPStats)
}

// ── Model Management ──────────────────────────────────────────────────────────

func (s *Scorer) trainModel() {
	if len(s.trainBuffer) < 10 { return }
	data := s.trainBuffer
	s.forest.Fit(data)
	s.computeBaseline(data)
	s.trained = true
	count := int64(len(data))
	s.baseline.Count += count
	s.trainBuffer = s.trainBuffer[:0]
	fmt.Printf("[zero-day] Model trained on %d samples (total: %d)\n",
		len(data), s.baseline.Count)
}

func (s *Scorer) computeBaseline(data [][]float64) {
	n := len(data)
	if n == 0 { return }

	for d := 0; d < FeatureDim; d++ {
		sum := 0.0
		for _, row := range data { sum += row[d] }
		s.baseline.Mean[d] = sum / float64(n)

		variance := 0.0
		for _, row := range data {
			diff := row[d] - s.baseline.Mean[d]
			variance += diff * diff
		}
		s.baseline.StdDev[d] = math.Sqrt(variance / float64(n))
		if s.baseline.StdDev[d] < 1e-10 { s.baseline.StdDev[d] = 1e-10 }
	}
}

func (s *Scorer) zScore(vec []float64) float64 {
	total := 0.0
	for d := 0; d < FeatureDim; d++ {
		z := math.Abs(vec[d] - s.baseline.Mean[d]) / s.baseline.StdDev[d]
		total += z
	}
	return total / FeatureDim
}

func (s *Scorer) topContributors(vec []float64, n int) []FeatureContrib {
	contribs := make([]FeatureContrib, FeatureDim)
	for d := 0; d < FeatureDim; d++ {
		dev := math.Abs(vec[d]-s.baseline.Mean[d]) / s.baseline.StdDev[d]
		contribs[d] = FeatureContrib{
			Feature:   featureNames[d],
			Value:     vec[d],
			Deviation: dev,
			Weight:    dev * vec[d],
		}
	}
	sort.Slice(contribs, func(i, j int) bool { return contribs[i].Deviation > contribs[j].Deviation })
	if n > len(contribs) { n = len(contribs) }
	return contribs[:n]
}

func (s *Scorer) explain(score float64, top []FeatureContrib) string {
	if len(top) == 0 { return "No baseline available yet" }
	parts := make([]string, 0, 3)
	for _, c := range top[:min3(3, len(top))] {
		if c.Deviation > 1.5 {
			parts = append(parts, fmt.Sprintf("%s (%.1fσ)", c.Feature, c.Deviation))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Marginal anomaly (score=%.2f) — all features within normal range", score)
	}
	return fmt.Sprintf("Anomaly driven by: %s", strings.Join(parts, ", "))
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func shannonEntropy(s string) float64 {
	if len(s) == 0 { return 0 }
	freq := make(map[rune]float64)
	for _, c := range s { freq[c]++ }
	n := float64(len(s))
	h := 0.0
	for _, f := range freq {
		p := f / n
		h -= p * math.Log2(p)
	}
	return h
}

func normaliseEntropy(h float64) float64 { return clamp01(h / 8.0) }

func charRatio(s string, fn func(rune) bool) float64 {
	if len(s) == 0 { return 0 }
	count := 0
	total := 0
	for _, c := range s { total++; if fn(c) { count++ } }
	return float64(count) / float64(total)
}

func isSpecial(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' '
}

func maxNesting(s string) int {
	max, curr := 0, 0
	for _, c := range s {
		if c == '(' || c == '[' || c == '{' { curr++; if curr > max { max = curr } }
		if c == ')' || c == ']' || c == '}' { curr-- }
	}
	return max
}

func quoteImbalance(s string) float64 {
	sq := strings.Count(s, "'")
	dq := strings.Count(s, `"`)
	total := sq + dq
	if total == 0 { return 0 }
	imbal := math.Abs(float64(sq%2)) + math.Abs(float64(dq%2))
	return clamp01(imbal / 2.0)
}

func clamp01(v float64) float64 {
	if v < 0 { return 0 }; if v > 1 { return 1 }; return v
}

func min3(a, b int) int { if a < b { return a }; return b }

// IsModelReady returns true if the model has been trained
func (s *Scorer) IsModelReady() bool {
	s.mu.RLock(); defer s.mu.RUnlock()
	return s.trained
}

// Stats returns current model statistics
func (s *Scorer) Stats() map[string]interface{} {
	s.mu.RLock(); defer s.mu.RUnlock()
	return map[string]interface{}{
		"trained":        s.trained,
		"samples_count":  s.baseline.Count,
		"buffer_size":    len(s.trainBuffer),
		"model_ready":    s.trained,
		"thresholds": map[string]float64{
			"zero_day": s.config.ZeroDayThreshold,
			"anomaly":  s.config.AnomalyThreshold,
			"suspect":  s.config.SuspectThreshold,
		},
	}
}
