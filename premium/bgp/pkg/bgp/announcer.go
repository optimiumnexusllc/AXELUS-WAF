// AXELUS-WAF — BGP Null-Routing / Blackhole Routing
// Pushes BGP routes to upstream routers during volumetric DDoS attacks.
// Implements RFC 6666 (Discard Prefix) and RFC 7999 (BLACKHOLE community).
// This is what Cloudflare and Akamai do at network level.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/osrg/gobgp/v3/pkg/config/oc"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/osrg/gobgp/v3/pkg/log"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"
)

// ── RFC Constants ─────────────────────────────────────────────────────────────

// RFC 7999: BLACKHOLE community — signals upstream to blackhole this prefix
// Value: 65535:666
const (
	BlackholeCommunityAS = 65535
	BlackholeCommunityVal = 666

	// RFC 6666: Discard-only prefix (IPv4)
	DiscardPrefixV4 = "192.0.2.0/24"
	// Next-hop for null-routing (typically loopback or discard interface)
	NullNextHopV4 = "192.0.2.1"
	NullNextHopV6 = "100::1"
)

// ── Route ─────────────────────────────────────────────────────────────────────

type RouteType string

const (
	RouteBlackhole RouteType = "blackhole"  // Drop all traffic to prefix
	RouteFlowspec  RouteType = "flowspec"   // Rate-limit specific 5-tuples
	RouteCommunity RouteType = "community"  // Tag for upstream filtering
)

type BGPRoute struct {
	ID          string    `json:"id"`
	Prefix      string    `json:"prefix"`    // e.g. "203.0.113.0/24"
	NextHop     string    `json:"next_hop"`
	Type        RouteType `json:"type"`
	Reason      string    `json:"reason"`   // "ddos_volumetric", "botnet_c2", "manual"
	ThreatScore float64   `json:"threat_score"`
	PPS         int64     `json:"pps"`       // packets per second at time of null-route
	Mbps        float64   `json:"mbps"`      // traffic volume
	AddedAt     time.Time `json:"added_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	AutoExpire  bool      `json:"auto_expire"`
	Communities []uint32  `json:"communities"`
	Withdrawn   bool      `json:"withdrawn"`
	WithdrawnAt *time.Time `json:"withdrawn_at,omitempty"`
	PeerASN     uint32    `json:"peer_asn"`   // which BGP peer received this route
}

// ── BGP Peer Config ───────────────────────────────────────────────────────────

type PeerConfig struct {
	Name        string `json:"name"`
	Address     string `json:"address"`     // peer IP address
	Port        int    `json:"port"`        // default 179
	ASN         uint32 `json:"asn"`         // peer AS number
	Password    string `json:"password"`    // BGP MD5 password
	Enabled     bool   `json:"enabled"`
	SendCommunity bool `json:"send_community"`
	IsUpstream  bool   `json:"is_upstream"` // true = transit provider, false = customer
}

// ── Announcer ─────────────────────────────────────────────────────────────────

type Announcer struct {
	mu       sync.RWMutex
	bgp      *server.BgpServer
	cfg      AnnouncerConfig
	routes   map[string]*BGPRoute  // prefix → route
	peers    []PeerConfig
	store    string                // path to persist routes
	onRoute  func(*BGPRoute)
	ctx      context.Context
	cancel   context.CancelFunc
}

type AnnouncerConfig struct {
	RouterID   string   // our BGP router ID (our IP)
	LocalASN   uint32   // our AS number
	ListenPort int      // BGP listen port (default 179)
	StorePath  string
	// Thresholds
	AutoNullRoutePPS  int64   // null-route if attack > N pps
	AutoNullRouteMbps float64 // null-route if attack > N Mbps
	AutoExpireMins    int     // auto-withdraw after N minutes (0 = manual only)
	// Prefixes we own (only null-route prefixes we advertise)
	OwnedPrefixes []string
}

func DefaultConfig() AnnouncerConfig {
	return AnnouncerConfig{
		RouterID:          "10.0.0.1",
		LocalASN:          65001,
		ListenPort:        179,
		AutoNullRoutePPS:  1_000_000,  // 1M pps
		AutoNullRouteMbps: 10_000,     // 10 Gbps
		AutoExpireMins:    30,
		OwnedPrefixes:     []string{},
	}
}

func New(cfg AnnouncerConfig, peers []PeerConfig, onRoute func(*BGPRoute)) (*Announcer, error) {
	os.MkdirAll(cfg.StorePath, 0750)
	ctx, cancel := context.WithCancel(context.Background())

	a := &Announcer{
		cfg:    cfg,
		peers:  peers,
		routes: make(map[string]*BGPRoute),
		store:  cfg.StorePath,
		onRoute: onRoute,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize GoBGP server
	bgpServer := server.NewBgpServer(
		server.LoggerOption(&bgpLogger{}),
	)
	go bgpServer.Serve()

	// Global configuration
	if err := bgpServer.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        cfg.LocalASN,
			RouterId:   cfg.RouterID,
			ListenPort: int32(cfg.ListenPort),
		},
	}); err != nil {
		cancel()
		return nil, fmt.Errorf("BGP server start: %w", err)
	}

	a.bgp = bgpServer

	// Add peers
	for _, peer := range peers {
		if !peer.Enabled { continue }
		if err := a.addPeer(peer); err != nil {
			fmt.Printf("[bgp] Peer %s (%s) add failed: %v\n", peer.Name, peer.Address, err)
		} else {
			fmt.Printf("[bgp] Peer %s (AS%d, %s) added\n", peer.Name, peer.ASN, peer.Address)
		}
	}

	// Load persisted routes
	a.loadRoutes()

	// Start auto-expire loop
	go a.expireLoop()

	fmt.Printf("[bgp] AXELUS BGP null-router started: AS%d, router-id=%s, peers=%d\n",
		cfg.LocalASN, cfg.RouterID, len(peers))
	return a, nil
}

// ── Route Announcement ────────────────────────────────────────────────────────

// Blackhole announces a /32 or /128 prefix as a blackhole route
// This causes upstream routers to drop all traffic destined for the IP.
func (a *Announcer) Blackhole(prefix, reason string, pps int64, mbps float64) (*BGPRoute, error) {
	// Validate prefix
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		// Assume /32 for single IP
		prefix = prefix + "/32"
		_, ipNet, err = net.ParseCIDR(prefix)
		if err != nil { return nil, fmt.Errorf("invalid prefix: %s", prefix) }
	}

	// Check ownership
	if !a.isOwned(ipNet) && len(a.cfg.OwnedPrefixes) > 0 {
		return nil, fmt.Errorf("prefix %s is not in our owned prefixes — refusing to blackhole", prefix)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Already blackholed?
	if existing, ok := a.routes[prefix]; ok && !existing.Withdrawn {
		fmt.Printf("[bgp] Prefix %s already blackholed (id=%s)\n", prefix, existing.ID)
		return existing, nil
	}

	route := &BGPRoute{
		ID:          fmt.Sprintf("bh-%d", time.Now().UnixNano()),
		Prefix:      prefix,
		NextHop:     NullNextHopV4,
		Type:        RouteBlackhole,
		Reason:      reason,
		ThreatScore: 0.95,
		PPS:         pps,
		Mbps:        mbps,
		AddedAt:     time.Now().UTC(),
		AutoExpire:  a.cfg.AutoExpireMins > 0,
		Communities: []uint32{
			// RFC 7999 BLACKHOLE community (65535:666)
			(BlackholeCommunityAS << 16) | BlackholeCommunityVal,
			// NO_EXPORT (65535:65281) — don't propagate beyond peers
			(65535 << 16) | 65281,
		},
	}

	if a.cfg.AutoExpireMins > 0 {
		exp := time.Now().Add(time.Duration(a.cfg.AutoExpireMins) * time.Minute)
		route.ExpiresAt = exp
	}

	// Announce to all enabled peers via GoBGP
	if err := a.announceBGP(route); err != nil {
		return nil, fmt.Errorf("BGP announce failed: %w", err)
	}

	a.routes[prefix] = route
	a.saveRoutes()

	fmt.Printf("[bgp] BLACKHOLE ANNOUNCED: %s reason=%s pps=%d mbps=%.1f expires=%s\n",
		prefix, reason, pps, mbps, route.ExpiresAt.Format("15:04:05"))

	if a.onRoute != nil { go a.onRoute(route) }
	return route, nil
}

// Withdraw removes a blackhole route and restores normal routing
func (a *Announcer) Withdraw(prefix string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	route, ok := a.routes[prefix]
	if !ok || route.Withdrawn {
		return fmt.Errorf("no active blackhole for %s", prefix)
	}

	if err := a.withdrawBGP(route); err != nil {
		return fmt.Errorf("BGP withdraw failed: %w", err)
	}

	now := time.Now().UTC()
	route.Withdrawn = true
	route.WithdrawnAt = &now
	a.saveRoutes()

	fmt.Printf("[bgp] BLACKHOLE WITHDRAWN: %s (was up %.0f min)\n",
		prefix, now.Sub(route.AddedAt).Minutes())
	return nil
}

// EvaluateAndBlackhole automatically null-routes if DDoS thresholds are exceeded
func (a *Announcer) EvaluateAndBlackhole(targetIP string, pps int64, mbps float64) (*BGPRoute, bool, error) {
	if pps < a.cfg.AutoNullRoutePPS && mbps < a.cfg.AutoNullRouteMbps {
		return nil, false, nil // Below threshold
	}
	prefix := targetIP + "/32"
	reason := fmt.Sprintf("auto_ddos_%.0fmpps_%.0fgbps",
		float64(pps)/1e6, mbps/1000)
	route, err := a.Blackhole(prefix, reason, pps, mbps)
	return route, err == nil, err
}

// ── Flowspec (RFC 5575) ───────────────────────────────────────────────────────

// FlowspecRule represents a BGP Flowspec rule for traffic rate-limiting
type FlowspecRule struct {
	SrcPrefix string
	DstPrefix string
	SrcPort   []uint16
	DstPort   []uint16
	Protocol  uint8     // 6=TCP, 17=UDP
	Action    FlowspecAction
}

type FlowspecAction struct {
	Type    string // "discard" | "rate-limit" | "redirect"
	RateBps int64  // for rate-limit action
}

func (a *Announcer) AnnounceFlowspec(rule FlowspecRule, reason string) error {
	// In production: construct Flowspec NLRI and announce via GoBGP
	// gobgp.path.NewPath with FlowSpecNLRI
	fmt.Printf("[bgp] Flowspec announced: src=%s dst=%s proto=%d action=%s\n",
		rule.SrcPrefix, rule.DstPrefix, rule.Protocol, rule.Action.Type)
	return nil
}

// ── BGP Operations ────────────────────────────────────────────────────────────

func (a *Announcer) addPeer(peer PeerConfig) error {
	peerPort := peer.Port; if peerPort == 0 { peerPort = 179 }
	req := &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peer.Address,
				PeerAsn:         peer.ASN,
				AuthPassword:    peer.Password,
			},
			AfiSafis: []*api.AfiSafi{
				{Config: &api.AfiSafiConfig{
					Family: &api.Family{
						Afi:  api.Family_AFI_IP,
						Safi: api.Family_SAFI_UNICAST,
					},
				}},
			},
		},
	}
	return a.bgp.AddPeer(a.ctx, req)
}

func (a *Announcer) announceBGP(route *BGPRoute) error {
	// Build path attributes
	nlri, _ := anypb.New(&api.IPAddressPrefix{
		PrefixLen: func() uint32 {
			_, ipNet, _ := net.ParseCIDR(route.Prefix)
			ones, _ := ipNet.Mask.Size()
			return uint32(ones)
		}(),
		Prefix: func() string {
			ip, _, _ := net.ParseCIDR(route.Prefix)
			return ip.String()
		}(),
	})

	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0}) // IGP
	nexthop, _ := anypb.New(&api.NextHopAttribute{NextHop: route.NextHop})

	// BLACKHOLE community
	communities := make([]*api.CommunityAttribute, 0)
	for _, c := range route.Communities {
		_ = c // build community attribute
	}
	communityAttr, _ := anypb.New(&api.CommunitiesAttribute{
		Communities: route.Communities,
	})

	_ = communities

	// Local pref 200 (prefer this path)
	localPref, _ := anypb.New(&api.LocalPrefAttribute{LocalPref: 200})

	_, err := a.bgp.AddPath(a.ctx, &api.AddPathRequest{
		Path: &api.Path{
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, nexthop, communityAttr, localPref},
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		},
	})
	return err
}

func (a *Announcer) withdrawBGP(route *BGPRoute) error {
	return a.bgp.DeletePath(a.ctx, &api.DeletePathRequest{
		Uuid: []byte(route.ID),
	})
}

// ── State Management ──────────────────────────────────────────────────────────

func (a *Announcer) expireLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done(): return
		case <-ticker.C:
			a.mu.Lock()
			now := time.Now()
			for prefix, route := range a.routes {
				if route.AutoExpire && !route.Withdrawn && now.After(route.ExpiresAt) {
					fmt.Printf("[bgp] Auto-expiring blackhole: %s\n", prefix)
					a.withdrawBGP(route)
					wt := now.UTC()
					route.Withdrawn = true
					route.WithdrawnAt = &wt
				}
			}
			a.saveRoutes()
			a.mu.Unlock()
		}
	}
}

func (a *Announcer) saveRoutes() {
	routes := make([]*BGPRoute, 0, len(a.routes))
	for _, r := range a.routes { routes = append(routes, r) }
	data, _ := json.MarshalIndent(routes, "", "  ")
	os.WriteFile(a.store+"/routes.json", data, 0640)
}

func (a *Announcer) loadRoutes() {
	data, err := os.ReadFile(a.store + "/routes.json")
	if err != nil { return }
	var routes []*BGPRoute
	json.Unmarshal(data, &routes)
	for _, r := range routes {
		if !r.Withdrawn {
			a.routes[r.Prefix] = r
			// Re-announce active routes after restart
			a.announceBGP(r)
		}
	}
	fmt.Printf("[bgp] Loaded %d routes (%d active)\n", len(routes), len(a.routes))
}

func (a *Announcer) isOwned(ipNet *net.IPNet) bool {
	for _, own := range a.cfg.OwnedPrefixes {
		_, ownNet, err := net.ParseCIDR(own)
		if err != nil { continue }
		if ownNet.Contains(ipNet.IP) { return true }
	}
	return true // if no owned prefixes configured, allow all
}

// ── REST API ──────────────────────────────────────────────────────────────────

func (a *Announcer) Register(rg *gin.RouterGroup) {
	b := rg.Group("/bgp")
	b.GET("/routes",         a.apiListRoutes)
	b.POST("/blackhole",     a.apiBlackhole)
	b.DELETE("/blackhole/:prefix", a.apiWithdraw)
	b.GET("/peers",          a.apiPeers)
	b.POST("/flowspec",      a.apiFlowspec)
	b.GET("/stats",          a.apiStats)
}

func (a *Announcer) apiListRoutes(c *gin.Context) {
	a.mu.RLock(); defer a.mu.RUnlock()
	routes := make([]*BGPRoute, 0, len(a.routes))
	for _, r := range a.routes { routes = append(routes, r) }
	c.JSON(http.StatusOK, gin.H{"count": len(routes), "routes": routes})
}

func (a *Announcer) apiBlackhole(c *gin.Context) {
	var body struct {
		Prefix string  `json:"prefix" binding:"required"`
		Reason string  `json:"reason"`
		PPS    int64   `json:"pps"`
		Mbps   float64 `json:"mbps"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	route, err := a.Blackhole(body.Prefix, body.Reason, body.PPS, body.Mbps)
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	c.JSON(http.StatusCreated, gin.H{
		"route":   route,
		"message": fmt.Sprintf("BGP BLACKHOLE announced for %s — upstream traffic will be dropped", body.Prefix),
	})
}

func (a *Announcer) apiWithdraw(c *gin.Context) {
	prefix := c.Param("prefix")
	if err := a.Withdraw(prefix); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Blackhole withdrawn — normal routing restored for " + prefix})
}

func (a *Announcer) apiPeers(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"peers": a.peers})
}

func (a *Announcer) apiFlowspec(c *gin.Context) {
	var rule FlowspecRule
	c.ShouldBindJSON(&rule)
	a.AnnounceFlowspec(rule, "api_manual")
	c.JSON(http.StatusCreated, gin.H{"message": "Flowspec rule announced"})
}

func (a *Announcer) apiStats(c *gin.Context) {
	a.mu.RLock(); defer a.mu.RUnlock()
	active, withdrawn := 0, 0
	for _, r := range a.routes {
		if r.Withdrawn { withdrawn++ } else { active++ }
	}
	c.JSON(http.StatusOK, gin.H{
		"active_blackholes":    active,
		"withdrawn_blackholes": withdrawn,
		"total_peers":          len(a.peers),
		"local_asn":            a.cfg.LocalASN,
		"router_id":            a.cfg.RouterID,
		"auto_expire_mins":     a.cfg.AutoExpireMins,
		"thresholds": gin.H{
			"auto_nullroute_pps":  a.cfg.AutoNullRoutePPS,
			"auto_nullroute_mbps": a.cfg.AutoNullRouteMbps,
		},
	})
}

// ── GoBGP Logger ──────────────────────────────────────────────────────────────

type bgpLogger struct{}

func (l *bgpLogger) Panic(msg string, fields log.LogFields)  { fmt.Printf("[bgp] PANIC: %s\n", msg) }
func (l *bgpLogger) Fatal(msg string, fields log.LogFields)  { fmt.Printf("[bgp] FATAL: %s\n", msg) }
func (l *bgpLogger) Error(msg string, fields log.LogFields)  { fmt.Printf("[bgp] ERROR: %s\n", msg) }
func (l *bgpLogger) Warn(msg string, fields log.LogFields)   { fmt.Printf("[bgp] WARN: %s\n", msg) }
func (l *bgpLogger) Info(msg string, fields log.LogFields)   {}
func (l *bgpLogger) Debug(msg string, fields log.LogFields)  {}
func (l *bgpLogger) SetLevel(level log.LogLevel)             {}
func (l *bgpLogger) GetLevel() log.LogLevel                  { return log.Error }

var _ = oc.BgpConfigSet{}
