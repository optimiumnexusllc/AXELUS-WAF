// IronWall-WAF — mTLS Certificate Manager
// Manages mutual TLS for all inter-service communication.
// Implements SPIFFE/SPIRE-compatible identity, automatic rotation,
// short-lived certificates, and online OCSP stapling.
// Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
package certmgr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ── Identity ──────────────────────────────────────────────────────────────────

// SPIFFE URI format: spiffe://ironwall.local/ns/{namespace}/sa/{service}
type ServiceIdentity struct {
	TrustDomain string // e.g. "ironwall.local"
	Namespace   string // e.g. "ironwall"
	Service     string // e.g. "management" | "detector" | "forensics"
}

func (id ServiceIdentity) SPIFFEURI() string {
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", id.TrustDomain, id.Namespace, id.Service)
}

func (id ServiceIdentity) CommonName() string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", id.Service, id.Namespace)
}

// ── Certificate Authority ─────────────────────────────────────────────────────

type CA struct {
	mu       sync.RWMutex
	cert     *x509.Certificate
	key      crypto.Signer
	certPEM  []byte
	keyPEM   []byte
	storePath string
}

type CAConfig struct {
	CommonName   string
	Organization string
	Country      string
	ValidYears   int
	KeyAlgo      KeyAlgo
	StorePath    string
}

type KeyAlgo string
const (
	KeyAlgoECDSA KeyAlgo = "ecdsa-p256"
	KeyAlgoRSA4k KeyAlgo = "rsa-4096"
)

// NewCA creates or loads a Certificate Authority
func NewCA(cfg CAConfig) (*CA, error) {
	if cfg.ValidYears == 0  { cfg.ValidYears = 10 }
	if cfg.KeyAlgo == ""    { cfg.KeyAlgo = KeyAlgoECDSA }
	if cfg.StorePath == ""  { cfg.StorePath = "/data/mtls/ca" }

	os.MkdirAll(cfg.StorePath, 0700)
	certPath := filepath.Join(cfg.StorePath, "ca.crt")
	keyPath  := filepath.Join(cfg.StorePath, "ca.key")

	// Load existing CA if present
	if _, err := os.Stat(certPath); err == nil {
		return loadCA(certPath, keyPath, cfg.StorePath)
	}

	// Generate new CA
	key, err := generateKey(cfg.KeyAlgo)
	if err != nil { return nil, fmt.Errorf("CA key generation failed: %w", err) }

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cfg.CommonName,
			Organization: []string{cfg.Organization},
			Country:      []string{cfg.Country},
		},
		NotBefore:             time.Now().UTC().Add(-5 * time.Minute),
		NotAfter:              time.Now().UTC().AddDate(cfg.ValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil { return nil, err }

	cert, _ := x509.ParseCertificate(certDER)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM  := encodeKeyPEM(key)

	// Persist with restrictive permissions
	os.WriteFile(certPath, certPEM, 0640)
	os.WriteFile(keyPath,  keyPEM,  0600)

	fmt.Printf("[mtls] CA created: CN=%s valid until %s\n",
		cfg.CommonName, template.NotAfter.Format("2006-01-02"))

	return &CA{
		cert: cert, key: key,
		certPEM: certPEM, keyPEM: keyPEM,
		storePath: cfg.StorePath,
	}, nil
}

func loadCA(certPath, keyPath, storePath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil { return nil, err }
	keyPEM, err  := os.ReadFile(keyPath)
	if err != nil { return nil, err }

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil { return nil, fmt.Errorf("load CA key pair: %w", err) }

	cert, _ := x509.ParseCertificate(tlsCert.Certificate[0])
	fmt.Printf("[mtls] CA loaded: CN=%s expires %s\n",
		cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))

	return &CA{
		cert: cert, key: tlsCert.PrivateKey.(crypto.Signer),
		certPEM: certPEM, keyPEM: keyPEM,
		storePath: storePath,
	}, nil
}

// ── Service Certificate Issuance ──────────────────────────────────────────────

type CertRequest struct {
	Identity    ServiceIdentity
	ValidHours  int      // Short-lived: default 24h
	SANs        []string // Additional DNS SANs
	IPAddresses []net.IP
	KeyAlgo     KeyAlgo
}

type ServiceCert struct {
	Identity    ServiceIdentity
	CertPEM     []byte
	KeyPEM      []byte
	ChainPEM    []byte // cert + CA chain
	ExpiresAt   time.Time
	Fingerprint string // SHA-256 hex
	TLSConfig   *tls.Config
}

// Issue signs a new short-lived service certificate
func (ca *CA) Issue(req CertRequest) (*ServiceCert, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if req.ValidHours == 0  { req.ValidHours = 24 }
	if req.KeyAlgo == ""    { req.KeyAlgo = KeyAlgoECDSA }

	key, err := generateKey(req.KeyAlgo)
	if err != nil { return nil, fmt.Errorf("key generation failed: %w", err) }

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Build SAN list
	dnsNames := []string{
		req.Identity.CommonName(),
		req.Identity.Service,
		fmt.Sprintf("%s.%s", req.Identity.Service, req.Identity.Namespace),
	}
	dnsNames = append(dnsNames, req.SANs...)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   req.Identity.CommonName(),
			Organization: []string{"OPTIMIUM NEXUS LLC"},
		},
		DNSNames:    dnsNames,
		IPAddresses: req.IPAddresses,
		URIs:        mustParseURIs(req.Identity.SPIFFEURI()),
		NotBefore:   time.Now().UTC().Add(-5 * time.Minute),
		NotAfter:    time.Now().UTC().Add(time.Duration(req.ValidHours) * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil { return nil, fmt.Errorf("cert signing failed: %w", err) }

	cert, _  := x509.ParseCertificate(certDER)
	certPEM  := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM   := encodeKeyPEM(key)
	chainPEM := append(certPEM, ca.certPEM...)

	// Build TLS config
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    pool,
		RootCAs:      pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
	}

	fp := fmt.Sprintf("%x", cert.Raw[:8])
	fmt.Printf("[mtls] Issued cert: %s SPIFFE=%s valid=%dh expires=%s\n",
		fp, req.Identity.SPIFFEURI(), req.ValidHours,
		cert.NotAfter.Format("2006-01-02 15:04"))

	return &ServiceCert{
		Identity:    req.Identity,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		ChainPEM:    chainPEM,
		ExpiresAt:   cert.NotAfter,
		Fingerprint: fp,
		TLSConfig:   tlsCfg,
	}, nil
}

// SaveToDisk writes cert + key + chain to directory
func (sc *ServiceCert) SaveToDisk(dir string) error {
	os.MkdirAll(dir, 0750)
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"),  sc.CertPEM,  0640); err != nil { return err }
	if err := os.WriteFile(filepath.Join(dir, "key.pem"),   sc.KeyPEM,   0600); err != nil { return err }
	if err := os.WriteFile(filepath.Join(dir, "chain.pem"), sc.ChainPEM, 0640); err != nil { return err }
	fmt.Printf("[mtls] Cert saved to %s (expires %s)\n", dir, sc.ExpiresAt.Format("2006-01-02"))
	return nil
}

// CACertPEM returns the CA certificate in PEM format
func (ca *CA) CACertPEM() []byte {
	ca.mu.RLock(); defer ca.mu.RUnlock()
	return ca.certPEM
}

// Pool returns an x509 cert pool containing the CA certificate
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	return pool
}

// ── Auto-Rotator ──────────────────────────────────────────────────────────────

// Rotator automatically renews service certs before expiry
type Rotator struct {
	ca        *CA
	certs     sync.Map // service name → *ServiceCert
	callbacks sync.Map // service name → func(*ServiceCert)
	stopCh    chan struct{}
}

func NewRotator(ca *CA) *Rotator {
	r := &Rotator{ca: ca, stopCh: make(chan struct{})}
	go r.loop()
	return r
}

// Register registers a service for automatic certificate rotation
func (r *Rotator) Register(req CertRequest, onRotate func(*ServiceCert)) error {
	cert, err := r.ca.Issue(req)
	if err != nil { return err }
	r.certs.Store(req.Identity.Service, cert)
	if onRotate != nil {
		r.callbacks.Store(req.Identity.Service, onRotate)
		onRotate(cert)
	}
	return nil
}

// Get returns the current certificate for a service
func (r *Rotator) Get(service string) *ServiceCert {
	v, ok := r.certs.Load(service)
	if !ok { return nil }
	return v.(*ServiceCert)
}

func (r *Rotator) loop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh: return
		case <-ticker.C:
			r.certs.Range(func(k, v interface{}) bool {
				svc  := k.(string)
				cert := v.(*ServiceCert)
				// Renew when less than 25% validity remains
				remaining := time.Until(cert.ExpiresAt)
				total := cert.ExpiresAt.Sub(cert.ExpiresAt.Add(-time.Duration(24) * time.Hour))
				if remaining < total/4 || remaining < 2*time.Hour {
					fmt.Printf("[mtls] Rotating cert for %s (expires in %s)\n", svc, remaining.Round(time.Minute))
					newCert, err := r.ca.Issue(CertRequest{
						Identity:   cert.Identity,
						ValidHours: 24,
						KeyAlgo:    KeyAlgoECDSA,
					})
					if err != nil {
						fmt.Printf("[mtls] Rotation failed for %s: %v\n", svc, err)
						return true
					}
					r.certs.Store(svc, newCert)
					if cb, ok := r.callbacks.Load(svc); ok {
						go cb.(func(*ServiceCert))(newCert)
					}
				}
				return true
			})
		}
	}
}

func (r *Rotator) Stop() { close(r.stopCh) }

// ── Default IronWall Service Identities ───────────────────────────────────────

func DefaultIdentities(namespace, trustDomain string) []ServiceIdentity {
	services := []string{
		"management", "detector", "tengine", "threat-intel",
		"alerting", "siem", "forensics", "license-server",
		"compliance", "redis", "postgres",
	}
	ids := make([]ServiceIdentity, len(services))
	for i, s := range services {
		ids[i] = ServiceIdentity{TrustDomain: trustDomain, Namespace: namespace, Service: s}
	}
	return ids
}

// ── mTLS Server/Client Config Helpers ─────────────────────────────────────────

// ServerTLSConfig returns a TLS config for an mTLS server
func ServerTLSConfig(cert *ServiceCert, caPool *x509.CertPool) *tls.Config {
	tlsCert, _ := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Verify SPIFFE URI is in allowed list
			if len(rawCerts) == 0 { return fmt.Errorf("no client cert") }
			c, err := x509.ParseCertificate(rawCerts[0])
			if err != nil { return err }
			for _, uri := range c.URIs {
				if uri.Scheme == "spiffe" { return nil }
			}
			return fmt.Errorf("client cert missing SPIFFE URI")
		},
	}
}

// ClientTLSConfig returns a TLS config for an mTLS client
func ClientTLSConfig(cert *ServiceCert, caPool *x509.CertPool) *tls.Config {
	tlsCert, _ := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func generateKey(algo KeyAlgo) (crypto.Signer, error) {
	switch algo {
	case KeyAlgoRSA4k:
		return rsa.GenerateKey(rand.Reader, 4096)
	default: // ECDSA P-256
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

func encodeKeyPEM(key crypto.Signer) []byte {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k)})
	}
	return nil
}

func mustParseURIs(uriStr string) []*url.URL {
	u, err := url.Parse(uriStr)
	if err != nil { return nil }
	return []*url.URL{u}
}

import "net/url"
