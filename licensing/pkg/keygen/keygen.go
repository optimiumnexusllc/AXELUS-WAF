// Package keygen handles cryptographic license key generation.
// Uses ED25519 signatures for tamper-proof, offline-verifiable licenses.
package keygen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	lic "github.com/optimiumnexusllc/ironwall/licensing/pkg/license"
)

// KeyPair holds the ED25519 key pair used to sign licenses
type KeyPair struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`  // hex-encoded
	PrivateKey string `json:"private_key"` // hex-encoded (KEEP SECRET)
	CreatedAt  time.Time `json:"created_at"`
}

// GenerateKeyPair creates a new ED25519 signing key pair
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ED25519 key pair: %w", err)
	}
	id := uuid.New().String()[:8]
	return &KeyPair{
		ID:         id,
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: hex.EncodeToString(priv),
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// ── License Key Format ────────────────────────────────────────────────────────
// Format: IW-{TIER_PREFIX}-{XXXX}-{XXXX}-{XXXX}-{XXXX}
// Example: IW-ENT-A3F2-B9K1-M7X4-Z2P8

const keyCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0,O,1,I to avoid confusion

func tierPrefix(t lic.Tier) string {
	switch t {
	case lic.TierCommunity:    return "COM"
	case lic.TierProfessional: return "PRO"
	case lic.TierEnterprise:   return "ENT"
	case lic.TierUltimate:     return "ULT"
	case lic.TierTrial:        return "TRL"
	case lic.TierDeveloper:    return "DEV"
	default:                   return "UNK"
	}
}

func randomSegment(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyCharset))))
		if err != nil {
			return "", err
		}
		result[i] = keyCharset[n.Int64()]
	}
	return string(result), nil
}

func generateHumanKey(tier lic.Tier) (string, error) {
	var segments []string
	for i := 0; i < 4; i++ {
		seg, err := randomSegment(4)
		if err != nil {
			return "", err
		}
		segments = append(segments, seg)
	}
	return fmt.Sprintf("IW-%s-%s", tierPrefix(tier), strings.Join(segments, "-")), nil
}

// ── License Payload (what gets signed) ────────────────────────────────────────

type LicensePayload struct {
	ID           string       `json:"id"`
	Key          string       `json:"key"`
	Tier         lic.Tier     `json:"tier"`
	Licensee     string       `json:"licensee"`
	Email        string       `json:"email"`
	Domain       string       `json:"domain,omitempty"`
	HardwareID   string       `json:"hardware_id,omitempty"`
	IssuedAt     int64        `json:"issued_at"`
	ExpiresAt    int64        `json:"expires_at"` // 0 = never
	IsLifetime   bool         `json:"is_lifetime"`
	ExtraFeatures []lic.Feature `json:"extra_features,omitempty"`
	DisabledFeatures []lic.Feature `json:"disabled_features,omitempty"`
	CustomLimits *lic.Limits  `json:"custom_limits,omitempty"`
	PublicKeyID  string       `json:"public_key_id"`
}

func payloadHash(p LicensePayload) ([]byte, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// ── LicenseRequest ────────────────────────────────────────────────────────────

type LicenseRequest struct {
	Tier             lic.Tier
	Licensee         string
	Email            string
	Domain           string        // optional: bind to domain
	HardwareID       string        // optional: bind to machine
	ValidForDays     int           // 0 = lifetime
	ExtraFeatures    []lic.Feature // features to add on top of tier
	DisabledFeatures []lic.Feature // features to remove from tier
	CustomLimits     *lic.Limits
	Notes            string
	CreatedBy        string
}

// Issue generates and cryptographically signs a new license
func Issue(req LicenseRequest, kp *KeyPair) (*lic.License, string, error) {
	privBytes, err := hex.DecodeString(kp.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("invalid private key: %w", err)
	}
	privKey := ed25519.PrivateKey(privBytes)

	id := uuid.New().String()
	humanKey, err := generateHumanKey(req.Tier)
	if err != nil {
		return nil, "", fmt.Errorf("key generation failed: %w", err)
	}

	now := time.Now().UTC()
	var expiresAt time.Time
	isLifetime := req.ValidForDays == 0
	if !isLifetime {
		expiresAt = now.Add(time.Duration(req.ValidForDays) * 24 * time.Hour)
	}

	payload := LicensePayload{
		ID:               id,
		Key:              humanKey,
		Tier:             req.Tier,
		Licensee:         req.Licensee,
		Email:            req.Email,
		Domain:           req.Domain,
		HardwareID:       req.HardwareID,
		IssuedAt:         now.Unix(),
		ExpiresAt:        expiresAt.Unix(),
		IsLifetime:       isLifetime,
		ExtraFeatures:    req.ExtraFeatures,
		DisabledFeatures: req.DisabledFeatures,
		CustomLimits:     req.CustomLimits,
		PublicKeyID:      kp.ID,
	}
	if isLifetime {
		payload.ExpiresAt = 0
	}

	hash, err := payloadHash(payload)
	if err != nil {
		return nil, "", fmt.Errorf("payload hash failed: %w", err)
	}

	sig := ed25519.Sign(privKey, hash)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	license := &lic.License{
		ID:               id,
		Key:              humanKey,
		Tier:             req.Tier,
		Licensee:         req.Licensee,
		Email:            req.Email,
		Domain:           req.Domain,
		HardwareID:       req.HardwareID,
		IssuedAt:         now,
		ExpiresAt:        expiresAt,
		IsLifetime:       isLifetime,
		ExtraFeatures:    req.ExtraFeatures,
		DisabledFeatures: req.DisabledFeatures,
		CustomLimits:     req.CustomLimits,
		IsRevoked:        false,
		Signature:        sigB64,
		PublicKeyID:      kp.ID,
		Notes:            req.Notes,
		CreatedBy:        req.CreatedBy,
	}

	// Encode the full license as a portable license file (base64 JSON)
	licData, _ := json.Marshal(license)
	licFile := base64.StdEncoding.EncodeToString(licData)
	encoded := fmt.Sprintf("-----BEGIN IRONWALL LICENSE-----\n%s\n-----END IRONWALL LICENSE-----",
		wordWrap(licFile, 64))

	return license, encoded, nil
}

func wordWrap(s string, width int) string {
	var sb strings.Builder
	for i, c := range s {
		if i > 0 && i%width == 0 {
			sb.WriteRune('\n')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
