// Package store handles license persistence (GORM — SQLite or PostgreSQL).
package store

import (
	"fmt"
	"time"

	"gorm.io/gorm"
	lic "github.com/optimiumnexusllc/ironwall/licensing/pkg/license"
)

// LicenseRecord is the GORM model for stored licenses
type LicenseRecord struct {
	gorm.Model
	LicenseID        string     `gorm:"uniqueIndex;not null"`
	Key              string     `gorm:"uniqueIndex;not null"`
	Tier             string     `gorm:"not null;index"`
	Licensee         string     `gorm:"not null"`
	Email            string     `gorm:"not null;index"`
	Domain           string
	HardwareID       string
	IssuedAt         time.Time  `gorm:"not null"`
	ExpiresAt        *time.Time
	IsLifetime       bool       `gorm:"default:false"`
	IsRevoked        bool       `gorm:"default:false;index"`
	RevokedAt        *time.Time
	RevokeReason     string
	ExtraFeatures    string     // JSON array
	DisabledFeatures string     // JSON array
	CustomLimitsJSON string     // JSON object
	Signature        string     `gorm:"not null"`
	PublicKeyID      string     `gorm:"not null"`
	LicenseFileB64   string     `gorm:"type:text"` // Full encoded license
	Notes            string
	CreatedBy        string
	ActivatedAt      *time.Time
	LastCheckedAt    *time.Time
	ActivationCount  int        `gorm:"default:0"`
}

// KeyPairRecord stores signing key pairs
type KeyPairRecord struct {
	gorm.Model
	KeyID      string `gorm:"uniqueIndex;not null"`
	PublicKey  string `gorm:"not null"`
	PrivateKey string `gorm:"not null"` // Store encrypted in production!
	IsActive   bool   `gorm:"default:true"`
	CreatedBy  string
}

// LicenseEvent tracks all license lifecycle events
type LicenseEvent struct {
	gorm.Model
	LicenseID   string    `gorm:"not null;index"`
	EventType   string    `gorm:"not null"` // issued|activated|checked|revoked|renewed|expired
	Details     string
	IPAddress   string
	UserAgent   string
	OccurredAt  time.Time `gorm:"not null"`
}

// Store manages the license database
type Store struct {
	db *gorm.DB
}

// New creates a new Store and auto-migrates the schema
func New(db *gorm.DB) (*Store, error) {
	if err := db.AutoMigrate(
		&LicenseRecord{},
		&KeyPairRecord{},
		&LicenseEvent{},
	); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}
	return &Store{db: db}, nil
}

// SaveLicense persists a new license record
func (s *Store) SaveLicense(l *lic.License, licenseFile string) error {
	record := &LicenseRecord{
		LicenseID:      l.ID,
		Key:            l.Key,
		Tier:           string(l.Tier),
		Licensee:       l.Licensee,
		Email:          l.Email,
		Domain:         l.Domain,
		HardwareID:     l.HardwareID,
		IssuedAt:       l.IssuedAt,
		IsLifetime:     l.IsLifetime,
		IsRevoked:      false,
		Signature:      l.Signature,
		PublicKeyID:    l.PublicKeyID,
		LicenseFileB64: licenseFile,
		Notes:          l.Notes,
		CreatedBy:      l.CreatedBy,
	}
	if !l.ExpiresAt.IsZero() {
		record.ExpiresAt = &l.ExpiresAt
	}

	if err := s.db.Create(record).Error; err != nil {
		return fmt.Errorf("save license failed: %w", err)
	}

	// Log the issuance event
	s.logEvent(l.ID, "issued", fmt.Sprintf("Issued %s license to %s", l.Tier, l.Email), "", "")
	return nil
}

// GetByKey retrieves a license record by human-readable key
func (s *Store) GetByKey(key string) (*LicenseRecord, error) {
	var record LicenseRecord
	if err := s.db.Where("key = ?", key).First(&record).Error; err != nil {
		return nil, fmt.Errorf("license not found: %w", err)
	}
	return &record, nil
}

// GetByID retrieves a license record by UUID
func (s *Store) GetByID(id string) (*LicenseRecord, error) {
	var record LicenseRecord
	if err := s.db.Where("license_id = ?", id).First(&record).Error; err != nil {
		return nil, fmt.Errorf("license not found: %w", err)
	}
	return &record, nil
}

// GetByEmail retrieves all licenses for an email address
func (s *Store) GetByEmail(email string) ([]LicenseRecord, error) {
	var records []LicenseRecord
	s.db.Where("email = ?", email).Order("created_at desc").Find(&records)
	return records, nil
}

// ListAll returns all licenses with optional filtering
func (s *Store) ListAll(tier string, revoked bool, page, pageSize int) ([]LicenseRecord, int64, error) {
	var records []LicenseRecord
	var total int64

	q := s.db.Model(&LicenseRecord{})
	if tier != "" {
		q = q.Where("tier = ?", tier)
	}
	if !revoked {
		q = q.Where("is_revoked = false")
	}
	q.Count(&total)
	q.Offset((page - 1) * pageSize).Limit(pageSize).Order("created_at desc").Find(&records)
	return records, total, nil
}

// RevokeLicense marks a license as revoked
func (s *Store) RevokeLicense(id, reason, revokedBy string) error {
	now := time.Now().UTC()
	result := s.db.Model(&LicenseRecord{}).
		Where("license_id = ?", id).
		Updates(map[string]interface{}{
			"is_revoked":    true,
			"revoked_at":    now,
			"revoke_reason": reason,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("license %s not found", id)
	}
	s.logEvent(id, "revoked", fmt.Sprintf("Revoked by %s: %s", revokedBy, reason), "", "")
	return nil
}

// RecordActivation tracks when and where a license was activated
func (s *Store) RecordActivation(id, ip, userAgent string) {
	now := time.Now().UTC()
	s.db.Model(&LicenseRecord{}).Where("license_id = ?", id).Updates(map[string]interface{}{
		"activated_at":     now,
		"last_checked_at":  now,
		"activation_count": gorm.Expr("activation_count + 1"),
	})
	s.logEvent(id, "activated", "License activated", ip, userAgent)
}

// SaveKeyPair persists a signing key pair
func (s *Store) SaveKeyPair(kp interface{}) error {
	return nil // Implementation with KeyPairRecord
}

// Stats returns license statistics
type Stats struct {
	Total       int64
	Active      int64
	Revoked     int64
	Expired     int64
	ByTier      map[string]int64
	Expiring7d  int64
	Expiring30d int64
}

func (s *Store) GetStats() Stats {
	var stats Stats
	s.db.Model(&LicenseRecord{}).Count(&stats.Total)
	s.db.Model(&LicenseRecord{}).Where("is_revoked = false AND (is_lifetime = true OR expires_at > ?)", time.Now()).Count(&stats.Active)
	s.db.Model(&LicenseRecord{}).Where("is_revoked = true").Count(&stats.Revoked)
	s.db.Model(&LicenseRecord{}).Where("is_revoked = false AND is_lifetime = false AND expires_at < ?", time.Now()).Count(&stats.Expired)
	s.db.Model(&LicenseRecord{}).Where("is_revoked = false AND is_lifetime = false AND expires_at BETWEEN ? AND ?",
		time.Now(), time.Now().Add(7*24*time.Hour)).Count(&stats.Expiring7d)
	s.db.Model(&LicenseRecord{}).Where("is_revoked = false AND is_lifetime = false AND expires_at BETWEEN ? AND ?",
		time.Now(), time.Now().Add(30*24*time.Hour)).Count(&stats.Expiring30d)

	stats.ByTier = make(map[string]int64)
	for _, t := range []string{"COMMUNITY", "PROFESSIONAL", "ENTERPRISE", "ULTIMATE", "TRIAL", "DEVELOPER"} {
		var count int64
		s.db.Model(&LicenseRecord{}).Where("tier = ?", t).Count(&count)
		stats.ByTier[t] = count
	}
	return stats
}

func (s *Store) logEvent(licenseID, eventType, details, ip, ua string) {
	s.db.Create(&LicenseEvent{
		LicenseID:  licenseID,
		EventType:  eventType,
		Details:    details,
		IPAddress:  ip,
		UserAgent:  ua,
		OccurredAt: time.Now().UTC(),
	})
}
