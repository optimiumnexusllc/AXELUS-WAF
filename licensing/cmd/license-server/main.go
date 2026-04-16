// AXELUS License Server — standalone HTTP API for license management
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/api"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/keygen"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/store"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/validator"
	"gorm.io/driver/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	log.Println("🛡️  AXELUS License Server starting...")

	// ── Database ─────────────────────────────────────────────────────────────
	var db *gorm.DB
	var err error
	if dsn := os.Getenv("LICENSE_DB_DSN"); dsn != "" {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	} else {
		dbPath := getEnv("LICENSE_DB_PATH", "./axelus-licenses.db")
		db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
		log.Printf("Using SQLite database: %s", dbPath)
	}
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}

	st, err := store.New(db)
	if err != nil {
		log.Fatalf("Store init failed: %v", err)
	}

	// ── Key Pair ──────────────────────────────────────────────────────────────
	privKey := os.Getenv("IRONWALL_PRIVATE_KEY")
	pubKey  := os.Getenv("IRONWALL_PUBLIC_KEY")
	kid     := getEnv("IRONWALL_KEY_ID", "default")

	if privKey == "" {
		log.Println("⚠️  No IRONWALL_PRIVATE_KEY set — generating ephemeral key pair (not for production!)")
		kp, _ := keygen.GenerateKeyPair()
		privKey = kp.PrivateKey
		pubKey  = kp.PublicKey
		kid     = kp.ID
		fmt.Printf("\n   Generated ephemeral key pair:\n")
		fmt.Printf("   export IRONWALL_PRIVATE_KEY=%s\n", privKey)
		fmt.Printf("   export IRONWALL_PUBLIC_KEY=%s\n", pubKey)
		fmt.Printf("   export IRONWALL_KEY_ID=%s\n\n", kid)
	}

	kp := &keygen.KeyPair{
		ID:         kid,
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}

	// ── Validator ─────────────────────────────────────────────────────────────
	v, err := validator.NewValidator(map[string]string{kid: pubKey}, false)
	if err != nil {
		log.Fatalf("Validator init failed: %v", err)
	}

	// ── HTTP Server ───────────────────────────────────────────────────────────
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	// Register license API routes
	srv := api.NewServer(st, kp, v)
	srv.Register(r)

	// Dashboard redirect
	r.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/api/v1/licensing/health")
	})

	port := getEnv("LICENSE_SERVER_PORT", "8090")
	log.Printf("✅ License server ready on :%s", port)
	log.Printf("   Admin API: http://localhost:%s/api/v1/licensing/admin/licenses", port)
	log.Printf("   Validate:  http://localhost:%s/api/v1/licensing/validate", port)
	log.Printf("   Set X-Admin-Key: %s", getEnv("LICENSE_ADMIN_KEY", "(see LICENSE_ADMIN_KEY env)"))

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
