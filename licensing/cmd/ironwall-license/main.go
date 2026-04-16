// AXELUS License CLI
// Usage: axelus-license [command] [flags]
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/keygen"
	lic "github.com/optimiumnexusllc/axelus/licensing/pkg/license"
	"github.com/optimiumnexusllc/axelus/licensing/pkg/validator"
)

var (
	privateKeyHex string
	publicKeyHex  string
	keyID         string
)

func main() {
	root := &cobra.Command{
		Use:   "axelus-license",
		Short: "🛡️  AXELUS License Manager",
		Long: `
╔══════════════════════════════════════════════════════╗
║         AXELUS WAF — License Manager CLI           ║
║         OptiumNexus LLC — Palantir-grade Security    ║
╚══════════════════════════════════════════════════════╝

Manage AXELUS license keys: generate, validate, inspect, revoke.
`,
	}

	root.PersistentFlags().StringVar(&privateKeyHex, "private-key", os.Getenv("IRONWALL_PRIVATE_KEY"), "ED25519 private key (hex) or set IRONWALL_PRIVATE_KEY env")
	root.PersistentFlags().StringVar(&publicKeyHex, "public-key", os.Getenv("IRONWALL_PUBLIC_KEY"), "ED25519 public key (hex) or set IRONWALL_PUBLIC_KEY env")
	root.PersistentFlags().StringVar(&keyID, "key-id", os.Getenv("IRONWALL_KEY_ID"), "Key pair ID")

	root.AddCommand(
		cmdGenKeyPair(),
		cmdIssue(),
		cmdValidate(),
		cmdInspect(),
		cmdHardwareID(),
		cmdListTiers(),
		cmdListFeatures(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ── axelus-license genkey ───────────────────────────────────────────────────

func cmdGenKeyPair() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a new ED25519 signing key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := keygen.GenerateKeyPair()
			if err != nil {
				return err
			}

			fmt.Printf("\n╔═══ NEW IRONWALL SIGNING KEY PAIR ═══╗\n")
			fmt.Printf("  Key ID:      %s\n", kp.ID)
			fmt.Printf("  Public Key:  %s\n", kp.PublicKey)
			fmt.Printf("  Private Key: %s\n", kp.PrivateKey)
			fmt.Printf("  Created:     %s\n", kp.CreatedAt.Format(time.RFC3339))
			fmt.Printf("╚═════════════════════════════════════╝\n\n")
			fmt.Printf("⚠️  Store the PRIVATE KEY securely — it cannot be recovered!\n")
			fmt.Printf("   Set environment variables:\n")
			fmt.Printf("   export IRONWALL_PRIVATE_KEY=%s\n", kp.PrivateKey)
			fmt.Printf("   export IRONWALL_PUBLIC_KEY=%s\n", kp.PublicKey)
			fmt.Printf("   export IRONWALL_KEY_ID=%s\n", kp.ID)

			// Save to file
			out := map[string]string{
				"id":          kp.ID,
				"public_key":  kp.PublicKey,
				"private_key": kp.PrivateKey,
			}
			data, _ := json.MarshalIndent(out, "", "  ")
			fname := fmt.Sprintf("axelus-keypair-%s.json", kp.ID)
			os.WriteFile(fname, data, 0600)
			fmt.Printf("\n   Saved to: %s (chmod 600)\n\n", fname)
			return nil
		},
	}
	return cmd
}

// ── axelus-license issue ────────────────────────────────────────────────────

func cmdIssue() *cobra.Command {
	var (
		tier         string
		licensee     string
		email        string
		domain       string
		hardwareID   string
		validDays    int
		extraFeats   []string
		outputFile   string
		isLifetime   bool
	)

	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a new license key",
		Example: `  # 1-year Enterprise license
  axelus-license issue --tier ENTERPRISE --licensee "Acme Corp" --email admin@acme.com --days 365

  # Lifetime Ultimate license bound to a domain
  axelus-license issue --tier ULTIMATE --licensee "BigCo" --email cto@bigco.com --lifetime --domain bigco.com

  # 30-day Trial
  axelus-license issue --tier TRIAL --licensee "Prospect Inc" --email test@prospect.com --days 30

  # Professional with extra AI feature
  axelus-license issue --tier PROFESSIONAL --licensee "StartupXYZ" --email ops@startup.xyz --days 365 \
    --extra-features ai_threat_hunting`,
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := loadKeyPair()
			if err != nil {
				return err
			}

			t := lic.Tier(strings.ToUpper(tier))
			if _, ok := lic.TierFeatures[t]; !ok {
				return fmt.Errorf("invalid tier %q — valid tiers: COMMUNITY, PROFESSIONAL, ENTERPRISE, ULTIMATE, TRIAL, DEVELOPER", tier)
			}

			days := validDays
			if isLifetime {
				days = 0
			}

			var extras []lic.Feature
			for _, f := range extraFeats {
				extras = append(extras, lic.Feature(f))
			}

			req := keygen.LicenseRequest{
				Tier:          t,
				Licensee:      licensee,
				Email:         email,
				Domain:        domain,
				HardwareID:    hardwareID,
				ValidForDays:  days,
				ExtraFeatures: extras,
				CreatedBy:     "cli",
			}

			license, licFile, err := keygen.Issue(req, kp)
			if err != nil {
				return fmt.Errorf("license generation failed: %w", err)
			}

			// Print summary
			fmt.Printf("\n")
			fmt.Printf("╔══════════════════════════════════════════════════════╗\n")
			fmt.Printf("║           LICENSE ISSUED SUCCESSFULLY                ║\n")
			fmt.Printf("╠══════════════════════════════════════════════════════╣\n")
			fmt.Printf("║  Key:       %-40s ║\n", license.Key)
			fmt.Printf("║  Tier:      %-40s ║\n", string(license.Tier))
			fmt.Printf("║  Licensee:  %-40s ║\n", license.Licensee)
			fmt.Printf("║  Email:     %-40s ║\n", license.Email)
			if license.Domain != "" {
				fmt.Printf("║  Domain:    %-40s ║\n", license.Domain)
			}
			fmt.Printf("║  Issued:    %-40s ║\n", license.IssuedAt.Format("2006-01-02"))
			if license.IsLifetime {
				fmt.Printf("║  Expires:   %-40s ║\n", "LIFETIME (never)")
			} else {
				fmt.Printf("║  Expires:   %-40s ║\n", license.ExpiresAt.Format("2006-01-02")+" ("+strconv.Itoa(license.DaysRemaining())+" days)")
			}
			fmt.Printf("║  ID:        %-40s ║\n", license.ID)
			fmt.Printf("╚══════════════════════════════════════════════════════╝\n\n")

			// Save license file
			if outputFile == "" {
				outputFile = fmt.Sprintf("axelus-%s-%s.lic", strings.ToLower(string(t)), license.Key)
			}
			if err := os.WriteFile(outputFile, []byte(licFile), 0644); err != nil {
				return fmt.Errorf("failed to write license file: %w", err)
			}
			fmt.Printf("✅ License file saved: %s\n\n", outputFile)
			fmt.Printf("📋 Human-readable key: %s\n\n", license.Key)
			return nil
		},
	}

	cmd.Flags().StringVarP(&tier, "tier", "t", "PROFESSIONAL", "License tier: COMMUNITY|PROFESSIONAL|ENTERPRISE|ULTIMATE|TRIAL|DEVELOPER")
	cmd.Flags().StringVarP(&licensee, "licensee", "l", "", "Licensee name (company or person)")
	cmd.Flags().StringVarP(&email, "email", "e", "", "Licensee email address")
	cmd.Flags().StringVarP(&domain, "domain", "d", "", "Bind license to domain (optional)")
	cmd.Flags().StringVar(&hardwareID, "hardware-id", "", "Bind license to hardware fingerprint (optional)")
	cmd.Flags().IntVar(&validDays, "days", 365, "License validity in days (0 = lifetime)")
	cmd.Flags().BoolVar(&isLifetime, "lifetime", false, "Issue a lifetime license (overrides --days)")
	cmd.Flags().StringArrayVar(&extraFeats, "extra-features", nil, "Additional features beyond tier defaults")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output .lic file path")
	cmd.MarkFlagRequired("licensee")
	cmd.MarkFlagRequired("email")
	return cmd
}

// ── axelus-license validate ─────────────────────────────────────────────────

func cmdValidate() *cobra.Command {
	var feature string
	cmd := &cobra.Command{
		Use:   "validate [license-file]",
		Short: "Validate a license file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("cannot read file: %w", err)
			}

			l, err := validator.ParseLicenseFile(string(data))
			if err != nil {
				return fmt.Errorf("parse error: %w", err)
			}

			pubKeys := map[string]string{publicKeyHex: publicKeyHex}
			if keyID != "" {
				pubKeys = map[string]string{keyID: publicKeyHex}
			}
			v, _ := validator.NewValidator(pubKeys, false)
			result := v.Validate(l)

			fmt.Printf("\n%s\n\n", validator.LicenseStatus(l))
			fmt.Printf("  Licensee:  %s <%s>\n", l.Licensee, l.Email)
			fmt.Printf("  Tier:      %s\n", l.Tier)
			fmt.Printf("  Key:       %s\n", l.Key)
			if l.IsLifetime {
				fmt.Printf("  Validity:  LIFETIME\n")
			} else {
				fmt.Printf("  Expires:   %s (%d days)\n", l.ExpiresAt.Format("2006-01-02"), l.DaysRemaining())
			}
			fmt.Printf("  Valid:     %v\n", result.Valid)

			if feature != "" {
				has := l.HasFeature(lic.Feature(feature))
				icon := "✅"
				if !has {
					icon = "❌"
				}
				fmt.Printf("\n  Feature %q: %s %v\n", feature, icon, has)
			}

			for _, e := range result.Errors {
				fmt.Printf("\n❌ ERROR: %s\n", e)
			}
			for _, w := range result.Warnings {
				fmt.Printf("\n⚠️  WARNING: %s\n", w)
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&feature, "feature", "", "Check if a specific feature is available")
	return cmd
}

// ── axelus-license inspect ──────────────────────────────────────────────────

func cmdInspect() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect [license-file]",
		Short: "Show all details and features of a license",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, _ := os.ReadFile(args[0])
			l, err := validator.ParseLicenseFile(string(data))
			if err != nil {
				return err
			}

			fmt.Printf("\n🛡️  AXELUS License Inspection\n")
			fmt.Printf("═══════════════════════════════════════════════════\n")
			fmt.Printf("  ID:         %s\n", l.ID)
			fmt.Printf("  Key:        %s\n", l.Key)
			fmt.Printf("  Tier:       %s\n", l.Tier)
			fmt.Printf("  Licensee:   %s\n", l.Licensee)
			fmt.Printf("  Email:      %s\n", l.Email)
			if l.Domain != "" {
				fmt.Printf("  Domain:     %s\n", l.Domain)
			}
			fmt.Printf("  Issued:     %s\n", l.IssuedAt.Format(time.RFC3339))
			if l.IsLifetime {
				fmt.Printf("  Expires:    LIFETIME\n")
			} else {
				fmt.Printf("  Expires:    %s\n", l.ExpiresAt.Format(time.RFC3339))
			}
			fmt.Printf("  Revoked:    %v\n", l.IsRevoked)

			fmt.Printf("\n  ── LIMITS ──────────────────────────────────────\n")
			limits := l.GetLimits()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "  Max Sites:\t%s\n", fmtLimit(limits.MaxSites))
			fmt.Fprintf(w, "  Max RPS:\t%s\n", fmtLimit(limits.MaxRequestsPerSec))
			fmt.Fprintf(w, "  Max Nodes:\t%s\n", fmtLimit(limits.MaxNodes))
			fmt.Fprintf(w, "  Max Users:\t%s\n", fmtLimit(limits.MaxUsers))
			fmt.Fprintf(w, "  Max Rules:\t%s\n", fmtLimit(limits.MaxCustomRules))
			fmt.Fprintf(w, "  Support:\t%s\n", limits.SupportLevel)
			w.Flush()

			fmt.Printf("\n  ── FEATURES ────────────────────────────────────\n")
			allFeatures := lic.TierFeatures[l.Tier]
			for _, f := range allFeatures {
				fmt.Printf("  ✅ %s\n", f)
			}
			for _, f := range l.ExtraFeatures {
				fmt.Printf("  ✅ %s (extra)\n", f)
			}
			for _, f := range l.DisabledFeatures {
				fmt.Printf("  ❌ %s (disabled)\n", f)
			}

			fmt.Printf("\n  ── SIGNATURE ────────────────────────────────────\n")
			fmt.Printf("  Key ID:     %s\n", l.PublicKeyID)
			fmt.Printf("  Signature:  %s...\n", l.Signature[:32])
			fmt.Println()
			return nil
		},
	}
}

// ── axelus-license hardware-id ───────────────────────────────────────────────

func cmdHardwareID() *cobra.Command {
	return &cobra.Command{
		Use:   "hardware-id",
		Short: "Print the hardware fingerprint of this machine",
		Run: func(cmd *cobra.Command, args []string) {
			id := validator.GetHardwareID()
			fmt.Printf("\n🖥️  Hardware ID: %s\n\n", id)
			fmt.Printf("Use this value when issuing a hardware-bound license:\n")
			fmt.Printf("  axelus-license issue --hardware-id %s ...\n\n", id)
		},
	}
}

// ── axelus-license tiers ────────────────────────────────────────────────────

func cmdListTiers() *cobra.Command {
	return &cobra.Command{
		Use:   "tiers",
		Short: "List all available license tiers and their limits",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("\n🛡️  AXELUS License Tiers\n\n")
			tiers := []lic.Tier{
				lic.TierCommunity, lic.TierProfessional,
				lic.TierEnterprise, lic.TierUltimate,
				lic.TierTrial, lic.TierDeveloper,
			}
			for _, t := range tiers {
				limits := lic.TierLimits[t]
				features := lic.TierFeatures[t]
				fmt.Printf("  ┌─ %s (%d features)\n", t, len(features))
				fmt.Printf("  │  Sites: %s │ RPS: %s │ Nodes: %s │ Support: %s\n",
					fmtLimit(limits.MaxSites), fmtLimit(limits.MaxRequestsPerSec),
					fmtLimit(limits.MaxNodes), limits.SupportLevel)
				fmt.Printf("  └─────────────────────────────────\n\n")
			}
		},
	}
}

// ── axelus-license features ─────────────────────────────────────────────────

func cmdListFeatures() *cobra.Command {
	var tier string
	cmd := &cobra.Command{
		Use:   "features",
		Short: "List all features available for a given tier",
		Run: func(cmd *cobra.Command, args []string) {
			t := lic.Tier(strings.ToUpper(tier))
			features, ok := lic.TierFeatures[t]
			if !ok {
				fmt.Printf("Unknown tier: %s\n", tier)
				return
			}
			fmt.Printf("\n✅ Features included in %s tier:\n\n", t)
			for _, f := range features {
				fmt.Printf("  • %s\n", f)
			}
			fmt.Println()
		},
	}
	cmd.Flags().StringVarP(&tier, "tier", "t", "ENTERPRISE", "Tier to inspect")
	return cmd
}

// ── Helpers ────────────────────────────────────────────────────────────────────

func fmtLimit(v int) string {
	if v == -1 {
		return "unlimited"
	}
	return strconv.Itoa(v)
}

func loadKeyPair() (*keygen.KeyPair, error) {
	if privateKeyHex == "" {
		return nil, fmt.Errorf("private key required: set --private-key or IRONWALL_PRIVATE_KEY env variable\nGenerate a key pair first: axelus-license genkey")
	}
	privBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(privBytes) != 64 {
		return nil, fmt.Errorf("invalid private key: must be 128-char hex (ED25519 private key)")
	}
	pubHex := publicKeyHex
	if pubHex == "" {
		// Derive public key from private key
		pubBytes := privBytes[32:]
		pubHex = hex.EncodeToString(pubBytes)
	}
	id := keyID
	if id == "" {
		id = "default"
	}
	return &keygen.KeyPair{
		ID:         id,
		PublicKey:  pubHex,
		PrivateKey: privateKeyHex,
		CreatedAt:  time.Now(),
	}, nil
}
