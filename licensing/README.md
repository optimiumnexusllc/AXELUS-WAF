# 🔑 AXELUS Licensing Module

Enterprise license key generation, validation, and management for AXELUS WAF.

## Architecture

```
licensing/
├── cmd/
│   ├── axelus-license/   ← CLI tool (generate, validate, inspect)
│   └── license-server/     ← Standalone REST API server
├── pkg/
│   ├── license/            ← Tier definitions, feature flags, License struct
│   ├── keygen/             ← ED25519 key generation + license signing
│   ├── validator/          ← Offline/online license validation
│   ├── store/              ← GORM persistence (SQLite or PostgreSQL)
│   └── api/                ← Gin HTTP REST API
└── Dockerfile
```

## License Tiers

| Tier | Sites | RPS | Nodes | Users | Support |
|------|-------|-----|-------|-------|---------|
| **COMMUNITY** | 1 | 500 | 1 | 2 | Community |
| **PROFESSIONAL** | 10 | 5,000 | 2 | 10 | Email |
| **ENTERPRISE** | Unlimited | 50,000 | 10 | 50 | Priority |
| **ULTIMATE** | Unlimited | Unlimited | Unlimited | Unlimited | Dedicated 24/7 |
| **TRIAL** | Unlimited | Unlimited | 3 | 10 | Email (30 days) |
| **DEVELOPER** | 3 | 1,000 | 1 | 5 | Email |

## Features by Tier

| Feature | COM | PRO | ENT | ULT |
|---------|-----|-----|-----|-----|
| Core WAF + OWASP rules | ✅ | ✅ | ✅ | ✅ |
| Bot protection | ✅ | ✅ | ✅ | ✅ |
| Advanced rule engine | ❌ | ✅ | ✅ | ✅ |
| API rate limiting | ❌ | ✅ | ✅ | ✅ |
| SSL offload / mTLS | ❌ | ✅ | ✅ | ✅ |
| Audit log | ❌ | ✅ | ✅ | ✅ |
| GeoIP blocking | ❌ | ❌ | ✅ | ✅ |
| Threat intelligence | ❌ | ❌ | ✅ | ✅ |
| Full alerting (Slack/PD) | ❌ | ❌ | ✅ | ✅ |
| SIEM integration | ❌ | ❌ | ✅ | ✅ |
| Prometheus + Grafana | ❌ | ❌ | ✅ | ✅ |
| Compliance reports | ❌ | ❌ | ✅ | ✅ |
| Kubernetes/Helm | ❌ | ❌ | ✅ | ✅ |
| AI Threat Hunting | ❌ | ❌ | ❌ | ✅ |
| Zero-Day Shield | ❌ | ❌ | ❌ | ✅ |
| DDoS Mitigation | ❌ | ❌ | ❌ | ✅ |
| Deception Layer | ❌ | ❌ | ❌ | ✅ |
| Forensics + PCAP | ❌ | ❌ | ❌ | ✅ |
| Multi-tenancy RBAC | ❌ | ❌ | ❌ | ✅ |
| White-label branding | ❌ | ❌ | ❌ | ✅ |
| Custom integrations | ❌ | ❌ | ❌ | ✅ |

---

## Quick Start — CLI

### 1. Generate a signing key pair (one-time setup)

```bash
# Build the CLI
cd licensing && go build -o axelus-license ./cmd/axelus-license

# Generate key pair — STORE THE PRIVATE KEY SECURELY
./axelus-license genkey

# Output:
# ╔═══ NEW IRONWALL SIGNING KEY PAIR ═══╗
#   Key ID:      a1b2c3d4
#   Public Key:  <hex>
#   Private Key: <hex>  ← KEEP SECRET
# ╚═════════════════════════════════════╝

export IRONWALL_PRIVATE_KEY=<private_key_hex>
export IRONWALL_PUBLIC_KEY=<public_key_hex>
export IRONWALL_KEY_ID=a1b2c3d4
```

### 2. Issue licenses

```bash
# 1-year Enterprise license
./axelus-license issue \
  --tier ENTERPRISE \
  --licensee "Acme Corporation" \
  --email admin@acme.com \
  --days 365

# Lifetime Ultimate license
./axelus-license issue \
  --tier ULTIMATE \
  --licensee "BigCo International" \
  --email cto@bigco.com \
  --lifetime \
  --domain bigco.com

# 30-day Trial
./axelus-license issue \
  --tier TRIAL \
  --licensee "Prospect Inc" \
  --email trial@prospect.com \
  --days 30

# Professional + extra AI feature
./axelus-license issue \
  --tier PROFESSIONAL \
  --licensee "StartupXYZ" \
  --email ops@startup.xyz \
  --days 365 \
  --extra-features ai_threat_hunting

# Hardware-bound license
HWID=$(./axelus-license hardware-id)
./axelus-license issue \
  --tier ENTERPRISE \
  --licensee "Secure Corp" \
  --email sec@corp.com \
  --hardware-id $HWID \
  --days 365
```

### 3. Validate a license

```bash
./axelus-license validate axelus-ENT-XXXX-XXXX-XXXX-XXXX.lic

# Check specific feature
./axelus-license validate axelus-ENT-XXXX.lic --feature geoip_blocking

# Inspect all details
./axelus-license inspect axelus-ENT-XXXX.lic
```

### 4. Explore tiers and features

```bash
./axelus-license tiers
./axelus-license features --tier ULTIMATE
```

---

## License Server API

### Start the server

```bash
export IRONWALL_PRIVATE_KEY=<hex>
export IRONWALL_PUBLIC_KEY=<hex>
export IRONWALL_KEY_ID=default
export LICENSE_ADMIN_KEY=your-strong-admin-key
export LICENSE_DB_PATH=./licenses.db   # SQLite
# Or: LICENSE_DB_DSN=postgres://user:pass@host/db

go run ./cmd/license-server
# → License server ready on :8090
```

### REST API Reference

#### Validate a license (public)
```http
POST /api/v1/licensing/validate
Content-Type: application/json

{
  "license_file": "-----BEGIN IRONWALL LICENSE-----\n...\n-----END IRONWALL LICENSE-----",
  "feature": "geoip_blocking"   // optional: check specific feature
}
```
Response:
```json
{
  "valid": true,
  "tier": "ENTERPRISE",
  "licensee": "Acme Corp",
  "days_remaining": 312,
  "status": "✅ ENTERPRISE (expires 2025-03-15)",
  "feature_requested": "geoip_blocking",
  "feature_available": true
}
```

#### Issue a license (admin)
```http
POST /api/v1/licensing/admin/licenses
X-Admin-Key: your-strong-admin-key
Content-Type: application/json

{
  "tier": "ENTERPRISE",
  "licensee": "Acme Corporation",
  "email": "admin@acme.com",
  "domain": "acme.com",
  "valid_for_days": 365,
  "extra_features": ["ai_threat_hunting"],
  "custom_limits": {
    "max_sites": 50,
    "max_nodes": 20
  },
  "notes": "Enterprise contract #2024-789"
}
```

#### List all licenses (admin)
```http
GET /api/v1/licensing/admin/licenses?tier=ENTERPRISE&page=1&page_size=20
X-Admin-Key: your-strong-admin-key
```

#### Revoke a license (admin)
```http
DELETE /api/v1/licensing/admin/licenses/{id}/revoke
X-Admin-Key: your-strong-admin-key
Content-Type: application/json

{ "reason": "Payment dispute — contract terminated" }
```

#### Download license file (admin)
```http
GET /api/v1/licensing/admin/licenses/{id}/download
X-Admin-Key: your-strong-admin-key
→ Downloads axelus-ENT-XXXX-XXXX-XXXX-XXXX.lic
```

#### Bulk issue (admin)
```http
POST /api/v1/licensing/admin/licenses/bulk
X-Admin-Key: your-strong-admin-key
Content-Type: application/json

[
  {"tier": "PROFESSIONAL", "licensee": "Client A", "email": "a@client.com", "valid_for_days": 365},
  {"tier": "TRIAL", "licensee": "Client B", "email": "b@client.com", "valid_for_days": 30}
]
```

#### Statistics (admin)
```http
GET /api/v1/licensing/admin/stats
X-Admin-Key: your-strong-admin-key
```
Response:
```json
{
  "total": 142,
  "active": 138,
  "revoked": 2,
  "expired": 2,
  "expiring_7d": 3,
  "expiring_30d": 11,
  "by_tier": {
    "COMMUNITY": 40,
    "PROFESSIONAL": 55,
    "ENTERPRISE": 38,
    "ULTIMATE": 7,
    "TRIAL": 2
  }
}
```

---

## Cryptographic Design

- **Algorithm**: ED25519 (fast, secure, small signatures)
- **License format**: JSON payload → SHA256 hash → ED25519 signature → base64 → PEM
- **Offline validation**: any node with the public key can validate without contacting the server
- **Tamper-proof**: modifying any field invalidates the signature
- **Key format**: `IW-{TIER}-{4x4 alphanum segments}` (e.g. `AX-ENT-A3F2-B9K1-M7X4-Z2P8`)

## Security Recommendations

1. **Never commit the private key** — use environment variables or a secrets manager (Vault, AWS Secrets Manager)
2. **Rotate key pairs** annually — keep old public keys for validating existing licenses
3. **Use hardware binding** for high-value Ultimate licenses
4. **Enable TLS** on the license server in production
5. **Set a strong `LICENSE_ADMIN_KEY`** — treat it like a root password
