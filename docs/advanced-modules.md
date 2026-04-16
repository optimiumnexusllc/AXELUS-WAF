# 🧠 AXELUS-WAF — Advanced Modules

**Publisher: OPTIMIUM NEXUS LLC** — [www.optimiumnexus.com](https://www.optimiumnexus.com)
**Contact:** [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

---

## 🧠 Zero-Day Shield (`premium/zerodayshield/`)

**License requirement: Ultimate** (`AX-ULT-*`)

ML-based anomaly detection using Isolation Forest + statistical z-scoring.
Detects previously-unseen attack patterns — no signature updates needed.

### Architecture

```
HTTP Request
     │
     ▼
Feature Extraction (24 dimensions)
  - Structural: path/query/body length, parameter count
  - Entropy:    Shannon entropy of URL, query, body, user-agent
  - Chars:      special char ratio, digit ratio, non-ASCII ratio
  - Structural: bracket nesting, quote balance, encoding layers
  - Behavioural: EWMA req/sec, unique paths ratio, error rate
  - Temporal:   hour, day of week, night-time flag
     │
     ▼
Isolation Forest (100 trees × 256 samples)
  + Z-Score baseline deviation
     │
     ▼
Combined Score: 0.60 × ISO + 0.40 × z-score
     │
     ├─ ≥ 0.85 → ZERO-DAY (block + alert)
     ├─ ≥ 0.70 → ANOMALY  (block or challenge)
     ├─ ≥ 0.50 → SUSPECT  (log + monitor)
     └─ < 0.50 → NORMAL   (pass through)
```

### Key Features

| Feature | Detail |
|---------|--------|
| **Isolation Forest** | Pure-Go, no external ML library needed |
| **EWMA velocity** | Per-IP exponential weighted moving average |
| **Auto-retraining** | Model updates rolling on clean traffic |
| **Warm-up period** | 500 samples before going live (configurable) |
| **Top contributors** | Explains which features drove the score |
| **MITRE mapping** | Auto-links detections to ATT&CK techniques |

### API Endpoints
```http
POST /api/open/zerodayshield/score      # Score a request manually
GET  /api/open/zerodayshield/stats      # Model stats + thresholds
GET  /api/open/zerodayshield/baseline   # Feature names + baseline info
GET  /api/open/zerodayshield/health
```

---

## 🌊 DDoS Mitigation (`premium/ddos/`)

**License requirement: Enterprise+** (`AX-ENT-*` or `AX-ULT-*`)

Volumetric + application-layer DDoS protection with adaptive thresholds.

### Detection Layers

| Layer | Method | Response |
|-------|--------|----------|
| **Per-IP velocity** | EWMA req/sec | Challenge → Block |
| **Subnet /24** | Distributed attack detection | Challenge → Block |
| **Slow HTTP** | Header/body timeout enforcement | Drop connection |
| **Amplification** | Response/request byte ratio > 50× | Block + blacklist |
| **Adaptive** | Auto-tighten thresholds during attack | Dynamic scaling |

### Adaptive Thresholds

```
Traffic ratio vs baseline → multiplier applied to all thresholds
  > 10× baseline  →  0.3×  (very strict — active attack)
  > 5×  baseline  →  0.5×  (tightened)
  > 2×  baseline  →  0.75× (elevated)
  ≤ 2×  baseline  →  1.0×  (normal)
```

### API Endpoints
```http
GET    /api/open/ddos/stats
GET    /api/open/ddos/events?limit=50
GET    /api/open/ddos/blacklist
POST   /api/open/ddos/blacklist/:ip?duration=5m
DELETE /api/open/ddos/blacklist/:ip
GET    /api/open/ddos/velocity/:ip
```

---

## 🌐 Customer Portal (`portal/`)

**Self-service portal for your customers to manage their own licenses.**

### Features

| Feature | Description |
|---------|-------------|
| **Registration** | Sign up, auto-issue trial license |
| **License management** | Issue, download, revoke, update domain |
| **License quota** | Plan-based limits (1 trial → unlimited ultimate) |
| **Usage analytics** | 30-day request/block stats |
| **Billing** | Plan selection, invoice history |
| **Support tickets** | Built-in ticket system |
| **API key** | Per-customer API key with rotation |
| **MFA** | TOTP two-factor authentication |
| **JWT auth** | 24h tokens + refresh, or API key header |

### Plan → License Tier Mapping

| Customer Plan | Max Licenses | Allowed Tiers |
|---------------|-------------|---------------|
| `trial` | 1 | TRIAL, COMMUNITY |
| `pro` | 10 | + PROFESSIONAL |
| `enterprise` | 50 | + ENTERPRISE |
| `ultimate` | Unlimited | ALL (including ULTIMATE) |

### Deploy

```bash
# 1. Generate a JWT secret
export PORTAL_JWT_SECRET=$(openssl rand -base64 48)

# 2. Start portal
docker compose -f compose.yaml -f compose.portal.yaml up -d

# 3. Access at http://YOUR_SERVER:8080/portal
```

### REST API (customer-facing)
```
POST /portal/api/v1/auth/register        # Register + auto-trial
POST /portal/api/v1/auth/login           # Get JWT
GET  /portal/api/v1/account              # Account info
GET  /portal/api/v1/licenses             # List licenses
POST /portal/api/v1/licenses             # Request new license
GET  /portal/api/v1/licenses/:key/download  # Download .lic file
POST /portal/api/v1/licenses/:key/renew  # Request renewal
GET  /portal/api/v1/usage/summary        # 30d usage stats
GET  /portal/api/v1/billing/invoices     # Invoice history
POST /portal/api/v1/support/tickets      # Open ticket
GET  /portal/api/v1/notifications        # Expiry alerts
```
