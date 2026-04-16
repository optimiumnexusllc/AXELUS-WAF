<div align="center">

# AXELUS-WAF

<p align="center"><img src="assets/axelus-logo.svg" width="500" alt="AXELUS-WAF"/></p>

### The Palantir of Web Application Firewalls

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE.md)
[![Version](https://img.shields.io/badge/version-v1.0.0-green.svg)](version.json)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](compose.yaml)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![CI](https://github.com/optimiumnexusllc/axelus-waf/actions/workflows/ci.yml/badge.svg)](https://github.com/optimiumnexusllc/axelus-waf/actions)

**AXELUS-WAF** is a next-generation, AI-powered Web Application Firewall engineered for enterprise and government environments. Designed and developed by **OPTIMIUM NEXUS LLC**, AXELUS delivers military-grade threat protection with cryptographic licensing, real-time threat intelligence, Kubernetes-native deployment, full SIEM integration, deep packet inspection, deception layers, and a Palantir-grade security dashboard.

[Features](#-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Licensing](#-licensing) • [Contributing](#-contributing)

---

**Publisher & Developer**
[OPTIMIUM NEXUS LLC](https://www.optimiumnexus.com) · [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

</div>

---

## ✨ Features

### 🔒 Core WAF Engine
- **Semantic AI detection** — ML-based payload analysis, not regex rule lists
- **OWASP Top 10 protection** — SQLi, XSS, RCE, path traversal, XXE, SSRF
- **Bot & crawler protection** with adaptive CAPTCHA challenges
- **Reverse proxy** on Tengine (hardened Nginx fork, battle-tested at scale)
- **Real-time attack dashboard** with live block feed

### 🆕 AXELUS Premium Modules
| Module | Description | Tier |
|--------|-------------|------|
| 🧠 **Threat Intelligence** | AbuseIPDB + Emerging Threats + custom feeds auto-sync | Enterprise+ |
| 🗺️ **GeoIP Blocking** | Country/ASN/CIDR blocking with MaxMind GeoIP2, risk scoring | Enterprise+ |
| 📡 **Multi-Channel Alerting** | Slack, Teams, PagerDuty, Email — severity-based routing | Enterprise+ |
| 📈 **Prometheus + Grafana** | 30+ metrics, pre-built dashboards, AlertManager | Enterprise+ |
| 🔗 **SIEM Forwarding** | Elasticsearch, Splunk HEC, Grafana Loki — real-time log streaming | Enterprise+ |
| 📋 **Compliance Reports** | Automated PCI-DSS, SOC2, ISO 27001 PDF generation | Enterprise+ |
| 🔍 **Deep Packet Inspection** | 7-layer payload analysis — deserial, XXE, NoSQLi, SSTI, polyglot evasion | Enterprise+ |
| 🍯 **Deception Layer** | Honeypots, honeytokens, honey cookies, auto-blacklist | Ultimate |
| ⚡ **Advanced Rate Limiting** | Sliding window, token bucket, leaky bucket — per-IP/token/endpoint | Professional+ |
| 🔬 **Forensics + PCAP** | Full packet capture, session replay, attack timeline reconstruction | Ultimate |
| 🏗️ **Kubernetes / Helm** | HPA, PDB, NetworkPolicies, mTLS, multi-namespace RBAC | Enterprise+ |
| 🔑 **License Management** | ED25519-signed cryptographic licenses, 6 tiers, REST + CLI | All |

---

## 🚀 Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose v2+
- Linux (Ubuntu 20.04+ / Debian 11+ / RHEL 8+)
- Minimum: 2 vCPU · 4 GB RAM | Recommended: 4 vCPU · 8 GB RAM

### One-Line Install
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/optimiumnexusllc/axelus-waf/main/scripts/install.sh)
```

### Manual Install
```bash
git clone https://github.com/optimiumnexusllc/axelus-waf.git
cd IronWAll-WAF
cp .env.example .env && nano .env

# Core only
docker compose up -d

# Core + Monitoring
docker compose -f compose.yaml -f compose.monitoring.yaml up -d

# Full stack (all premium features)
docker compose -f compose.yaml -f compose.monitoring.yaml -f compose.premium.yaml up -d

# Dashboard → https://YOUR_IP:9443
docker logs axelus-mgt | grep "Initial password"
```

---

## 🏗️ Architecture

```
                            Internet
                               │
                      ┌────────▼────────┐
                      │  Tengine WAF    │ ← Port 80/443
                      │ (Reverse Proxy) │
                      └────────┬────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
 ┌──────▼──────┐    ┌──────────▼──────────┐  ┌───────▼──────┐
 │  Semantic   │    │  Deep Packet        │  │   GeoIP +    │
 │  AI Engine  │    │  Inspection (7-lyr) │  │  Rate Limit  │
 └──────┬──────┘    └──────────┬──────────┘  └───────┬──────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐  ┌──────▼──────┐  ┌─────▼──────────┐
     │  Management   │  │  Honeypot / │  │  Forensics +   │
     │  API + Dash   │  │  Deception  │  │  PCAP Capture  │
     └────────┬──────┘  └─────────────┘  └─────┬──────────┘
              │                                  │
     ┌────────▼──────┐                  ┌────────▼──────────┐
     │  PostgreSQL   │                  │  SIEM / Alerting  │
     └───────────────┘                  │  ES·Splunk·Loki   │
                                        └───────────────────┘
              │
     ┌────────▼──────────────────────────────────────────┐
     │           Prometheus + Grafana + AlertManager      │
     └────────────────────────────────────────────────────┘
```

---

## 📦 Service Map

| Container | Role | Port |
|-----------|------|------|
| `axelus-tengine` | WAF reverse proxy | 80, 443 |
| `axelus-mgt` | Management API + Dashboard | 9443 |
| `axelus-detector` | AI semantic detection | internal |
| `axelus-postgres` | Primary database | internal |
| `axelus-redis` | Cache + rate limit + honeypot | internal |
| `axelus-threat-intel` | Feed syncer | internal |
| `axelus-alerting` | Slack/Teams/PD/Email router | internal |
| `axelus-siem` | Log forwarder | internal |
| `axelus-forensics` | PCAP capture + session store | internal |
| `axelus-honeypot` | Deception layer | internal |
| `axelus-license-server` | License API | 8090 |
| `axelus-prometheus` | Metrics | 9090 |
| `axelus-grafana` | Dashboards | 3000 |
| `axelus-alertmanager` | Alert routing | 9093 |

---

## 🔑 Licensing

AXELUS-WAF uses a **cryptographic license system** (ED25519 signatures).

### Tiers
| Tier | Sites | RPS | Support | Key Format |
|------|-------|-----|---------|------------|
| COMMUNITY | 1 | 500/s | Community | `AX-COM-XXXX-XXXX-XXXX-XXXX` |
| PROFESSIONAL | 10 | 5,000/s | Email | `AX-PRO-XXXX-XXXX-XXXX-XXXX` |
| ENTERPRISE | ∞ | 50,000/s | Priority | `AX-ENT-XXXX-XXXX-XXXX-XXXX` |
| ULTIMATE | ∞ | ∞ | 24/7 Dedicated | `AX-ULT-XXXX-XXXX-XXXX-XXXX` |
| TRIAL | ∞ | ∞ | Email (30d) | `AX-TRL-XXXX-XXXX-XXXX-XXXX` |

**→ [License Documentation](licensing/README.md)** · **[Admin Dashboard](licensing/web/dashboard.html)**

---

## 📁 Repository Structure

```
IronWAll-WAF/
├── compose.yaml                # Core stack
├── compose.monitoring.yaml     # Prometheus + Grafana
├── compose.premium.yaml        # Premium modules
├── compose.licensing.yaml      # License server
├── compose.forensics.yaml      # Forensics + PCAP
├── .env.example
├── management/                 # WAF management API (Go)
├── geoip/                      # GeoIP blocking engine
├── licensing/                  # License system (CLI + API + Dashboard)
│   ├── cmd/axelus-license/   # CLI tool
│   ├── cmd/license-server/     # HTTP API
│   ├── pkg/                    # Core packages
│   ├── web/dashboard.html      # Admin dashboard
│   └── tests/                  # Unit tests (40+)
├── premium/
│   ├── threat-intel/           # Feed syncer
│   ├── alerting/               # Multi-channel alerts
│   ├── siem/                   # Log forwarder
│   ├── compliance/             # Report generator
│   ├── deepinspect/            # 7-layer DPI engine
│   ├── honeypot/               # Deception layer
│   ├── ratelimit/              # Advanced rate limiter
│   └── forensics/              # PCAP + session forensics
├── helm/axelus/              # Kubernetes Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
│       ├── management.yaml
│       ├── networkpolicies.yaml
│       ├── forensics.yaml
│       ├── hpa.yaml
│       ├── pdb.yaml
│       └── rbac.yaml
├── monitoring/                 # Prometheus + Alertmanager configs
├── scripts/
│   ├── install.sh
│   ├── backup.sh
│   └── manage.py
└── sdk/                        # Ingress-nginx, Kong, Traefik SDKs
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues → [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

---

## 📄 License

**GNU General Public License v3.0** — See [LICENSE.md](LICENSE.md)

---

<div align="center">

Designed & engineered by **[OPTIMIUM NEXUS LLC](https://www.optimiumnexus.com)**

[www.optimiumnexus.com](https://www.optimiumnexus.com) · [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

</div>
