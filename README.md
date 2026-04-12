<div align="center">

# 🛡️ IronWall

### Enterprise-Grade Web Application Firewall

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE.md)
[![Version](https://img.shields.io/badge/version-v1.0.0-green.svg)](version.json)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](compose.yaml)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![CI](https://github.com/optimiumnexusllc/IronWall/actions/workflows/ci.yml/badge.svg)](https://github.com/optimiumnexusllc/IronWall/actions)

**IronWall** is a next-generation, AI-powered Web Application Firewall (WAF) designed for enterprise environments. Built on top of [SafeLine CE](https://github.com/chaitin/safeline), IronWall extends the foundation with advanced threat intelligence, real-time monitoring, Kubernetes-native deployment, SIEM integration, and a premium security dashboard.

[Features](#features) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## ✨ Features

### Core (inherited from SafeLine CE)
- 🔒 **Semantic-based WAF engine** — AI-driven detection, not rule-based
- 🚫 **OWASP Top 10 protection** — SQLi, XSS, RCE, path traversal, and more
- 🤖 **Bot & crawler protection** with CAPTCHA challenges
- 🌐 **Reverse proxy** based on Tengine (battle-tested Nginx fork)
- 📊 **Real-time attack dashboard**

### 🆕 IronWall Premium Additions
- 🧠 **Threat Intelligence Feeds** — automatic sync with AbuseIPDB, Emerging Threats, and custom feeds
- 📡 **Real-time Alerting** — Slack, Teams, PagerDuty, and email webhooks on critical events
- 📈 **Prometheus + Grafana monitoring** — 30+ pre-built metrics and dashboards
- 🗺️ **GeoIP Blocking** — country/region-level access control with MaxMind GeoIP2
- 🔑 **Advanced API Rate Limiting** — per-IP, per-token, per-endpoint rate controls
- 🏗️ **Kubernetes-native** — full Helm chart with HPA, PDB, and network policies
- 🔗 **SIEM Integration** — Splunk, Elasticsearch/OpenSearch, Loki log forwarding
- 🔐 **mTLS Support** — mutual TLS for upstream service authentication
- 📋 **Compliance Reports** — automated PCI-DSS, SOC2, ISO 27001 report generation
- 🔄 **GitOps-ready** — declarative configuration with CI/CD pipeline templates
- 🛡️ **DDoS Mitigation** — adaptive rate limiting with automatic IP reputation scoring
- 🔍 **Deep Packet Inspection** — enhanced payload analysis with custom rule engine

---

## 🚀 Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose v2+
- Linux (Ubuntu 20.04+ / Debian 11+ / RHEL 8+ recommended)
- 2 CPU cores, 4GB RAM minimum (8GB+ recommended for production)

### One-Line Install
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/optimiumnexusllc/IronWall/main/scripts/install.sh)
```

### Manual Install
```bash
# 1. Clone the repository
git clone https://github.com/optimiumnexusllc/IronWall.git
cd IronWall

# 2. Configure environment
cp .env.example .env
nano .env  # Set your passwords and subnet

# 3. Start IronWall (core only)
docker compose up -d

# 4. Start with monitoring stack
docker compose -f compose.yaml -f compose.monitoring.yaml up -d

# 5. Start with all premium features
docker compose -f compose.yaml -f compose.monitoring.yaml -f compose.premium.yaml up -d

# 6. Access the dashboard
# https://YOUR_SERVER_IP:9443
docker logs safeline-mgt | grep "Initial password"
```

---

## 🏗️ Architecture

```
                          Internet
                             │
                    ┌────────▼────────┐
                    │   Tengine WAF   │  ← IronWall Core (port 80/443)
                    │  (Reverse Proxy)│
                    └────────┬────────┘
                             │
              ┌──────────────▼──────────────┐
              │       Detection Engine       │
              │  AI Semantic Analysis + DPI  │
              └──────────────┬──────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
  ┌──────▼──────┐   ┌────────▼────────┐  ┌──────▼──────┐
  │  Management │   │  Threat Intel   │  │  Monitoring  │
  │   API (mgt) │   │  Feed Syncer    │  │  Prometheus  │
  └──────┬──────┘   └────────┬────────┘  └──────┬──────┘
         │                   │                   │
  ┌──────▼──────┐   ┌────────▼────────┐  ┌──────▼──────┐
  │ PostgreSQL  │   │   Redis Cache   │  │   Grafana    │
  └─────────────┘   └─────────────────┘  └─────────────┘
         │
  ┌──────▼──────────────────────────────────┐
  │              SIEM / Alerting             │
  │   Splunk │ Elasticsearch │ Slack │ PD   │
  └──────────────────────────────────────────┘
```

---

## 📦 Services

| Service | Description | Port |
|---------|-------------|------|
| `ironwall-tengine` | WAF reverse proxy engine | 80, 443 |
| `ironwall-mgt` | Management API & Web Dashboard | 9443 |
| `ironwall-detector` | AI-based attack detection | internal |
| `ironwall-postgres` | Primary database | internal |
| `ironwall-redis` | Cache & session store | internal |
| `ironwall-threat-intel` | Threat intelligence syncer | internal |
| `ironwall-prometheus` | Metrics collection | 9090 |
| `ironwall-grafana` | Monitoring dashboards | 3000 |
| `ironwall-alertmanager` | Alert routing | 9093 |

---

## 🆕 Premium Features Guide

### Threat Intelligence
```bash
# Configure threat feeds in .env
THREAT_INTEL_ABUSEIPDB_KEY=your_api_key
THREAT_INTEL_UPDATE_INTERVAL=3600  # seconds

# Manual sync
docker exec ironwall-threat-intel ./sync --force
```

### GeoIP Blocking
Configure in the dashboard under **Security → GeoIP Rules**, or via API:
```bash
curl -X POST https://localhost:9443/api/open/geoip/rules \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"action":"block","countries":["KP","IR"]}'
```

### Slack Alerts
```bash
# In .env
ALERT_SLACK_WEBHOOK=https://hooks.slack.com/services/xxx/yyy/zzz
ALERT_SLACK_CHANNEL=#security-alerts
ALERT_THRESHOLD_SEVERITY=high  # low|medium|high|critical
```

### Prometheus Metrics
Available at `http://localhost:9090` — pre-built dashboards at `http://localhost:3000`.

Key metrics:
- `ironwall_requests_total` — total proxied requests
- `ironwall_attacks_blocked_total` — blocked attacks by type
- `ironwall_threat_intel_matches_total` — IP reputation hits
- `ironwall_rate_limit_triggered_total` — rate limit events

---

## 📁 Repository Structure

```
IronWall/
├── compose.yaml              # Main Docker Compose (core services)
├── compose.monitoring.yaml   # Monitoring stack (Prometheus + Grafana)
├── compose.premium.yaml      # Premium features (Redis, threat-intel, alerting)
├── .env.example              # Environment variable template
├── management/               # Management API (Go)
├── monitoring/               # Prometheus + Grafana configs
│   ├── prometheus/
│   ├── grafana/dashboards/
│   └── alertmanager/
├── premium/                  # Premium feature modules
│   ├── threat-intel/         # Threat intelligence syncer (Go)
│   ├── geoip/                # GeoIP blocking module
│   ├── alerting/             # Multi-channel alerting service
│   └── compliance/           # Compliance report generator
├── helm/                     # Kubernetes Helm chart
│   └── ironwall/
├── scripts/                  # Installation & management scripts
├── sdk/                      # Integration SDKs
└── yanshi/                   # Traffic replay tool
```

---

## 🤝 Contributing

IronWall welcomes contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit: `git commit -m 'feat: add AmazingFeature'`
4. Push: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📄 License

IronWall is licensed under the **GNU General Public License v3.0**.
Based on [SafeLine CE](https://github.com/chaitin/safeline) by Chaitin Technology.
See [LICENSE.md](LICENSE.md) for details.

---

<div align="center">
Made with ❤️ by <a href="https://github.com/optimiumnexusllc">OptiumNexus LLC</a>
</div>
