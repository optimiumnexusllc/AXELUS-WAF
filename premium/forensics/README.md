# 🔬 AXELUS-WAF — Forensics & PCAP Module

**Publisher: OPTIMIUM NEXUS LLC** — [www.optimiumnexus.com](https://www.optimiumnexus.com)
**Contact:** [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

> **License requirement:** Ultimate tier (`AX-ULT-*`)

---

## Overview

The AXELUS Forensics module provides Palantir-grade network packet capture,
session reconstruction, attack timeline building, and cryptographic evidence packaging.

```
premium/forensics/
├── pkg/
│   ├── capture/   ← Ring-buffer PCAP engine
│   ├── analyzer/  ← Timeline, session replay, evidence packaging
│   └── api/       ← REST API (Gin)
├── Dockerfile
└── go.mod
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Ring Buffer** | 100k-packet lock-free circular buffer, O(1) write |
| **PCAP Export** | Native `.pcap` files — open in Wireshark |
| **Capture Modes** | `full` · `session` · `threat` · `header` (GDPR) |
| **BPF Filtering** | Berkeley Packet Filter — limit capture scope |
| **File Rotation** | Auto-rotate at configurable size, 30-day retention |
| **Session Tracking** | Reconstruct full TCP sessions from packets |
| **Attack Timeline** | Group events by attacker IP, build MITRE ATT&CK timeline |
| **Session Replay** | Side-by-side hex + printable request/response reconstruction |
| **Evidence Package** | Sealed ZIP with SHA-256 manifest + chain of custody |
| **MITRE Mapping** | Auto-map attack types to MITRE ATT&CK technique IDs |
| **REST API** | Full CRUD — live packets, sessions, timelines, PCAP download |

---

## Quick Start

### Docker Compose
```bash
# Add forensics to your stack
docker compose \
  -f compose.yaml \
  -f compose.premium.yaml \
  -f compose.forensics.yaml \
  up -d

# Verify
docker logs axelus-forensics
curl http://localhost:8095/health
```

### Kubernetes
```yaml
# values.yaml
forensics:
  enabled: true
  captureMode: threat
  retentionDays: 30
  storage:
    size: 100Gi
```

---

## REST API Reference

All endpoints require `X-Admin-Key` header.

### Live Monitoring
```http
GET /api/open/forensics/stats
GET /api/open/forensics/packets/live?limit=100&threat_only=true
```

### Session Management
```http
GET    /api/open/forensics/sessions
GET    /api/open/forensics/sessions/:id
GET    /api/open/forensics/sessions/:id/pcap       → download .pcap
GET    /api/open/forensics/sessions/:id/replay     → reconstructed conversation
POST   /api/open/forensics/sessions/:id/close
```

### Attack Timelines
```http
POST   /api/open/forensics/timelines
GET    /api/open/forensics/timelines
GET    /api/open/forensics/timelines/:id
```

### Evidence Packages
```http
POST   /api/open/forensics/evidence                → create sealed ZIP
GET    /api/open/forensics/evidence/:id            → download ZIP
GET    /api/open/forensics/evidence/:id/manifest   → SHA-256 manifest
```

### PCAP File Management
```http
GET    /api/open/forensics/pcap/files
GET    /api/open/forensics/pcap/files/:name        → download
DELETE /api/open/forensics/pcap/cleanup
```

---

## Evidence Package Format

Every evidence package is a sealed ZIP containing:

```
ev-pkg-INC-2024-001-1234567890.zip
├── manifest.json        ← Incident metadata + chain of custody
├── timeline.json        ← Full attack timeline with MITRE mapping
├── events.csv           ← All events in CSV format
├── threat-2024-01-15.pcap
└── session-abc123.pcap
```

The ZIP hash (SHA-256) is stored in `*.manifest.json` for tamper detection.

---

## Capture Modes

| Mode | Captures | GDPR |
|------|----------|------|
| `full` | All packets | ⚠️ Review |
| `session` | Complete TCP sessions only | ⚠️ Review |
| `threat` | Only threat-scored packets (≥30) | ✅ Better |
| `header` | Headers only — no body | ✅ Compliant |

---

## MITRE ATT&CK Mapping

| Attack Type | MITRE Technique |
|-------------|-----------------|
| sql_injection | T1190 — Exploit Public-Facing Application |
| xss | T1059.007 — JavaScript Execution |
| rce | T1190 + T1059 — Exploit + Execution |
| path_traversal | T1083 — File and Directory Discovery |
| ssrf | T1090 — Proxy / Internal Network Pivot |
| deserialization | T1190 — XML External Entity |
| honeypot_trigger | T1595 — Active Scanning |
| brute_force | T1110 — Brute Force |
