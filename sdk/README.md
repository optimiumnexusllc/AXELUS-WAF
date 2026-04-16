# 🔗 AXELUS-WAF — API Gateway Integration SDK

**Publisher: OPTIMIUM NEXUS LLC** — [www.optimiumnexus.com](https://www.optimiumnexus.com)
**Contact:** [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

---

## Supported API Gateways

| Gateway | Integration Type | License Tier |
|---------|-----------------|--------------|
| **Kong** | Native Lua plugin | Professional+ |
| **Traefik** | Go middleware plugin | Professional+ |
| **Nginx / ingress-nginx** | Lua module (see `sdk/lua-resty-t1k`) | All tiers |
| **Traefik** | Declarative middleware chain | Professional+ |

---

## Kong Integration

### Installation

```bash
# 1. Copy plugin files to Kong
cp -r sdk/kong/plugins/axelus-waf /usr/local/share/lua/5.1/kong/plugins/

# 2. Enable in kong.conf
echo 'plugins = bundled,axelus-waf' >> /etc/kong/kong.conf

# 3. Reload Kong
kong reload

# 4. Apply declarative config (deck)
export IRONWALL_ADMIN_KEY=your-admin-key
deck sync -s sdk/kong/deck/kong-axelus.yaml
```

### Enable on a Service
```bash
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "axelus-waf",
    "config": {
      "axelus_host": "axelus-mgt",
      "axelus_port": 9443,
      "admin_key": "YOUR_ADMIN_KEY",
      "geoip_enabled": true,
      "threat_intel_enabled": true,
      "dpi_enabled": true,
      "rate_limit_enabled": true,
      "block_status": 403,
      "fail_open": true
    }
  }'
```

### Enable on a Route
```bash
curl -X POST http://kong-admin:8001/routes/my-route/plugins \
  -d "name=axelus-waf" \
  -d "config.axelus_host=axelus-mgt" \
  -d "config.admin_key=YOUR_ADMIN_KEY" \
  -d "config.dpi_enabled=true"
```

### Plugin Config Reference
| Field | Default | Description |
|-------|---------|-------------|
| `axelus_host` | required | AXELUS management API hostname |
| `axelus_port` | 9443 | Management API port |
| `admin_key` | required | AXELUS admin API key |
| `timeout_ms` | 50 | Max ms to wait for AXELUS response |
| `geoip_enabled` | true | Enable GeoIP country blocking |
| `threat_intel_enabled` | true | Enable threat intelligence IP check |
| `dpi_enabled` | true | Enable deep packet inspection |
| `rate_limit_enabled` | true | Enable rate limiting enforcement |
| `honeypot_enabled` | false | Enable honeypot path detection |
| `inspect_body` | true | Include request body in inspection |
| `block_status` | 403 | HTTP status for blocked requests |
| `fail_open` | true | Allow traffic if AXELUS unreachable |
| `license_check_header` | — | Header to check for AXELUS license key |

---

## Traefik Integration

### Installation

```bash
# 1. Add static config (traefik.yaml)
cp sdk/traefik/traefik-static.yaml /etc/traefik/traefik.yaml

# 2. Add dynamic config
cp sdk/traefik/middleware/traefik-dynamic.yaml /etc/traefik/dynamic/axelus.yaml

# 3. Set environment variable
export IRONWALL_ADMIN_KEY=your-admin-key

# 4. Restart Traefik
systemctl restart traefik
```

### Label your Docker services
```yaml
# docker-compose.yaml
services:
  my-api:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.my-api.rule=Host(`api.example.com`)"
      - "traefik.http.routers.my-api.entrypoints=websecure"
      - "traefik.http.routers.my-api.middlewares=axelus-chain-full@file"
      - "traefik.http.routers.my-api.tls.certresolver=letsencrypt"
```

### Middleware Presets
| Preset | Checks | Use Case |
|--------|--------|----------|
| `axelus-full` | GeoIP + TI + DPI + RL + Honeypot | Public web apps, high security |
| `axelus-lite` | GeoIP + Rate limit only | Static assets, low-risk routes |
| `axelus-api` | TI + DPI + Rate limit | API endpoints, fail-closed |
| `axelus-chain-full` | Full + security headers + compress | Recommended for most routes |
| `axelus-chain-api` | API + security headers | REST API endpoints |

### Kubernetes Ingress (Traefik)
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: >-
      axelus-axelus-chain-full@kubernetescrd
spec:
  rules:
    - host: app.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: my-app
                port:
                  number: 80
```

---

## Inspection Flow (both gateways)

```
Request → Gateway
    │
    ├─ 1. GeoIP Check          → block if country/ASN blocked
    ├─ 2. Threat Intel Check   → block if IP in threat feeds
    ├─ 3. Rate Limit Check     → 429 if limit exceeded
    ├─ 4. Deep Packet Inspect  → block if threat score ≥ threshold
    └─ 5. Honeypot Check       → block if honeypot path accessed
         │
         └─ PASS → upstream service
                   (with X-AXELUS-* headers)
```

### Headers added to upstream
| Header | Value |
|--------|-------|
| `X-AXELUS-Inspected` | `1` |
| `X-AXELUS-Country` | ISO country code |
| `X-AXELUS-Risk-Score` | 0–100 |
| `X-AXELUS-Threat-Score` | 0–100 (DPI) |
| `X-AXELUS-License-Tier` | License tier (if license check enabled) |

### Headers added to response
| Header | Value |
|--------|-------|
| `X-WAF-Provider` | `AXELUS-WAF` |
| `X-Publisher` | `OPTIMIUM NEXUS LLC` |
| `X-AXELUS-Blocked` | `1` (only when blocking) |
| `X-AXELUS-Block-Reason` | Reason code |
