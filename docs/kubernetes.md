# ☸️ IronWall-WAF — Kubernetes Deployment Guide

**Publisher: OPTIMIUM NEXUS LLC** — [www.optimiumnexus.com](https://www.optimiumnexus.com)

---

## Prerequisites

- Kubernetes 1.25+
- Helm 3.12+
- cert-manager (for TLS)
- A storage class with ReadWriteOnce support
- `kubectl` access to the cluster

---

## 1. Create Secrets

```bash
# PostgreSQL
kubectl create secret generic ironwall-postgres-secret \
  --namespace ironwall \
  --from-literal=password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)

# Redis
kubectl create secret generic ironwall-redis-secret \
  --namespace ironwall \
  --from-literal=password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)

# Grafana
kubectl create secret generic ironwall-grafana-secret \
  --namespace ironwall \
  --from-literal=admin-password=$(openssl rand -base64 24)

# License server
kubectl create secret generic ironwall-license-secret \
  --namespace ironwall \
  --from-literal=private-key=$IRONWALL_PRIVATE_KEY \
  --from-literal=public-key=$IRONWALL_PUBLIC_KEY \
  --from-literal=key-id=$IRONWALL_KEY_ID \
  --from-literal=admin-key=$(openssl rand -base64 32)

# Threat Intelligence (AbuseIPDB)
kubectl create secret generic ironwall-threat-intel-secret \
  --namespace ironwall \
  --from-literal=abuseipdb-key=YOUR_ABUSEIPDB_KEY

# MaxMind GeoIP2
kubectl create secret generic ironwall-maxmind-secret \
  --namespace ironwall \
  --from-literal=license-key=YOUR_MAXMIND_KEY \
  --from-literal=account-id=YOUR_MAXMIND_ACCOUNT
```

---

## 2. Add Helm Repositories

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

---

## 3. Install Dependencies

```bash
# Cert-manager (if not already installed)
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set installCRDs=true
```

---

## 4. Deploy IronWall

### Minimal (Core only)
```bash
helm install ironwall ./helm/ironwall \
  --namespace ironwall \
  --create-namespace \
  --set monitoring.enabled=false \
  --set networkPolicies.enabled=true
```

### Enterprise (Full monitoring + security)
```bash
helm install ironwall ./helm/ironwall \
  --namespace ironwall \
  --create-namespace \
  --values ./helm/ironwall/values.yaml \
  --set management.ingress.enabled=true \
  --set management.ingress.hosts[0].host=waf.yourcompany.com \
  --set autoscaling.enabled=true \
  --set autoscaling.maxReplicas=10 \
  --set forensics.enabled=false   # Enable with Ultimate license
```

### Ultimate (All features including Forensics)
```bash
helm install ironwall ./helm/ironwall \
  --namespace ironwall \
  --create-namespace \
  --values ./helm/ironwall/values.yaml \
  --set forensics.enabled=true \
  --set forensics.captureMode=threat \
  --set forensics.storage.size=500Gi \
  --set autoscaling.enabled=true \
  --set autoscaling.maxReplicas=20 \
  --set networkPolicies.enabled=true
```

---

## 5. Verify Deployment

```bash
# Check all pods
kubectl get pods -n ironwall

# Expected output:
# ironwall-mgt-xxx          1/1  Running
# ironwall-detector-xxx     1/1  Running
# ironwall-postgres-0       1/1  Running
# ironwall-redis-master-0   1/1  Running
# ironwall-threat-intel-xxx 1/1  Running
# ironwall-prometheus-xxx   1/1  Running
# ironwall-grafana-xxx      1/1  Running
# ironwall-license-server   1/1  Running

# Check NetworkPolicies
kubectl get networkpolicies -n ironwall

# Check HPA
kubectl get hpa -n ironwall

# Check PDB
kubectl get pdb -n ironwall

# Get initial admin password
kubectl logs -n ironwall deploy/ironwall-mgt | grep "Initial password"
```

---

## 6. Network Policies — Zero Trust Architecture

IronWall deploys **9 NetworkPolicies** implementing deny-all-by-default:

| Policy | Controls |
|--------|----------|
| `default-deny-all` | Blocks all pod-to-pod traffic baseline |
| `tengine` | Allows HTTP/S ingress + egress to detector + mgt |
| `management` | Accepts from tengine + Prometheus + admin NS |
| `detector` | Only accepts from tengine + mgt |
| `postgres` | Only accepts from mgt + threat-intel + compliance |
| `redis` | Only accepts from IronWall pods (part-of label) |
| `threat-intel` | Egress to internet (feeds) + Redis + mgt only |
| `forensics` | Internal + egress to SIEM endpoints |
| `license-server` | Only from IronWall pods + admin NS |

Label your admin namespace:
```bash
kubectl label namespace your-admin-ns ironwall.io/admin=true
```

---

## 7. Upgrading

```bash
helm upgrade ironwall ./helm/ironwall \
  --namespace ironwall \
  --reuse-values \
  --set management.image.tag=1.1.0
```

---

## 8. Scaling

```bash
# Manual scale
kubectl scale deploy ironwall-mgt -n ironwall --replicas=4
kubectl scale deploy ironwall-detector -n ironwall --replicas=6

# HPA will auto-scale based on CPU/memory/custom metrics
kubectl get hpa -n ironwall -w
```

---

## 9. Uninstall

```bash
helm uninstall ironwall --namespace ironwall

# Remove PVCs (destructive — deletes all data)
kubectl delete pvc --all -n ironwall

# Remove namespace
kubectl delete namespace ironwall
```

---

## Architecture Diagram (Kubernetes)

```
┌─────────────────────────────────────────────────────────────┐
│                    namespace: ironwall                       │
│                                                              │
│  ┌──────────┐    ┌───────────┐    ┌──────────────────────┐  │
│  │ ingress- │───▶│  tengine  │───▶│      detector        │  │
│  │  nginx   │    │  (WAF)    │    │  (AI engine × N)     │  │
│  └──────────┘    └─────┬─────┘    └──────────────────────┘  │
│                        │                                     │
│                   ┌────▼────────────────┐                   │
│                   │   management API    │                    │
│                   │   (× 2 replicas)    │                    │
│                   └────┬────────────────┘                   │
│                        │                                     │
│          ┌─────────────┼─────────────────┐                  │
│          │             │                 │                   │
│     ┌────▼───┐   ┌─────▼──────┐  ┌──────▼─────┐           │
│     │postgres│   │   redis    │  │ prometheus  │           │
│     │  (HA)  │   │ (master+1) │  │  + grafana  │           │
│     └────────┘   └────────────┘  └─────────────┘           │
│                                                              │
│     ┌─────────────┐  ┌───────────┐  ┌─────────────────┐   │
│     │ threat-intel│  │ forensics │  │ license-server  │   │
│     │  (syncer)   │  │ (PCAP)    │  │  (ED25519 API)  │   │
│     └─────────────┘  └───────────┘  └─────────────────┘   │
│                                                              │
│  ━━━━━━━━━━ NetworkPolicy boundaries (deny-all default) ━━  │
└─────────────────────────────────────────────────────────────┘
```
