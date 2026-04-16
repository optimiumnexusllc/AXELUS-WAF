# ☸️ AXELUS-WAF — Kubernetes Deployment Guide

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
kubectl create secret generic axelus-postgres-secret \
  --namespace axelus \
  --from-literal=password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)

# Redis
kubectl create secret generic axelus-redis-secret \
  --namespace axelus \
  --from-literal=password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 32)

# Grafana
kubectl create secret generic axelus-grafana-secret \
  --namespace axelus \
  --from-literal=admin-password=$(openssl rand -base64 24)

# License server
kubectl create secret generic axelus-license-secret \
  --namespace axelus \
  --from-literal=private-key=$IRONWALL_PRIVATE_KEY \
  --from-literal=public-key=$IRONWALL_PUBLIC_KEY \
  --from-literal=key-id=$IRONWALL_KEY_ID \
  --from-literal=admin-key=$(openssl rand -base64 32)

# Threat Intelligence (AbuseIPDB)
kubectl create secret generic axelus-threat-intel-secret \
  --namespace axelus \
  --from-literal=abuseipdb-key=YOUR_ABUSEIPDB_KEY

# MaxMind GeoIP2
kubectl create secret generic axelus-maxmind-secret \
  --namespace axelus \
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

## 4. Deploy AXELUS

### Minimal (Core only)
```bash
helm install axelus ./helm/axelus \
  --namespace axelus \
  --create-namespace \
  --set monitoring.enabled=false \
  --set networkPolicies.enabled=true
```

### Enterprise (Full monitoring + security)
```bash
helm install axelus ./helm/axelus \
  --namespace axelus \
  --create-namespace \
  --values ./helm/axelus/values.yaml \
  --set management.ingress.enabled=true \
  --set management.ingress.hosts[0].host=waf.yourcompany.com \
  --set autoscaling.enabled=true \
  --set autoscaling.maxReplicas=10 \
  --set forensics.enabled=false   # Enable with Ultimate license
```

### Ultimate (All features including Forensics)
```bash
helm install axelus ./helm/axelus \
  --namespace axelus \
  --create-namespace \
  --values ./helm/axelus/values.yaml \
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
kubectl get pods -n axelus

# Expected output:
# axelus-mgt-xxx          1/1  Running
# axelus-detector-xxx     1/1  Running
# axelus-postgres-0       1/1  Running
# axelus-redis-master-0   1/1  Running
# axelus-threat-intel-xxx 1/1  Running
# axelus-prometheus-xxx   1/1  Running
# axelus-grafana-xxx      1/1  Running
# axelus-license-server   1/1  Running

# Check NetworkPolicies
kubectl get networkpolicies -n axelus

# Check HPA
kubectl get hpa -n axelus

# Check PDB
kubectl get pdb -n axelus

# Get initial admin password
kubectl logs -n axelus deploy/axelus-mgt | grep "Initial password"
```

---

## 6. Network Policies — Zero Trust Architecture

AXELUS deploys **9 NetworkPolicies** implementing deny-all-by-default:

| Policy | Controls |
|--------|----------|
| `default-deny-all` | Blocks all pod-to-pod traffic baseline |
| `tengine` | Allows HTTP/S ingress + egress to detector + mgt |
| `management` | Accepts from tengine + Prometheus + admin NS |
| `detector` | Only accepts from tengine + mgt |
| `postgres` | Only accepts from mgt + threat-intel + compliance |
| `redis` | Only accepts from AXELUS pods (part-of label) |
| `threat-intel` | Egress to internet (feeds) + Redis + mgt only |
| `forensics` | Internal + egress to SIEM endpoints |
| `license-server` | Only from AXELUS pods + admin NS |

Label your admin namespace:
```bash
kubectl label namespace your-admin-ns axelus.io/admin=true
```

---

## 7. Upgrading

```bash
helm upgrade axelus ./helm/axelus \
  --namespace axelus \
  --reuse-values \
  --set management.image.tag=1.1.0
```

---

## 8. Scaling

```bash
# Manual scale
kubectl scale deploy axelus-mgt -n axelus --replicas=4
kubectl scale deploy axelus-detector -n axelus --replicas=6

# HPA will auto-scale based on CPU/memory/custom metrics
kubectl get hpa -n axelus -w
```

---

## 9. Uninstall

```bash
helm uninstall axelus --namespace axelus

# Remove PVCs (destructive — deletes all data)
kubectl delete pvc --all -n axelus

# Remove namespace
kubectl delete namespace axelus
```

---

## Architecture Diagram (Kubernetes)

```
┌─────────────────────────────────────────────────────────────┐
│                    namespace: axelus                       │
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
