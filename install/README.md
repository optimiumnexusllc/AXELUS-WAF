# AXELUS-WAF — Procédure d'Installation POC

**Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com**

---

## Prérequis

| Composant | Minimum | Recommandé POC |
|-----------|---------|----------------|
| OS | Ubuntu 22.04 / 24.04 LTS | Ubuntu 24.04 LTS |
| RAM | 2 GB | 4 GB |
| CPU | 2 vCPUs | 4 vCPUs |
| Disque | 10 GB | 40 GB SSD |
| Docker | 24.0+ | 27.0+ |
| Réseau | Port 80, 443 ouverts | + 9443, 8080, 8085, 3000 |

---

## Installation en 1 commande

```bash
# Option A — One-liner (recommandée)
curl -fsSL https://raw.githubusercontent.com/optimiumnexusllc/AXELUS-WAF/main/install/install.sh | sudo bash

# Option B — Avec paramètres
sudo bash install.sh --domain waf.monentreprise.com --email sec@monentreprise.com

# Option C — Avec TLS auto-signé
sudo bash install.sh --domain waf.monentreprise.com --tls

# Option D — Sans monitoring (minimal)
sudo bash install.sh --no-monitoring
```

---

## Installation manuelle étape par étape

### 1. Préparer le système

```bash
# Mise à jour du système
sudo apt-get update && sudo apt-get upgrade -y

# Vérification de la version Ubuntu
lsb_release -a

# Vérification des ressources
free -h && df -h / && nproc
```

### 2. Installer Docker

```bash
# Installation Docker Engine officielle
curl -fsSL https://get.docker.com | sudo bash

# Activer le démarrage automatique
sudo systemctl enable docker --now

# Vérifier l'installation
docker --version
docker compose version

# Ajouter votre utilisateur au groupe docker (évite sudo à chaque commande)
sudo usermod -aG docker $USER
newgrp docker
```

### 3. Cloner le dépôt AXELUS-WAF

```bash
# Cloner
git clone https://github.com/optimiumnexusllc/AXELUS-WAF.git
cd AXELUS-WAF

# Rendre le script exécutable
chmod +x install/install.sh
```

### 4. Lancer l'installation automatisée

```bash
sudo bash install/install.sh
```

Le script effectue automatiquement :
- ✅ Vérification des prérequis (RAM, disk, CPU, ports)
- ✅ Installation de Docker si absent
- ✅ Création du user système `axelus`
- ✅ Génération de tous les secrets (passwords, JWT, API keys)
- ✅ Création de la structure `/opt/axelus-waf/`
- ✅ Configuration Nginx, Redis, Prometheus, Grafana
- ✅ Démarrage du stack Docker Compose
- ✅ Attente des healthchecks de tous les services
- ✅ Émission d'une licence trial 30 jours
- ✅ Smoke tests automatiques
- ✅ Installation de la commande `axelus`
- ✅ Service systemd (démarrage automatique au boot)

Durée : **5 à 10 minutes** selon la connexion Internet.

---

## Services déployés

| Container | Port | Description |
|-----------|------|-------------|
| `axelus-waf` | 80, 443 | Tengine WAF Engine |
| `axelus-mgt` | 9443 | Management API + Dashboard |
| `axelus-pg` | (interne) | PostgreSQL 15 |
| `axelus-redis` | (interne) | Redis 7 |
| `axelus-portal` | 8080 | Customer Portal |
| `axelus-admin` | 8085 | Admin Center |
| `axelus-license` | 8090 | License Server |
| `axelus-prometheus` | 9090* | Prometheus metrics |
| `axelus-grafana` | 3000 | Grafana dashboards |
| `axelus-node-exporter` | (interne) | Host metrics |

*Prometheus accessible en loopback uniquement (127.0.0.1:9090)

---

## URLs d'accès (remplacer `SERVER_IP` par votre IP)

```
WAF Dashboard   : http://SERVER_IP:9443
Admin Center    : http://SERVER_IP:8085/admin
Customer Portal : http://SERVER_IP:8080
API Docs        : http://SERVER_IP:9443/docs
Grafana         : http://SERVER_IP:3000
```

---

## Commandes de gestion

```bash
# Statut de tous les services
axelus status

# Suivre les logs du WAF
axelus logs waf

# Suivre les logs de l'API de management
axelus logs mgt

# Redémarrer tous les services
axelus restart

# Santé du système
axelus health

# Mise à jour vers la dernière version
axelus update

# Backup de la base de données
axelus backup

# Ouvrir un shell dans un conteneur
axelus shell mgt

# Désinstallation complète
axelus uninstall
```

---

## Vérification de l'installation

```bash
# 1. Vérifier tous les conteneurs
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 2. Tester l'API de management
curl -s http://localhost:9443/api/open/health | jq .

# 3. Vérifier les logs du WAF
docker logs axelus-waf --tail 20

# 4. Tester un blocage OWASP (SQLi)
curl -v "http://localhost/?id=1+UNION+SELECT+*+FROM+users--"
# → Doit retourver 403 Forbidden

# 5. Vérifier Prometheus
curl -s http://localhost:9090/-/healthy

# 6. Vérifier Grafana
curl -s http://localhost:3000/api/health | jq .
```

---

## Configuration des règles WAF (premier site protégé)

```bash
# Via l'API — ajouter un site protégé
curl -X POST http://localhost:9443/api/v1/sites \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: $(grep ADMIN_API_KEY /opt/axelus-waf/.env | cut -d= -f2)" \
  -d '{
    "name": "Mon application web",
    "upstream": "http://192.168.1.100:8080",
    "ports": ["80", "443"],
    "protection_level": "enterprise",
    "waf_enabled": true
  }'
```

---

## Configuration avancée post-installation

### Activer les notifications Slack

```bash
# Éditer le fichier .env
sudo nano /opt/axelus-waf/.env

# Décommenter et remplir :
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Redémarrer
axelus restart
```

### Configurer SMTP pour les emails

```bash
sudo nano /opt/axelus-waf/.env

# Remplir les variables SMTP :
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=noreply@monentreprise.com
SMTP_PASSWORD=mon-mot-de-passe-app

axelus restart
```

### Activer GeoIP (MaxMind)

```bash
# 1. Créer un compte gratuit sur maxmind.com
# 2. Générer une clé de licence
sudo nano /opt/axelus-waf/.env

MAXMIND_LICENSE_KEY=votre-cle-ici

axelus restart
```

---

## Backup et restauration

```bash
# Backup automatique (à ajouter dans crontab)
# Backup quotidien à 2h du matin
echo "0 2 * * * root /usr/local/bin/axelus backup >> /var/log/axelus-backup.log 2>&1" \
  | sudo tee /etc/cron.d/axelus-backup

# Restauration depuis un backup
axelus restore /opt/axelus-waf/backup-20240413_020001.sql.gz
```

---

## Mise à jour

```bash
# Mise à jour automatique (tire les nouvelles images Docker)
axelus update

# Mise à jour avec interruption minimale (rolling restart)
cd /opt/axelus-waf
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml up -d --no-deps axelus-mgt
docker compose -f docker-compose.yml up -d --no-deps axelus-waf
```

---

## Désinstallation

```bash
# Désinstallation complète (SUPPRIME TOUTES LES DONNÉES)
axelus uninstall

# Ou manuellement :
cd /opt/axelus-waf
docker compose down -v
sudo rm -rf /opt/axelus-waf
sudo rm -f /usr/local/bin/axelus
sudo systemctl disable axelus-waf.service
sudo rm -f /etc/systemd/system/axelus-waf.service
```

---

## Dépannage

### Les conteneurs ne démarrent pas

```bash
# Voir les logs détaillés
docker compose -f /opt/axelus-waf/docker-compose.yml logs --tail 50

# Vérifier l'espace disque
df -h

# Vérifier les ports en conflit
ss -tlnp | grep -E '80|443|9443|8080|8085|3000'

# Recréer depuis zéro
docker compose -f /opt/axelus-waf/docker-compose.yml down
docker compose -f /opt/axelus-waf/docker-compose.yml up -d
```

### L'API ne répond pas sur le port 9443

```bash
docker logs axelus-mgt --tail 50
docker exec axelus-mgt curl -sf http://localhost:9443/api/open/health
```

### La base de données refuse les connexions

```bash
docker logs axelus-pg --tail 20
docker exec axelus-pg psql -U axelus -c "\l"
```

### Réinitialiser le mot de passe admin

```bash
# Récupérer le mot de passe depuis .env
grep ADMIN_PASSWORD /opt/axelus-waf/.env

# Ou le réinitialiser via l'API
curl -X POST http://localhost:9443/api/v1/admin/reset-password \
  -H "X-Admin-Key: $(grep ADMIN_API_KEY /opt/axelus-waf/.env | cut -d= -f2)" \
  -d '{"email":"admin@optimiumnexus.com","new_password":"NouveauMotDePasse123!"}'
```

---

## Architecture réseau du POC

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────┐
│                  Ubuntu Server 24.04                 │
│                                                      │
│  ┌──────────────┐     ┌──────────────────────────┐  │
│  │ axelus-waf   │────▶│      axelus-mgt          │  │
│  │ (Tengine)    │     │  (Management API :9443)  │  │
│  │ :80 / :443   │     │                          │  │
│  └──────────────┘     └──────────┬───────────────┘  │
│                                  │                   │
│                    ┌─────────────┼─────────────┐    │
│                    │             │             │    │
│              ┌─────▼───┐ ┌──────▼──┐ ┌────────▼─┐  │
│              │axelus-pg│ │ redis   │ │ detector │  │
│              │ :5432   │ │ :6379   │ │ (ML/AI)  │  │
│              └─────────┘ └─────────┘ └──────────┘  │
│                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐             │
│  │ portal   │ │  admin   │ │ license  │             │
│  │ :8080    │ │  :8085   │ │ :8090    │             │
│  └──────────┘ └──────────┘ └──────────┘             │
│                                                      │
│  ┌──────────┐ ┌──────────┐                          │
│  │prometheus│ │ grafana  │                          │
│  │ :9090*   │ │ :3000    │                          │
│  └──────────┘ └──────────┘                          │
└─────────────────────────────────────────────────────┘

* Prometheus accessible en loopback uniquement (sécurité)
```

---

## Contact et support

- **Documentation** : https://www.optimiumnexus.com/docs
- **GitHub** : https://github.com/optimiumnexusllc/AXELUS-WAF
- **Email** : contact@optimiumnexus.com
- **Upgrade** : https://www.optimiumnexus.com/upgrade

**OPTIMIUM NEXUS LLC** — Next-Generation Web Application Firewall
