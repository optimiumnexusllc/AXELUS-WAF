# 🔑 AXELUS-WAF — Client SDKs

**Publisher: OPTIMIUM NEXUS LLC** — [www.optimiumnexus.com](https://www.optimiumnexus.com)
**Contact:** [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)

---

## Python SDK (`sdk/python/`)

### Install
```bash
pip install axelus-sdk
# Or from source:
pip install ./sdk/python
```

### Basic Usage
```python
from axelus import AXELUSClient, Feature

client = AXELUSClient(
    license_file='/etc/axelus/axelus.lic',
    api_url='https://waf.mycompany.com:9443',   # optional: online validation
)

# Check license status
print(client.status())  # ✅ ENTERPRISE (expires 2025-12-31)
print(client.tier)      # ENTERPRISE
print(client.days_remaining)  # 365

# Check a feature
if client.has_feature(Feature.GEO_IP_BLOCKING):
    enable_geoip_rules()

# Decorator pattern
@client.require_feature(Feature.AI_THREAT_HUNTING)
def run_ml_threat_hunt():
    ...

# Assert and catch
try:
    client.assert_feature(Feature.FORENSICS)
    start_packet_capture()
except FeatureNotAvailableError as e:
    print(f"Upgrade needed: {e}")
```

### Django Integration
```python
# settings.py
IRONWALL_LICENSE_FILE = '/etc/axelus/axelus.lic'
MIDDLEWARE = ['axelus.django.AXELUSMiddleware', ...]

# views.py
from axelus import Feature

@client.require_feature(Feature.SIEM)
def siem_dashboard(request):
    return render(request, 'siem.html')
```

### FastAPI Integration
```python
from fastapi import Depends
from axelus import AXELUSClient, Feature, create_fastapi_dependency

client = AXELUSClient(license_file='axelus.lic')

@app.get('/forensics')
async def forensics_endpoint(
    _=Depends(create_fastapi_dependency(client, Feature.FORENSICS))
):
    return {'status': 'ok'}
```

### Flask Integration
```python
from axelus import AXELUS, Feature

app = Flask(__name__)
axelus = AXELUS(app)

@app.route('/premium')
@axelus.require(Feature.AI_THREAT_HUNTING)
def premium_view():
    return 'OK'
```

### Environment Variables
| Variable | Description |
|----------|-------------|
| `IRONWALL_LICENSE_FILE` | Path to `.lic` file |
| `IRONWALL_LICENSE_KEY`  | Inline license key |
| `IRONWALL_API_URL`      | AXELUS management API URL |
| `IRONWALL_ADMIN_KEY`    | Admin API key |

### Testing
```bash
cd sdk/python
pip install pytest
pytest tests/ -v --tb=short
```

---

## Node.js / TypeScript SDK (`sdk/nodejs/`)

### Install
```bash
npm install axelus-sdk
# or: yarn add axelus-sdk
```

### Basic Usage (TypeScript)
```typescript
import { AXELUSClient, Feature, createAXELUSClient } from 'axelus-sdk';

const client = await createAXELUSClient({
  licenseFile: '/etc/axelus/axelus.lic',
  apiUrl:      'https://waf.mycompany.com:9443',  // optional
});

console.log(client.status());         // ✅ ENTERPRISE (expires 2025-12-31)
console.log(client.tier);             // 'ENTERPRISE'
console.log(client.daysRemaining);    // 365

// Check feature
if (await client.hasFeature(Feature.GeoIPBlocking)) {
  enableGeoIP();
}

// Assert (throws FeatureNotAvailableError)
await client.assertFeature(Feature.Forensics);

// Clean up
client.destroy();
```

### Express Middleware
```typescript
import express from 'express';
import { AXELUSClient, Feature } from 'axelus-sdk';

const app = express();
const client = await createAXELUSClient({ licenseFile: 'axelus.lic' });

// Protect a route
app.get('/forensics', client.requireFeature(Feature.Forensics), (req, res) => {
  res.json({ status: 'ok' });
});

// Protect a router
app.use('/premium', client.requireFeature(Feature.AIThreatHunting), premiumRouter);
```

### NestJS Guard
```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { AXELUSClient, Feature } from 'axelus-sdk';

const client = new AXELUSClient({ licenseFile: 'axelus.lic' });

@Controller('siem')
export class SiemController {
  @Get('dashboard')
  @UseGuards(client.createGuard(Feature.SIEM))
  async getDashboard() {
    return { data: 'siem data' };
  }
}
```

### CommonJS (JavaScript)
```javascript
const { AXELUSClient, Feature } = require('axelus-sdk');

const client = new AXELUSClient({ licenseFile: 'axelus.lic', autoRefresh: false });
await client.init();

if (await client.hasFeature(Feature.ThreatIntel)) {
  console.log('Threat intelligence enabled');
}
```

### Testing
```bash
cd sdk/nodejs
npm install
npm test
npm run test -- --coverage
```

---

## Features Reference

| Feature Constant (Python) | Feature Constant (Node.js) | Tier |
|---------------------------|---------------------------|------|
| `Feature.CORE_WAF` | `Feature.CoreWAF` | All |
| `Feature.OWASP_RULES` | `Feature.OWASPRules` | All |
| `Feature.API_RATE_LIMIT` | `Feature.APIRateLimit` | Professional+ |
| `Feature.GEO_IP_BLOCKING` | `Feature.GeoIPBlocking` | Enterprise+ |
| `Feature.THREAT_INTEL` | `Feature.ThreatIntel` | Enterprise+ |
| `Feature.SIEM` | `Feature.SIEM` | Enterprise+ |
| `Feature.PROMETHEUS` | `Feature.Prometheus` | Enterprise+ |
| `Feature.COMPLIANCE_REPORT` | `Feature.ComplianceReport` | Enterprise+ |
| `Feature.KUBERNETES_HELM` | `Feature.KubernetesHelm` | Enterprise+ |
| `Feature.AI_THREAT_HUNTING` | `Feature.AIThreatHunting` | Ultimate |
| `Feature.ZERO_DAY_SHIELD` | `Feature.ZeroDayShield` | Ultimate |
| `Feature.DDOS_MITIGATION` | `Feature.DDoSMitigation` | Ultimate |
| `Feature.FORENSICS` | `Feature.Forensics` | Ultimate |
| `Feature.DECEPTION_LAYER` | `Feature.DeceptionLayer` | Ultimate |
| `Feature.PRIORITY_SUPPORT` | `Feature.PrioritySupport` | Ultimate |

## Upgrade

Contact us to upgrade your license:
- 🌐 [www.optimiumnexus.com/upgrade](https://www.optimiumnexus.com/upgrade)
- ✉️ [contact@optimiumnexus.com](mailto:contact@optimiumnexus.com)
