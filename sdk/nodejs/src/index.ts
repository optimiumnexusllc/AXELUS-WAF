/**
 * AXELUS-WAF Node.js / TypeScript SDK
 * License validation and feature gating for Node.js applications.
 *
 * Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
 * Contact:   contact@optimiumnexus.com
 *
 * Install: npm install axelus-sdk
 *
 * @example
 * import { AXELUSClient, Feature } from 'axelus-sdk';
 *
 * const client = new AXELUSClient({
 *   licenseFile: '/etc/axelus/axelus.lic',
 *   apiUrl: 'https://waf.mycompany.com:9443',
 * });
 *
 * await client.init();
 *
 * if (await client.hasFeature(Feature.GeoIPBlocking)) {
 *   enableGeoIP();
 * }
 *
 * // Express middleware
 * app.use('/premium', client.requireFeature(Feature.Forensics));
 */

import fs from 'fs';
import path from 'path';
import https from 'https';
import http from 'http';

// ── Feature Enum ──────────────────────────────────────────────────────────────

export enum Feature {
  // Core (all tiers)
  CoreWAF           = 'core_waf',
  BasicDashboard    = 'basic_dashboard',
  OWASPRules        = 'owasp_rules',
  BotProtection     = 'bot_protection',

  // Professional+
  AdvancedRules     = 'advanced_rules',
  APIRateLimit      = 'api_rate_limit',
  SSLOffload        = 'ssl_offload',
  MultiSite         = 'multi_site',
  AuditLog          = 'audit_log',
  AlertingBasic     = 'alerting_basic',
  BackupRestore     = 'backup_restore',

  // Enterprise+
  GeoIPBlocking     = 'geoip_blocking',
  ThreatIntel       = 'threat_intel',
  AlertingFull      = 'alerting_full',
  SIEM              = 'siem',
  Prometheus        = 'prometheus',
  HighAvailability  = 'high_availability',
  UnlimitedSites    = 'unlimited_sites',
  ComplianceReport  = 'compliance_report',
  KubernetesHelm    = 'kubernetes_helm',

  // Ultimate only
  AIThreatHunting   = 'ai_threat_hunting',
  ZeroDayShield     = 'zero_day_shield',
  DDoSMitigation    = 'ddos_mitigation',
  DeceptionLayer    = 'deception_layer',
  Forensics         = 'forensics',
  CustomBranding    = 'custom_branding',
  MultiTenancy      = 'multi_tenancy',
  APIFullAccess     = 'api_full_access',
  PrioritySupport   = 'priority_support',
  CustomIntegration = 'custom_integration',
}

// ── Tier → Features mapping ───────────────────────────────────────────────────

export const TIER_FEATURES: Record<string, Feature[]> = {
  COMMUNITY: [
    Feature.CoreWAF, Feature.BasicDashboard,
    Feature.OWASPRules, Feature.BotProtection,
  ],
  PROFESSIONAL: [
    Feature.CoreWAF, Feature.BasicDashboard, Feature.OWASPRules, Feature.BotProtection,
    Feature.AdvancedRules, Feature.APIRateLimit, Feature.SSLOffload,
    Feature.MultiSite, Feature.AuditLog, Feature.AlertingBasic, Feature.BackupRestore,
  ],
  ENTERPRISE: [
    Feature.CoreWAF, Feature.BasicDashboard, Feature.OWASPRules, Feature.BotProtection,
    Feature.AdvancedRules, Feature.APIRateLimit, Feature.SSLOffload,
    Feature.MultiSite, Feature.AuditLog, Feature.AlertingBasic, Feature.BackupRestore,
    Feature.GeoIPBlocking, Feature.ThreatIntel, Feature.AlertingFull,
    Feature.SIEM, Feature.Prometheus, Feature.HighAvailability,
    Feature.UnlimitedSites, Feature.ComplianceReport, Feature.KubernetesHelm,
  ],
  ULTIMATE: [
    Feature.CoreWAF, Feature.BasicDashboard, Feature.OWASPRules, Feature.BotProtection,
    Feature.AdvancedRules, Feature.APIRateLimit, Feature.SSLOffload,
    Feature.MultiSite, Feature.AuditLog, Feature.AlertingBasic, Feature.BackupRestore,
    Feature.GeoIPBlocking, Feature.ThreatIntel, Feature.AlertingFull,
    Feature.SIEM, Feature.Prometheus, Feature.HighAvailability,
    Feature.UnlimitedSites, Feature.ComplianceReport, Feature.KubernetesHelm,
    Feature.AIThreatHunting, Feature.ZeroDayShield, Feature.DDoSMitigation,
    Feature.DeceptionLayer, Feature.Forensics, Feature.CustomBranding,
    Feature.MultiTenancy, Feature.APIFullAccess, Feature.PrioritySupport,
    Feature.CustomIntegration,
  ],
  TRIAL: [
    Feature.CoreWAF, Feature.BasicDashboard, Feature.OWASPRules, Feature.BotProtection,
    Feature.AdvancedRules, Feature.APIRateLimit, Feature.GeoIPBlocking,
    Feature.ThreatIntel, Feature.AlertingFull, Feature.SIEM, Feature.Prometheus,
    Feature.HighAvailability, Feature.UnlimitedSites, Feature.ComplianceReport,
    Feature.AIThreatHunting, Feature.ZeroDayShield, Feature.DDoSMitigation,
  ],
  DEVELOPER: [
    Feature.CoreWAF, Feature.BasicDashboard, Feature.OWASPRules, Feature.BotProtection,
    Feature.AdvancedRules, Feature.APIFullAccess, Feature.CustomIntegration,
  ],
};

// ── Types ─────────────────────────────────────────────────────────────────────

export interface LicenseLimits {
  maxSites:          number;  // -1 = unlimited
  maxRequestsPerSec: number;
  maxNodes:          number;
  maxUsers:          number;
  maxCustomRules:    number;
  supportLevel:      string;
  updateChannel:     string;
}

export interface ValidationResult {
  valid:             boolean;
  tier:              string;
  licensee:          string;
  email:             string;
  key:               string;
  domain?:           string;
  isLifetime:        boolean;
  expiresAt?:        Date;
  daysRemaining:     number;  // -1 = lifetime
  features:          string[];
  extraFeatures:     string[];
  disabledFeatures:  string[];
  limits?:           LicenseLimits;
  errors:            string[];
  warnings:          string[];
  validatedAt:       Date;
}

export interface AXELUSClientOptions {
  licenseFile?:   string;
  licenseKey?:    string;
  apiUrl?:        string;
  adminKey?:      string;
  cacheTtlMs?:    number;   // default: 3_600_000 (1h)
  autoRefresh?:   boolean;  // default: true
  rejectUnauthorized?: boolean; // default: false for self-signed certs
}

// ── Errors ────────────────────────────────────────────────────────────────────

export class AXELUSError extends Error {
  constructor(msg: string) { super(msg); this.name = 'AXELUSError'; }
}

export class LicenseNotFoundError extends AXELUSError {
  constructor(msg: string) { super(msg); this.name = 'LicenseNotFoundError'; }
}

export class LicenseInvalidError extends AXELUSError {
  constructor(msg: string) { super(msg); this.name = 'LicenseInvalidError'; }
}

export class FeatureNotAvailableError extends AXELUSError {
  constructor(
    public readonly feature: Feature,
    public readonly tier: string,
  ) {
    super(
      `Feature '${feature}' is not available on ${tier} tier. ` +
      `Upgrade at https://www.optimiumnexus.com/upgrade`
    );
    this.name = 'FeatureNotAvailableError';
  }
}

// ── Client ────────────────────────────────────────────────────────────────────

export class AXELUSClient {
  private readonly opts: Required<AXELUSClientOptions>;
  private cache: ValidationResult | null = null;
  private cacheTs = 0;
  private refreshTimer?: ReturnType<typeof setInterval>;

  constructor(opts: AXELUSClientOptions = {}) {
    this.opts = {
      licenseFile:          opts.licenseFile  ?? process.env.IRONWALL_LICENSE_FILE ?? '',
      licenseKey:           opts.licenseKey   ?? process.env.IRONWALL_LICENSE_KEY  ?? '',
      apiUrl:               (opts.apiUrl      ?? process.env.IRONWALL_API_URL ?? '').replace(/\/$/, ''),
      adminKey:             opts.adminKey     ?? process.env.IRONWALL_ADMIN_KEY ?? '',
      cacheTtlMs:           opts.cacheTtlMs   ?? 3_600_000,
      autoRefresh:          opts.autoRefresh  ?? true,
      rejectUnauthorized:   opts.rejectUnauthorized ?? false,
    };

    if (!this.opts.licenseFile && !this.opts.licenseKey) {
      throw new AXELUSError(
        'Provide licenseFile or licenseKey option (or set IRONWALL_LICENSE_FILE env var)'
      );
    }
  }

  /** Initialize the client (performs initial validation). */
  async init(): Promise<ValidationResult> {
    const result = await this.validate();
    if (this.opts.autoRefresh && this.opts.apiUrl) {
      this.refreshTimer = setInterval(
        () => this.validate(true).catch(() => {}),
        Math.max(60_000, this.opts.cacheTtlMs - 300_000),
      );
      if (this.refreshTimer.unref) this.refreshTimer.unref();
    }
    return result;
  }

  // ── Validation ──────────────────────────────────────────────────────────────

  async validate(force = false): Promise<ValidationResult> {
    const now = Date.now();
    if (!force && this.cache && now - this.cacheTs < this.opts.cacheTtlMs) {
      return this.cache;
    }
    const result = this.opts.apiUrl
      ? await this.validateOnline().catch(() => this.validateOffline())
      : await this.validateOffline();
    this.cache  = result;
    this.cacheTs = Date.now();
    return result;
  }

  private async validateOnline(): Promise<ValidationResult> {
    const pem = this.loadPEM();
    const payload = JSON.stringify({ license_file: pem });
    const url = new URL(`${this.opts.apiUrl}/api/v1/licensing/validate`);
    const data = await this.httpPost(url, payload, {
      'Content-Type': 'application/json',
      'X-Admin-Key':  this.opts.adminKey,
    });
    return this.parseApiResponse(data);
  }

  private async validateOffline(): Promise<ValidationResult> {
    const pem = this.loadPEM();
    try {
      const content = pem
        .replace('-----BEGIN IRONWALL LICENSE-----', '')
        .replace('-----END IRONWALL LICENSE-----', '')
        .replace(/\n/g, '')
        .trim();

      const raw  = Buffer.from(content, 'base64').toString('utf-8');
      const data = JSON.parse(raw);

      const tier    = data.tier ?? 'UNKNOWN';
      const isLife  = data.is_lifetime ?? false;
      let expiresAt: Date | undefined;
      let daysLeft  = -1;

      if (!isLife && data.expires_at) {
        const ts = typeof data.expires_at === 'number'
          ? data.expires_at * 1000
          : Date.parse(data.expires_at);
        expiresAt = new Date(ts);
        daysLeft  = Math.max(0, Math.ceil((expiresAt.getTime() - Date.now()) / 86_400_000));
      }

      const features         = (TIER_FEATURES[tier] ?? []) as string[];
      const extraFeatures    = (data.extra_features ?? []) as string[];
      const disabledFeatures = (data.disabled_features ?? []) as string[];

      return {
        valid: true, tier, licensee: data.licensee ?? '', email: data.email ?? '',
        key: data.key ?? '', domain: data.domain, isLifetime: isLife,
        expiresAt, daysRemaining: daysLeft, features, extraFeatures, disabledFeatures,
        limits: this.buildLimits(tier), errors: [], warnings: this.buildWarnings(daysLeft),
        validatedAt: new Date(),
      };
    } catch (err) {
      return {
        valid: false, tier: 'UNKNOWN', licensee: '', email: '', key: '',
        isLifetime: false, daysRemaining: 0, features: [],
        extraFeatures: [], disabledFeatures: [], errors: [`Parse error: ${err}`],
        warnings: [], validatedAt: new Date(),
      };
    }
  }

  private parseApiResponse(data: any): ValidationResult {
    const tier     = data.tier ?? 'UNKNOWN';
    const isLife   = data.is_lifetime ?? false;
    let expiresAt: Date | undefined;
    let daysLeft   = data.days_remaining ?? 0;

    if (data.expires_at && !isLife) {
      expiresAt = new Date(data.expires_at);
    }
    const features = (TIER_FEATURES[tier] ?? []) as string[];

    return {
      valid: data.valid ?? false, tier, licensee: data.licensee ?? '',
      email: data.email ?? '', key: data.key ?? '', domain: data.domain,
      isLifetime: isLife, expiresAt, daysRemaining: isLife ? -1 : daysLeft,
      features, extraFeatures: data.extra_features ?? [],
      disabledFeatures: data.disabled_features ?? [],
      limits: this.buildLimits(tier),
      errors: data.errors ?? [], warnings: data.warnings ?? [],
      validatedAt: new Date(),
    };
  }

  // ── Feature Access ──────────────────────────────────────────────────────────

  async hasFeature(feature: Feature): Promise<boolean> {
    try {
      const r = await this.validate();
      return this.checkFeature(r, feature);
    } catch {
      return false;
    }
  }

  async assertFeature(feature: Feature): Promise<void> {
    const r = await this.validate();
    if (!this.checkFeature(r, feature)) {
      throw new FeatureNotAvailableError(feature, r.tier);
    }
  }

  private checkFeature(r: ValidationResult, feature: Feature): boolean {
    if (!r.valid) return false;
    const f = feature as string;
    if (r.disabledFeatures.includes(f)) return false;
    if (r.extraFeatures.includes(f))    return true;
    return r.features.includes(f);
  }

  /**
   * Express/Fastify/Hapi middleware that requires a specific feature.
   * @example
   * app.get('/forensics', client.requireFeature(Feature.Forensics), handler);
   */
  requireFeature(feature: Feature) {
    return async (req: any, res: any, next: any): Promise<void> => {
      try {
        await this.assertFeature(feature);
        next();
      } catch (err) {
        if (err instanceof FeatureNotAvailableError) {
          res.status(403).json({
            error:       'feature_not_licensed',
            feature:     err.feature,
            currentTier: err.tier,
            upgradeUrl:  'https://www.optimiumnexus.com/upgrade',
          });
        } else {
          next(err);
        }
      }
    };
  }

  /**
   * NestJS Guard factory.
   * @example
   * @UseGuards(client.createGuard(Feature.SIEM))
   * @Get('siem-data')
   * async getSiemData() { ... }
   */
  createGuard(feature: Feature) {
    const self = this;
    return class AXELUSGuard {
      async canActivate(): Promise<boolean> {
        const r = await self.validate();
        if (!self.checkFeature(r, feature)) {
          throw new FeatureNotAvailableError(feature, r.tier);
        }
        return true;
      }
    };
  }

  // ── Properties ──────────────────────────────────────────────────────────────

  get tier(): string { return this.cache?.tier ?? 'UNKNOWN'; }
  get isValid(): boolean { return this.cache?.valid ?? false; }
  get daysRemaining(): number { return this.cache?.daysRemaining ?? 0; }

  status(): string {
    const r = this.cache;
    if (!r) return '⏳ Not initialized — call await client.init()';
    if (!r.valid)      return `❌ Invalid: ${r.errors.join('; ')}`;
    if (r.isLifetime)  return `✅ ${r.tier} (lifetime)`;
    const exp = r.expiresAt?.toISOString().split('T')[0] ?? 'unknown';
    if (r.daysRemaining <= 0)  return `⛔ ${r.tier} EXPIRED`;
    if (r.daysRemaining <= 14) return `⚠️  ${r.tier} (${r.daysRemaining} days remaining)`;
    return `✅ ${r.tier} (expires ${exp})`;
  }

  info(): Record<string, unknown> {
    const r = this.cache;
    return {
      valid:         r?.valid ?? false,
      tier:          r?.tier  ?? 'UNKNOWN',
      licensee:      r?.licensee ?? '',
      key:           r?.key ?? '',
      isLifetime:    r?.isLifetime ?? false,
      daysRemaining: r?.daysRemaining ?? 0,
      featuresCount: r?.features.length ?? 0,
      status:        this.status(),
    };
  }

  destroy(): void {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
  }

  // ── Internals ────────────────────────────────────────────────────────────────

  private loadPEM(): string {
    if (this.opts.licenseFile) {
      if (!fs.existsSync(this.opts.licenseFile)) {
        throw new LicenseNotFoundError(`License file not found: ${this.opts.licenseFile}`);
      }
      return fs.readFileSync(this.opts.licenseFile, 'utf-8');
    }
    if (this.opts.licenseKey?.startsWith('-----BEGIN')) {
      return this.opts.licenseKey;
    }
    throw new LicenseInvalidError('No valid license file or inline PEM found');
  }

  private buildLimits(tier: string): LicenseLimits {
    const map: Record<string, LicenseLimits> = {
      COMMUNITY:    { maxSites: 1,   maxRequestsPerSec: 500,   maxNodes: 1,  maxUsers: 2,  maxCustomRules: 10,   supportLevel: 'community', updateChannel: 'stable' },
      PROFESSIONAL: { maxSites: 10,  maxRequestsPerSec: 5000,  maxNodes: 2,  maxUsers: 10, maxCustomRules: 100,  supportLevel: 'email',     updateChannel: 'stable' },
      ENTERPRISE:   { maxSites: -1,  maxRequestsPerSec: 50000, maxNodes: 10, maxUsers: 50, maxCustomRules: 1000, supportLevel: 'priority',  updateChannel: 'edge'   },
      ULTIMATE:     { maxSites: -1,  maxRequestsPerSec: -1,    maxNodes: -1, maxUsers: -1, maxCustomRules: -1,   supportLevel: 'dedicated', updateChannel: 'edge'   },
      TRIAL:        { maxSites: -1,  maxRequestsPerSec: -1,    maxNodes: 3,  maxUsers: 10, maxCustomRules: 500,  supportLevel: 'email',     updateChannel: 'edge'   },
      DEVELOPER:    { maxSites: 3,   maxRequestsPerSec: 1000,  maxNodes: 1,  maxUsers: 5,  maxCustomRules: 500,  supportLevel: 'email',     updateChannel: 'edge'   },
    };
    return map[tier] ?? { maxSites: -1, maxRequestsPerSec: -1, maxNodes: -1, maxUsers: -1, maxCustomRules: -1, supportLevel: 'unknown', updateChannel: 'stable' };
  }

  private buildWarnings(days: number): string[] {
    if (days === -1) return [];
    if (days === 0)  return ['License has expired'];
    if (days <= 7)   return [`⚠️  License expires in ${days} days — renew immediately at https://www.optimiumnexus.com`];
    if (days <= 30)  return [`License expires in ${days} days`];
    return [];
  }

  private async httpPost(url: URL, body: string, headers: Record<string, string>): Promise<any> {
    return new Promise((resolve, reject) => {
      const lib = url.protocol === 'https:' ? https : http;
      const req = lib.request(
        { hostname: url.hostname, port: url.port, path: url.pathname, method: 'POST',
          headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
          rejectUnauthorized: this.opts.rejectUnauthorized },
        (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try { resolve(JSON.parse(data)); }
            catch { resolve({}); }
          });
        }
      );
      req.on('error', reject);
      req.setTimeout(10_000, () => req.destroy(new Error('timeout')));
      req.write(body);
      req.end();
    });
  }
}

// ── Convenience factory ───────────────────────────────────────────────────────

export async function createAXELUSClient(opts: AXELUSClientOptions): Promise<AXELUSClient> {
  const client = new AXELUSClient(opts);
  await client.init();
  return client;
}

export default AXELUSClient;
