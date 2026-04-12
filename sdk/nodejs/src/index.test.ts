/**
 * IronWall Node.js SDK — Jest Test Suite
 * Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  IronWallClient, Feature, TIER_FEATURES,
  IronWallError, LicenseNotFoundError,
  FeatureNotAvailableError, createIronWallClient,
} from '../src/index';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeLicensePEM(
  tier = 'ENTERPRISE',
  daysFromNow = 365,
  isLifetime  = false,
  extraFeatures: string[] = [],
  disabledFeatures: string[] = [],
): string {
  const payload = {
    id:                `test-id-${tier.toLowerCase()}`,
    key:               `IW-${tier.substring(0,3)}-TEST-XXXX-YYYY-ZZZZ`,
    tier,
    licensee:          'Test Corp Node',
    email:             'test@corp.local',
    is_lifetime:       isLifetime,
    issued_at:         new Date().toISOString(),
    expires_at:        isLifetime ? 0 : Math.floor((Date.now() + daysFromNow * 86_400_000) / 1000),
    extra_features:    extraFeatures,
    disabled_features: disabledFeatures,
    signature:         'fakesig==',
    public_key_id:     'test-key',
  };
  const b64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  return `-----BEGIN IRONWALL LICENSE-----\n${b64}\n-----END IRONWALL LICENSE-----`;
}

function writeTempLicense(content: string): string {
  const tmpFile = path.join(os.tmpdir(), `ironwall-test-${Date.now()}.lic`);
  fs.writeFileSync(tmpFile, content, 'utf-8');
  return tmpFile;
}

function makeClient(
  tier = 'ENTERPRISE',
  daysFromNow = 365,
  isLifetime = false,
  extraFeatures: string[] = [],
  disabledFeatures: string[] = [],
): IronWallClient {
  const pem  = makeLicensePEM(tier, daysFromNow, isLifetime, extraFeatures, disabledFeatures);
  const file = writeTempLicense(pem);
  return new IronWallClient({ licenseFile: file, autoRefresh: false });
}

// ── TIER FEATURES ─────────────────────────────────────────────────────────────

describe('TIER_FEATURES', () => {
  test('COMMUNITY includes core_waf', () => {
    expect(TIER_FEATURES.COMMUNITY).toContain(Feature.CoreWAF);
  });

  test('COMMUNITY does not include geoip_blocking', () => {
    expect(TIER_FEATURES.COMMUNITY).not.toContain(Feature.GeoIPBlocking);
  });

  test('PROFESSIONAL includes api_rate_limit', () => {
    expect(TIER_FEATURES.PROFESSIONAL).toContain(Feature.APIRateLimit);
  });

  test('PROFESSIONAL does not include siem', () => {
    expect(TIER_FEATURES.PROFESSIONAL).not.toContain(Feature.SIEM);
  });

  test('ENTERPRISE includes siem', () => {
    expect(TIER_FEATURES.ENTERPRISE).toContain(Feature.SIEM);
  });

  test('ENTERPRISE does not include ai_threat_hunting', () => {
    expect(TIER_FEATURES.ENTERPRISE).not.toContain(Feature.AIThreatHunting);
  });

  test('ULTIMATE includes all premium features', () => {
    const premium = [
      Feature.AIThreatHunting, Feature.ZeroDayShield, Feature.DDoSMitigation,
      Feature.Forensics, Feature.DeceptionLayer, Feature.PrioritySupport,
    ];
    premium.forEach(f => expect(TIER_FEATURES.ULTIMATE).toContain(f));
  });

  test('ENTERPRISE includes all PROFESSIONAL features (tier progression)', () => {
    const proSet = new Set(TIER_FEATURES.PROFESSIONAL);
    TIER_FEATURES.ENTERPRISE.forEach(f => proSet.delete(f));
    // proSet should be empty (all PRO features present in ENT)
    expect(proSet.size).toBe(0);
  });

  test('ULTIMATE includes all ENTERPRISE features', () => {
    const entSet = new Set(TIER_FEATURES.ENTERPRISE);
    TIER_FEATURES.ULTIMATE.forEach(f => entSet.delete(f));
    expect(entSet.size).toBe(0);
  });

  test('no duplicate features per tier', () => {
    Object.entries(TIER_FEATURES).forEach(([tier, features]) => {
      const seen = new Set<string>();
      features.forEach(f => {
        expect(seen.has(f)).toBe(false); // fail on duplicate
        seen.add(f);
      });
    });
  });
});

// ── CLIENT INIT ───────────────────────────────────────────────────────────────

describe('IronWallClient — init', () => {
  test('throws IronWallError without license', () => {
    expect(() => new IronWallClient({ autoRefresh: false }))
      .toThrow(IronWallError);
  });

  test('throws LicenseNotFoundError for missing file', async () => {
    const client = new IronWallClient({
      licenseFile: '/nonexistent/test.lic', autoRefresh: false,
    });
    await expect(client.validate()).rejects.toThrow();
  });

  test('initializes with valid license file', async () => {
    const client = makeClient('ENTERPRISE');
    const result = await client.validate();
    expect(result.valid).toBe(true);
    expect(result.tier).toBe('ENTERPRISE');
  });

  test('createIronWallClient factory works', async () => {
    const pem  = makeLicensePEM('ULTIMATE');
    const file = writeTempLicense(pem);
    const client = await createIronWallClient({ licenseFile: file, autoRefresh: false });
    expect(client.tier).toBe('ULTIMATE');
  });
});

// ── VALIDATION ────────────────────────────────────────────────────────────────

describe('IronWallClient — validate()', () => {
  test('ENTERPRISE license validates correctly', async () => {
    const client = makeClient('ENTERPRISE');
    const r = await client.validate();
    expect(r.valid).toBe(true);
    expect(r.tier).toBe('ENTERPRISE');
    expect(r.licensee).toBe('Test Corp Node');
    expect(r.errors).toHaveLength(0);
  });

  test('ULTIMATE license validates correctly', async () => {
    const r = await makeClient('ULTIMATE').validate();
    expect(r.valid).toBe(true);
    expect(r.tier).toBe('ULTIMATE');
  });

  test('lifetime license has daysRemaining = -1', async () => {
    const r = await makeClient('ULTIMATE', 0, true).validate();
    expect(r.isLifetime).toBe(true);
    expect(r.daysRemaining).toBe(-1);
  });

  test('30-day license has correct daysRemaining', async () => {
    const r = await makeClient('TRIAL', 30).validate();
    expect(r.daysRemaining).toBeGreaterThanOrEqual(29);
    expect(r.daysRemaining).toBeLessThanOrEqual(31);
  });

  test('result is cached on second call', async () => {
    const client = makeClient('ENTERPRISE');
    const r1 = await client.validate();
    const r2 = await client.validate();
    expect(r1).toBe(r2); // same reference
  });

  test('force=true returns new result object', async () => {
    const client = makeClient('ENTERPRISE');
    const r1 = await client.validate();
    const r2 = await client.validate(true);
    expect(r1).not.toBe(r2);
    expect(r1.tier).toBe(r2.tier);
  });
});

// ── FEATURE GATING ────────────────────────────────────────────────────────────

describe('IronWallClient — hasFeature()', () => {
  const cases: [string, Feature, boolean][] = [
    ['COMMUNITY',    Feature.CoreWAF,          true],
    ['COMMUNITY',    Feature.GeoIPBlocking,    false],
    ['COMMUNITY',    Feature.SIEM,             false],
    ['PROFESSIONAL', Feature.APIRateLimit,     true],
    ['PROFESSIONAL', Feature.AIThreatHunting,  false],
    ['ENTERPRISE',   Feature.SIEM,             true],
    ['ENTERPRISE',   Feature.Prometheus,       true],
    ['ENTERPRISE',   Feature.ZeroDayShield,    false],
    ['ULTIMATE',     Feature.ZeroDayShield,    true],
    ['ULTIMATE',     Feature.Forensics,        true],
    ['ULTIMATE',     Feature.DDoSMitigation,   true],
    ['TRIAL',        Feature.ThreatIntel,      true],
    ['TRIAL',        Feature.AIThreatHunting,  true],
  ];

  test.each(cases)('%s/%s → %s', async (tier, feature, expected) => {
    const client = makeClient(tier);
    await client.init();
    expect(await client.hasFeature(feature)).toBe(expected);
  });

  test('extra features extend tier', async () => {
    const client = makeClient('PROFESSIONAL', 365, false, ['ai_threat_hunting']);
    await client.init();
    expect(await client.hasFeature(Feature.AIThreatHunting)).toBe(true);
  });

  test('disabled features override tier', async () => {
    const client = makeClient('ENTERPRISE', 365, false, [], ['siem']);
    await client.init();
    expect(await client.hasFeature(Feature.SIEM)).toBe(false);
    // Other ENT features should still work
    expect(await client.hasFeature(Feature.GeoIPBlocking)).toBe(true);
  });

  test('hasFeature returns false on invalid license', async () => {
    const file = writeTempLicense('INVALID CONTENT NOT BASE64');
    const client = new IronWallClient({ licenseFile: file, autoRefresh: false });
    expect(await client.hasFeature(Feature.CoreWAF)).toBe(false);
  });
});

// ── ASSERT FEATURE ────────────────────────────────────────────────────────────

describe('IronWallClient — assertFeature()', () => {
  test('assertFeature passes for available feature', async () => {
    const client = makeClient('ENTERPRISE');
    await client.init();
    await expect(client.assertFeature(Feature.SIEM)).resolves.toBeUndefined();
  });

  test('assertFeature throws FeatureNotAvailableError', async () => {
    const client = makeClient('COMMUNITY');
    await client.init();
    await expect(client.assertFeature(Feature.Forensics))
      .rejects.toThrow(FeatureNotAvailableError);
  });

  test('FeatureNotAvailableError contains feature name', async () => {
    const client = makeClient('COMMUNITY');
    await client.init();
    try {
      await client.assertFeature(Feature.ZeroDayShield);
    } catch (err) {
      expect(err).toBeInstanceOf(FeatureNotAvailableError);
      const e = err as FeatureNotAvailableError;
      expect(e.feature).toBe(Feature.ZeroDayShield);
      expect(e.tier).toBe('COMMUNITY');
      expect(e.message).toContain('optimiumnexus.com');
    }
  });
});

// ── EXPRESS MIDDLEWARE ────────────────────────────────────────────────────────

describe('IronWallClient — requireFeature() Express middleware', () => {
  test('calls next() when feature is available', async () => {
    const client = makeClient('ULTIMATE');
    await client.init();
    const middleware = client.requireFeature(Feature.Forensics);

    const req = {} as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();

    await middleware(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  test('returns 403 when feature is not available', async () => {
    const client = makeClient('COMMUNITY');
    await client.init();
    const middleware = client.requireFeature(Feature.Forensics);

    const req = {} as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();

    await middleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: 'feature_not_licensed',
        feature: Feature.Forensics,
        upgradeUrl: expect.stringContaining('optimiumnexus.com'),
      })
    );
  });
});

// ── LIMITS ────────────────────────────────────────────────────────────────────

describe('IronWallClient — limits', () => {
  test('COMMUNITY has maxSites=1', async () => {
    const r = await makeClient('COMMUNITY').validate();
    expect(r.limits?.maxSites).toBe(1);
    expect(r.limits?.maxRequestsPerSec).toBe(500);
    expect(r.limits?.supportLevel).toBe('community');
  });

  test('ULTIMATE has unlimited everything', async () => {
    const r = await makeClient('ULTIMATE').validate();
    expect(r.limits?.maxSites).toBe(-1);
    expect(r.limits?.maxRequestsPerSec).toBe(-1);
    expect(r.limits?.maxNodes).toBe(-1);
    expect(r.limits?.supportLevel).toBe('dedicated');
  });

  test('ENTERPRISE limits are correct', async () => {
    const r = await makeClient('ENTERPRISE').validate();
    expect(r.limits?.maxSites).toBe(-1);
    expect(r.limits?.maxNodes).toBe(10);
    expect(r.limits?.maxUsers).toBe(50);
    expect(r.limits?.supportLevel).toBe('priority');
  });
});

// ── STATUS & INFO ─────────────────────────────────────────────────────────────

describe('IronWallClient — status() & info()', () => {
  test('status includes tier for valid license', async () => {
    const client = makeClient('ENTERPRISE', 100);
    await client.init();
    expect(client.status()).toContain('ENTERPRISE');
    expect(client.status()).toContain('✅');
  });

  test('status shows expiry warning for soon-expiring license', async () => {
    const client = makeClient('PROFESSIONAL', 5);
    await client.init();
    expect(client.status()).toMatch(/⚠|5/);
  });

  test('status shows lifetime for lifetime license', async () => {
    const client = makeClient('ULTIMATE', 0, true);
    await client.init();
    expect(client.status().toLowerCase()).toContain('lifetime');
  });

  test('status before init is descriptive', () => {
    const client = makeClient('ENTERPRISE');
    expect(client.status()).toContain('init');
  });

  test('info() returns expected shape', async () => {
    const client = makeClient('ENTERPRISE');
    await client.init();
    const info = client.info();
    expect(info.valid).toBe(true);
    expect(info.tier).toBe('ENTERPRISE');
    expect(typeof info.featuresCount).toBe('number');
    expect((info.featuresCount as number)).toBeGreaterThan(0);
  });
});

// ── PROPERTIES ────────────────────────────────────────────────────────────────

describe('IronWallClient — properties', () => {
  test('tier property after init', async () => {
    const client = makeClient('PROFESSIONAL');
    await client.init();
    expect(client.tier).toBe('PROFESSIONAL');
  });

  test('isValid after successful init', async () => {
    const client = makeClient('ENTERPRISE');
    await client.init();
    expect(client.isValid).toBe(true);
  });

  test('daysRemaining for lifetime license', async () => {
    const client = makeClient('ULTIMATE', 0, true);
    await client.init();
    expect(client.daysRemaining).toBe(-1);
  });

  test('destroy() clears refresh timer', () => {
    const client = makeClient('ENTERPRISE');
    expect(() => client.destroy()).not.toThrow();
  });
});
