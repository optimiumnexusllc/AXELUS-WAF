"""
IronWall Python SDK — Unit Tests
Publisher: OPTIMIUM NEXUS LLC
"""
import base64
import json
import pytest
from datetime import datetime, timedelta, timezone
from ironwall import (
    IronWallClient, Feature, IronWallError, LicenseNotFoundError,
    FeatureNotAvailableError, ValidationResult, TIER_FEATURES
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_license_pem(tier="ENTERPRISE", days=365, is_lifetime=False,
                      extra_features=None, disabled_features=None):
    """Generate a mock license PEM for testing (no real crypto)."""
    payload = {
        "id":   "test-id-" + tier.lower(),
        "key":  f"IW-{tier[:3]}-TEST-XXXX-YYYY-ZZZZ",
        "tier": tier,
        "licensee": "Test Corp E2E",
        "email":    "test@corp.local",
        "is_lifetime": is_lifetime,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=days)).timestamp() if not is_lifetime else 0,
        "extra_features":    extra_features or [],
        "disabled_features": disabled_features or [],
        "signature": "fakesig==",
        "public_key_id": "test-key",
    }
    b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    return f"-----BEGIN IRONWALL LICENSE-----\n{b64}\n-----END IRONWALL LICENSE-----"


def make_client(tier="ENTERPRISE", days=365, is_lifetime=False,
                extra_features=None, disabled_features=None, tmp_path=None):
    """Create an IronWallClient with a mock license file."""
    pem = make_license_pem(tier, days, is_lifetime, extra_features, disabled_features)
    if tmp_path:
        lic_file = tmp_path / "test.lic"
        lic_file.write_text(pem)
        return IronWallClient(license_file=str(lic_file), auto_refresh=False)
    # Use inline PEM via env trick
    import tempfile, os
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.lic', delete=False)
    f.write(pem)
    f.close()
    return IronWallClient(license_file=f.name, auto_refresh=False)


# ── Tier Feature Tests ────────────────────────────────────────────────────────

class TestTierFeatures:
    def test_community_has_core_waf(self):
        assert Feature.CORE_WAF in TIER_FEATURES["COMMUNITY"]

    def test_community_missing_geoip(self):
        assert Feature.GEO_IP_BLOCKING not in TIER_FEATURES["COMMUNITY"]

    def test_professional_has_rate_limit(self):
        assert Feature.API_RATE_LIMIT in TIER_FEATURES["PROFESSIONAL"]

    def test_professional_missing_siem(self):
        assert Feature.SIEM not in TIER_FEATURES["PROFESSIONAL"]

    def test_enterprise_has_siem(self):
        assert Feature.SIEM in TIER_FEATURES["ENTERPRISE"]

    def test_enterprise_missing_ai_hunting(self):
        assert Feature.AI_THREAT_HUNTING not in TIER_FEATURES["ENTERPRISE"]

    def test_ultimate_has_all_premium(self):
        ult = TIER_FEATURES["ULTIMATE"]
        premium = [
            Feature.AI_THREAT_HUNTING, Feature.ZERO_DAY_SHIELD,
            Feature.DDOS_MITIGATION, Feature.FORENSICS, Feature.DECEPTION_LAYER,
        ]
        for f in premium:
            assert f in ult, f"ULTIMATE missing {f}"

    def test_tier_progression(self):
        """Enterprise should include all Professional features."""
        pro = set(TIER_FEATURES["PROFESSIONAL"])
        ent = set(TIER_FEATURES["ENTERPRISE"])
        missing = pro - ent
        assert not missing, f"Enterprise missing PRO features: {missing}"

    def test_ultimate_includes_enterprise(self):
        ent = set(TIER_FEATURES["ENTERPRISE"])
        ult = set(TIER_FEATURES["ULTIMATE"])
        missing = ent - ult
        assert not missing, f"Ultimate missing ENT features: {missing}"

    def test_no_duplicates(self):
        for tier, features in TIER_FEATURES.items():
            seen = set()
            for f in features:
                assert f not in seen, f"Duplicate feature {f} in {tier}"
                seen.add(f)


# ── Client Tests ──────────────────────────────────────────────────────────────

class TestIronWallClient:
    def test_init_without_license_raises(self):
        with pytest.raises(IronWallError):
            IronWallClient(auto_refresh=False)

    def test_missing_file_raises(self):
        with pytest.raises(LicenseNotFoundError):
            IronWallClient(license_file="/nonexistent/ironwall.lic", auto_refresh=False)

    def test_enterprise_valid(self):
        c = make_client("ENTERPRISE")
        r = c.validate()
        assert r.valid is True
        assert r.tier == "ENTERPRISE"
        assert r.licensee == "Test Corp E2E"

    def test_has_feature_enterprise(self):
        c = make_client("ENTERPRISE")
        assert c.has_feature(Feature.SIEM) is True
        assert c.has_feature(Feature.GEO_IP_BLOCKING) is True
        assert c.has_feature(Feature.AI_THREAT_HUNTING) is False

    def test_has_feature_ultimate(self):
        c = make_client("ULTIMATE")
        assert c.has_feature(Feature.AI_THREAT_HUNTING) is True
        assert c.has_feature(Feature.FORENSICS) is True
        assert c.has_feature(Feature.ZERO_DAY_SHIELD) is True

    def test_has_feature_community(self):
        c = make_client("COMMUNITY")
        assert c.has_feature(Feature.CORE_WAF) is True
        assert c.has_feature(Feature.GEO_IP_BLOCKING) is False
        assert c.has_feature(Feature.SIEM) is False

    def test_extra_features_override(self):
        c = make_client("PROFESSIONAL", extra_features=["ai_threat_hunting"])
        assert c.has_feature(Feature.AI_THREAT_HUNTING) is True

    def test_disabled_features(self):
        c = make_client("ENTERPRISE", disabled_features=["siem"])
        assert c.has_feature(Feature.SIEM) is False
        # Other ENT features should still work
        assert c.has_feature(Feature.GEO_IP_BLOCKING) is True

    def test_require_feature_decorator_passes(self):
        c = make_client("ULTIMATE")

        @c.require_feature(Feature.FORENSICS)
        def forensics_fn():
            return "ran"

        assert forensics_fn() == "ran"

    def test_require_feature_decorator_blocks(self):
        c = make_client("COMMUNITY")

        @c.require_feature(Feature.FORENSICS)
        def forensics_fn():
            return "ran"

        with pytest.raises(FeatureNotAvailableError) as exc:
            forensics_fn()
        assert "forensics" in str(exc.value).lower()
        assert "COMMUNITY" in str(exc.value)
        assert "optimiumnexus.com" in str(exc.value)

    def test_assert_feature_raises_correctly(self):
        c = make_client("PROFESSIONAL")
        with pytest.raises(FeatureNotAvailableError):
            c.assert_feature(Feature.AI_THREAT_HUNTING)

    def test_assert_feature_passes(self):
        c = make_client("ENTERPRISE")
        c.assert_feature(Feature.SIEM)  # should not raise

    def test_tier_property(self):
        c = make_client("ENTERPRISE")
        assert c.tier == "ENTERPRISE"

    def test_is_valid_property(self):
        c = make_client("PROFESSIONAL")
        assert c.is_valid is True

    def test_days_remaining_positive(self):
        c = make_client("ENTERPRISE", days=30)
        assert 28 <= c.days_remaining <= 31

    def test_days_remaining_lifetime(self):
        c = make_client("ULTIMATE", is_lifetime=True)
        assert c.days_remaining == -1

    def test_status_string_valid(self):
        c = make_client("ENTERPRISE", days=100)
        s = c.status()
        assert "✅" in s
        assert "ENTERPRISE" in s

    def test_status_string_expiring_soon(self):
        c = make_client("PROFESSIONAL", days=5)
        s = c.status()
        assert "⚠" in s or "5" in s

    def test_status_string_lifetime(self):
        c = make_client("ULTIMATE", is_lifetime=True)
        s = c.status()
        assert "lifetime" in s.lower()

    def test_info_dict(self):
        c = make_client("ENTERPRISE")
        info = c.info()
        assert info["valid"] is True
        assert info["tier"] == "ENTERPRISE"
        assert info["features_count"] > 0

    def test_caching(self):
        """validate() should return same object on repeated calls (cached)."""
        c = make_client("ENTERPRISE")
        r1 = c.validate()
        r2 = c.validate()
        assert r1 is r2  # same cached object

    def test_force_refresh(self):
        c = make_client("ENTERPRISE")
        r1 = c.validate()
        r2 = c.validate(force=True)
        assert r1.tier == r2.tier  # same content
        assert r1 is not r2        # different objects

    def test_limits_enterprise(self):
        c = make_client("ENTERPRISE")
        r = c.validate()
        assert r.limits is not None
        assert r.limits.max_sites == -1    # unlimited
        assert r.limits.max_nodes == 10
        assert r.limits.support_level == "priority"

    def test_limits_community(self):
        c = make_client("COMMUNITY")
        r = c.validate()
        assert r.limits.max_sites == 1
        assert r.limits.max_requests_per_sec == 500

    def test_limits_ultimate_unlimited(self):
        c = make_client("ULTIMATE")
        r = c.validate()
        assert r.limits.max_sites == -1
        assert r.limits.max_requests_per_sec == -1
        assert r.limits.max_nodes == -1
        assert r.limits.support_level == "dedicated"

    def test_validation_result_is_expired_false(self):
        c = make_client("ENTERPRISE", days=100)
        r = c.validate()
        assert r.is_expired is False

    def test_validation_result_is_expired_lifetime(self):
        c = make_client("ULTIMATE", is_lifetime=True)
        r = c.validate()
        assert r.is_expired is False
        assert r.is_lifetime is True


# ── Feature Not Available Error ───────────────────────────────────────────────

class TestFeatureNotAvailableError:
    def test_error_message_contains_feature(self):
        err = FeatureNotAvailableError(Feature.FORENSICS, "PROFESSIONAL")
        assert "forensics" in str(err).lower()

    def test_error_message_contains_tier(self):
        err = FeatureNotAvailableError(Feature.FORENSICS, "PROFESSIONAL")
        assert "PROFESSIONAL" in str(err)

    def test_error_message_contains_upgrade_url(self):
        err = FeatureNotAvailableError(Feature.FORENSICS, "PROFESSIONAL")
        assert "optimiumnexus.com" in str(err)

    def test_error_attributes(self):
        err = FeatureNotAvailableError(Feature.AI_THREAT_HUNTING, "ENTERPRISE")
        assert err.feature == Feature.AI_THREAT_HUNTING
        assert err.tier == "ENTERPRISE"
