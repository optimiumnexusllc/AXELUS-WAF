"""
IronWall-WAF Python SDK
=======================
Client library for validating IronWall licenses and gating features
in Python applications.

Publisher: OPTIMIUM NEXUS LLC — https://www.optimiumnexus.com
Contact:   contact@optimiumnexus.com
License:   MIT (SDK only)

Installation:
    pip install ironwall-sdk

Usage:
    from ironwall import IronWallClient, Feature

    client = IronWallClient(
        license_file="path/to/ironwall.lic",
        # OR
        license_key="IW-ENT-XXXX-XXXX-XXXX-XXXX",
        api_url="https://your-ironwall-instance:9443",
    )

    # Validate license
    status = client.validate()
    print(status.tier, status.days_remaining)

    # Check a specific feature
    if client.has_feature(Feature.GEO_IP_BLOCKING):
        # enable GeoIP blocking
        pass

    # Decorator usage
    @client.require_feature(Feature.AI_THREAT_HUNTING)
    def run_threat_hunt():
        pass
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any
import urllib.request
import urllib.error
import ssl


# ── Feature Enum ──────────────────────────────────────────────────────────────

class Feature(str, Enum):
    """All available IronWall-WAF features."""

    # Core (all tiers)
    CORE_WAF          = "core_waf"
    BASIC_DASHBOARD   = "basic_dashboard"
    OWASP_RULES       = "owasp_rules"
    BOT_PROTECTION    = "bot_protection"

    # Professional+
    ADVANCED_RULES    = "advanced_rules"
    API_RATE_LIMIT    = "api_rate_limit"
    SSL_OFFLOAD       = "ssl_offload"
    MULTI_SITE        = "multi_site"
    AUDIT_LOG         = "audit_log"
    ALERTING_BASIC    = "alerting_basic"
    BACKUP_RESTORE    = "backup_restore"

    # Enterprise+
    GEO_IP_BLOCKING   = "geoip_blocking"
    THREAT_INTEL      = "threat_intel"
    ALERTING_FULL     = "alerting_full"
    SIEM              = "siem"
    PROMETHEUS        = "prometheus"
    HIGH_AVAILABILITY = "high_availability"
    UNLIMITED_SITES   = "unlimited_sites"
    COMPLIANCE_REPORT = "compliance_report"
    KUBERNETES_HELM   = "kubernetes_helm"

    # Ultimate only
    AI_THREAT_HUNTING = "ai_threat_hunting"
    ZERO_DAY_SHIELD   = "zero_day_shield"
    DDOS_MITIGATION   = "ddos_mitigation"
    DECEPTION_LAYER   = "deception_layer"
    FORENSICS         = "forensics"
    CUSTOM_BRANDING   = "custom_branding"
    MULTI_TENANCY     = "multi_tenancy"
    API_FULL_ACCESS   = "api_full_access"
    PRIORITY_SUPPORT  = "priority_support"
    CUSTOM_INTEGRATION = "custom_integration"


# ── Tier → Features mapping (mirrors Go licensing/pkg/license/license.go) ─────

TIER_FEATURES: Dict[str, List[str]] = {
    "COMMUNITY": [
        Feature.CORE_WAF, Feature.BASIC_DASHBOARD,
        Feature.OWASP_RULES, Feature.BOT_PROTECTION,
    ],
    "PROFESSIONAL": [
        Feature.CORE_WAF, Feature.BASIC_DASHBOARD, Feature.OWASP_RULES, Feature.BOT_PROTECTION,
        Feature.ADVANCED_RULES, Feature.API_RATE_LIMIT, Feature.SSL_OFFLOAD,
        Feature.MULTI_SITE, Feature.AUDIT_LOG, Feature.ALERTING_BASIC, Feature.BACKUP_RESTORE,
    ],
    "ENTERPRISE": [
        Feature.CORE_WAF, Feature.BASIC_DASHBOARD, Feature.OWASP_RULES, Feature.BOT_PROTECTION,
        Feature.ADVANCED_RULES, Feature.API_RATE_LIMIT, Feature.SSL_OFFLOAD,
        Feature.MULTI_SITE, Feature.AUDIT_LOG, Feature.ALERTING_BASIC, Feature.BACKUP_RESTORE,
        Feature.GEO_IP_BLOCKING, Feature.THREAT_INTEL, Feature.ALERTING_FULL,
        Feature.SIEM, Feature.PROMETHEUS, Feature.HIGH_AVAILABILITY,
        Feature.UNLIMITED_SITES, Feature.COMPLIANCE_REPORT, Feature.KUBERNETES_HELM,
    ],
    "ULTIMATE": [
        Feature.CORE_WAF, Feature.BASIC_DASHBOARD, Feature.OWASP_RULES, Feature.BOT_PROTECTION,
        Feature.ADVANCED_RULES, Feature.API_RATE_LIMIT, Feature.SSL_OFFLOAD,
        Feature.MULTI_SITE, Feature.AUDIT_LOG, Feature.ALERTING_BASIC, Feature.BACKUP_RESTORE,
        Feature.GEO_IP_BLOCKING, Feature.THREAT_INTEL, Feature.ALERTING_FULL,
        Feature.SIEM, Feature.PROMETHEUS, Feature.HIGH_AVAILABILITY,
        Feature.UNLIMITED_SITES, Feature.COMPLIANCE_REPORT, Feature.KUBERNETES_HELM,
        Feature.AI_THREAT_HUNTING, Feature.ZERO_DAY_SHIELD, Feature.DDOS_MITIGATION,
        Feature.DECEPTION_LAYER, Feature.FORENSICS, Feature.CUSTOM_BRANDING,
        Feature.MULTI_TENANCY, Feature.API_FULL_ACCESS, Feature.PRIORITY_SUPPORT,
        Feature.CUSTOM_INTEGRATION,
    ],
    "TRIAL": [
        Feature.CORE_WAF, Feature.BASIC_DASHBOARD, Feature.OWASP_RULES, Feature.BOT_PROTECTION,
        Feature.ADVANCED_RULES, Feature.API_RATE_LIMIT, Feature.GEO_IP_BLOCKING,
        Feature.THREAT_INTEL, Feature.ALERTING_FULL, Feature.SIEM, Feature.PROMETHEUS,
        Feature.HIGH_AVAILABILITY, Feature.UNLIMITED_SITES, Feature.COMPLIANCE_REPORT,
        Feature.AI_THREAT_HUNTING, Feature.ZERO_DAY_SHIELD, Feature.DDOS_MITIGATION,
    ],
    "DEVELOPER": [
        Feature.CORE_WAF, Feature.BASIC_DASHBOARD, Feature.OWASP_RULES, Feature.BOT_PROTECTION,
        Feature.ADVANCED_RULES, Feature.API_FULL_ACCESS, Feature.CUSTOM_INTEGRATION,
    ],
}


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class LicenseLimits:
    max_sites: int           # -1 = unlimited
    max_requests_per_sec: int
    max_nodes: int
    max_users: int
    max_custom_rules: int
    support_level: str
    update_channel: str


@dataclass
class ValidationResult:
    valid: bool
    tier: str
    licensee: str
    email: str
    key: str
    domain: Optional[str]
    is_lifetime: bool
    expires_at: Optional[datetime]
    days_remaining: int          # -1 = lifetime
    features: List[str]
    extra_features: List[str]
    disabled_features: List[str]
    limits: Optional[LicenseLimits]
    errors: List[str]
    warnings: List[str]
    validated_at: datetime

    @property
    def is_expired(self) -> bool:
        if self.is_lifetime or self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def has_feature(self, feature: Feature) -> bool:
        if not self.valid or self.is_expired:
            return False
        f = str(feature) if not isinstance(feature, str) else feature
        if f in self.disabled_features:
            return False
        if f in self.extra_features:
            return True
        return f in self.features


# ── Exceptions ────────────────────────────────────────────────────────────────

class IronWallError(Exception):
    """Base IronWall SDK exception."""

class LicenseNotFoundError(IronWallError):
    """License file or key not found."""

class LicenseInvalidError(IronWallError):
    """License is invalid, expired, or revoked."""

class FeatureNotAvailableError(IronWallError):
    """Feature not available on current license tier."""
    def __init__(self, feature: Feature, tier: str):
        self.feature = feature
        self.tier = tier
        super().__init__(
            f"Feature '{feature}' is not available on {tier} tier. "
            f"Upgrade at https://www.optimiumnexus.com/upgrade"
        )


# ── Client ────────────────────────────────────────────────────────────────────

class IronWallClient:
    """
    IronWall-WAF Python SDK client.

    Validates licenses online (via IronWall API) or offline (from license file).
    Caches validation results and auto-refreshes in the background.

    Examples:
        # Online validation
        client = IronWallClient(
            license_key="IW-ENT-XXXX-XXXX-XXXX-XXXX",
            api_url="https://waf.mycompany.com:9443",
        )

        # Offline validation from file
        client = IronWallClient(license_file="/etc/ironwall/ironwall.lic")

        # Check feature and use decorator
        if client.has_feature(Feature.GEO_IP_BLOCKING):
            enable_geoip()

        @client.require_feature(Feature.AI_THREAT_HUNTING)
        def run_threat_analysis():
            ...
    """

    def __init__(
        self,
        license_file: Optional[str] = None,
        license_key:  Optional[str] = None,
        api_url:      Optional[str] = None,
        admin_key:    Optional[str] = None,
        cache_ttl:    int = 3600,      # seconds (1h default)
        auto_refresh: bool = True,
        verify_tls:   bool = False,    # Set True in production with valid cert
    ):
        self._license_file = license_file or os.getenv("IRONWALL_LICENSE_FILE")
        self._license_key  = license_key  or os.getenv("IRONWALL_LICENSE_KEY")
        self._api_url      = (api_url or os.getenv("IRONWALL_API_URL", "")).rstrip("/")
        self._admin_key    = admin_key or os.getenv("IRONWALL_ADMIN_KEY", "")
        self._cache_ttl    = cache_ttl
        self._verify_tls   = verify_tls

        self._cache:        Optional[ValidationResult] = None
        self._cache_ts:     float = 0
        self._lock          = threading.Lock()

        if not self._license_file and not self._license_key:
            raise IronWallError(
                "Provide license_file or license_key (or set IRONWALL_LICENSE_FILE / IRONWALL_LICENSE_KEY env var)"
            )

        # Initial validation
        self.validate()

        # Background refresh
        if auto_refresh and self._api_url:
            self._start_background_refresh()

    # ── Validation ──────────────────────────────────────────────────────────────

    def validate(self, force: bool = False) -> ValidationResult:
        """
        Validate the license. Returns cached result if still fresh.
        Set force=True to bypass cache.
        """
        with self._lock:
            if not force and self._cache and (time.time() - self._cache_ts) < self._cache_ttl:
                return self._cache

            if self._api_url:
                result = self._validate_online()
            else:
                result = self._validate_offline()

            self._cache = result
            self._cache_ts = time.time()
            return result

    def _validate_online(self) -> ValidationResult:
        """Validate via IronWall management API."""
        payload = self._build_validation_payload()
        try:
            ctx = ssl.create_default_context()
            if not self._verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                f"{self._api_url}/api/v1/licensing/validate",
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-Admin-Key":  self._admin_key,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                body = json.loads(resp.read().decode())
                return self._parse_api_response(body)

        except urllib.error.URLError as e:
            # Fall back to offline validation
            import warnings
            warnings.warn(f"Online validation failed ({e}), falling back to offline mode")
            return self._validate_offline()

    def _validate_offline(self) -> ValidationResult:
        """
        Parse and validate the license file locally.
        Verifies the PEM structure but cannot verify the ED25519 signature
        without the CA public key (use online mode for full verification).
        """
        pem = self._load_pem()
        if not pem:
            raise LicenseNotFoundError("No license file or key content found")

        try:
            # Extract base64 payload
            content = pem
            content = content.replace("-----BEGIN IRONWALL LICENSE-----", "")
            content = content.replace("-----END IRONWALL LICENSE-----", "")
            content = content.replace("\n", "").strip()

            raw = base64.b64decode(content + "==")
            data = json.loads(raw.decode())

            tier   = data.get("tier", "UNKNOWN")
            expiry = None
            is_life = data.get("is_lifetime", False)

            if not is_life and data.get("expires_at"):
                ts = data["expires_at"]
                if isinstance(ts, (int, float)):
                    expiry = datetime.fromtimestamp(ts, tz=timezone.utc)
                else:
                    expiry = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))

            days = -1
            if not is_life and expiry:
                delta = expiry - datetime.now(timezone.utc)
                days  = max(0, int(delta.total_seconds() / 86400))

            features         = [str(f) for f in TIER_FEATURES.get(tier, [])]
            extra_features   = [str(f) for f in data.get("extra_features", []) or []]
            disabled_features = [str(f) for f in data.get("disabled_features", []) or []]

            return ValidationResult(
                valid              = True,
                tier               = tier,
                licensee           = data.get("licensee", ""),
                email              = data.get("email", ""),
                key                = data.get("key", ""),
                domain             = data.get("domain"),
                is_lifetime        = is_life,
                expires_at         = expiry,
                days_remaining     = days,
                features           = features,
                extra_features     = extra_features,
                disabled_features  = disabled_features,
                limits             = self._build_limits(tier),
                errors             = [],
                warnings           = self._build_warnings(days),
                validated_at       = datetime.now(timezone.utc),
            )
        except Exception as e:
            return ValidationResult(
                valid=False, tier="UNKNOWN", licensee="", email="", key="",
                domain=None, is_lifetime=False, expires_at=None, days_remaining=0,
                features=[], extra_features=[], disabled_features=[],
                limits=None, errors=[f"License parse failed: {e}"],
                warnings=[], validated_at=datetime.now(timezone.utc),
            )

    def _parse_api_response(self, body: dict) -> ValidationResult:
        tier     = body.get("tier", "UNKNOWN")
        is_life  = body.get("is_lifetime", False)
        expiry   = None
        days     = body.get("days_remaining", 0)

        if body.get("expires_at") and not is_life:
            try:
                expiry = datetime.fromisoformat(str(body["expires_at"]).replace("Z", "+00:00"))
            except Exception:
                pass

        features = [str(f) for f in TIER_FEATURES.get(tier, [])]

        return ValidationResult(
            valid              = body.get("valid", False),
            tier               = tier,
            licensee           = body.get("licensee", ""),
            email              = body.get("email", ""),
            key                = body.get("key", ""),
            domain             = body.get("domain"),
            is_lifetime        = is_life,
            expires_at         = expiry,
            days_remaining     = days if is_life else days,
            features           = features,
            extra_features     = body.get("extra_features", []) or [],
            disabled_features  = body.get("disabled_features", []) or [],
            limits             = self._build_limits(tier),
            errors             = body.get("errors", []) or [],
            warnings           = body.get("warnings", []) or [],
            validated_at       = datetime.now(timezone.utc),
        )

    # ── Feature Access ──────────────────────────────────────────────────────────

    def has_feature(self, feature: Feature) -> bool:
        """Returns True if the current license grants the given feature."""
        try:
            result = self.validate()
            return result.has_feature(feature)
        except Exception:
            return False

    def require_feature(self, feature: Feature) -> Callable:
        """
        Decorator that raises FeatureNotAvailableError if the feature
        is not licensed.

        Usage::

            @client.require_feature(Feature.FORENSICS)
            def start_packet_capture():
                ...
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                if not self.has_feature(feature):
                    result = self.validate()
                    raise FeatureNotAvailableError(feature, result.tier)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def assert_feature(self, feature: Feature) -> None:
        """Raises FeatureNotAvailableError if feature is not available."""
        if not self.has_feature(feature):
            result = self.validate()
            raise FeatureNotAvailableError(feature, result.tier)

    # ── Status / Info ────────────────────────────────────────────────────────────

    @property
    def tier(self) -> str:
        return self.validate().tier

    @property
    def is_valid(self) -> bool:
        try:
            return self.validate().valid
        except Exception:
            return False

    @property
    def days_remaining(self) -> int:
        """Returns days remaining (-1 if lifetime, 0 if expired)."""
        return self.validate().days_remaining

    def status(self) -> str:
        """Returns a human-readable status string."""
        try:
            r = self.validate()
            if not r.valid:
                return f"❌ Invalid: {'; '.join(r.errors)}"
            if r.is_lifetime:
                return f"✅ {r.tier} (lifetime)"
            if r.is_expired:
                return f"⛔ {r.tier} EXPIRED"
            if r.days_remaining <= 14:
                return f"⚠️  {r.tier} (expires in {r.days_remaining} days)"
            return f"✅ {r.tier} (expires {r.expires_at.strftime('%Y-%m-%d') if r.expires_at else 'never'})"
        except Exception as e:
            return f"❌ Error: {e}"

    def info(self) -> dict:
        """Returns a dict of license information."""
        r = self.validate()
        return {
            "valid":          r.valid,
            "tier":           r.tier,
            "licensee":       r.licensee,
            "key":            r.key,
            "is_lifetime":    r.is_lifetime,
            "days_remaining": r.days_remaining,
            "features_count": len(r.features),
            "status":         self.status(),
        }

    # ── Helpers ──────────────────────────────────────────────────────────────────

    def _load_pem(self) -> Optional[str]:
        if self._license_file:
            path = Path(self._license_file)
            if not path.exists():
                raise LicenseNotFoundError(f"License file not found: {self._license_file}")
            return path.read_text(encoding="utf-8")
        if self._license_key:
            # Treat key as inline PEM content
            if self._license_key.startswith("-----BEGIN"):
                return self._license_key
            raise LicenseInvalidError("license_key should be a PEM file path or use license_file parameter")
        return None

    def _build_validation_payload(self) -> dict:
        pem = self._load_pem()
        payload: dict = {}
        if pem:
            payload["license_file"] = pem
        elif self._license_key:
            payload["license_key"] = self._license_key
        return payload

    def _build_limits(self, tier: str) -> LicenseLimits:
        defaults = {
            "COMMUNITY":    LicenseLimits(1,    500,   1,  2,  10,  "community", "stable"),
            "PROFESSIONAL": LicenseLimits(10,   5000,  2,  10, 100, "email",     "stable"),
            "ENTERPRISE":   LicenseLimits(-1,   50000, 10, 50, 1000,"priority",  "edge"),
            "ULTIMATE":     LicenseLimits(-1,   -1,    -1, -1, -1,  "dedicated", "edge"),
            "TRIAL":        LicenseLimits(-1,   -1,    3,  10, 500, "email",     "edge"),
            "DEVELOPER":    LicenseLimits(3,    1000,  1,  5,  500, "email",     "edge"),
        }
        return defaults.get(tier, LicenseLimits(-1, -1, -1, -1, -1, "unknown", "stable"))

    def _build_warnings(self, days: int) -> List[str]:
        if days == -1:
            return []
        if days == 0:
            return ["License has expired"]
        if days <= 7:
            return [f"⚠️  License expires in {days} days — renew immediately"]
        if days <= 30:
            return [f"License expires in {days} days"]
        return []

    def _start_background_refresh(self):
        def refresh_loop():
            while True:
                time.sleep(max(60, self._cache_ttl - 300))
                try:
                    self.validate(force=True)
                except Exception:
                    pass
        t = threading.Thread(target=refresh_loop, daemon=True)
        t.start()


# ── Django Middleware ────────────────────────────────────────────────────────

class IronWallMiddleware:
    """
    Django middleware that validates IronWall license on startup
    and gates feature usage.

    Add to MIDDLEWARE in settings.py:
        MIDDLEWARE = [
            ...
            'ironwall.django.IronWallMiddleware',
        ]
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.client = IronWallClient(
            license_file=os.getenv("IRONWALL_LICENSE_FILE"),
            api_url=os.getenv("IRONWALL_API_URL"),
        )

    def __call__(self, request):
        request.ironwall = self.client
        return self.get_response(request)


# ── FastAPI Dependency ────────────────────────────────────────────────────────

def create_fastapi_dependency(client: IronWallClient, feature: Feature):
    """
    Creates a FastAPI dependency that requires a specific IronWall feature.

    Usage::

        from ironwall import IronWallClient, Feature, create_fastapi_dependency
        from fastapi import Depends

        client = IronWallClient(license_file="ironwall.lic")

        @app.get("/advanced")
        async def advanced_endpoint(
            _=Depends(create_fastapi_dependency(client, Feature.AI_THREAT_HUNTING))
        ):
            return {"status": "ok"}
    """
    from fastapi import HTTPException

    async def dependency():
        if not client.has_feature(feature):
            result = client.validate()
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "feature_not_licensed",
                    "feature": str(feature),
                    "current_tier": result.tier,
                    "upgrade_url": "https://www.optimiumnexus.com/upgrade",
                }
            )
    return dependency


# ── Flask Extension ───────────────────────────────────────────────────────────

class IronWall:
    """
    Flask extension for IronWall license validation.

    Usage::

        from ironwall import IronWall, Feature

        app = Flask(__name__)
        ironwall = IronWall(app)  # or ironwall.init_app(app)

        @app.route("/premium")
        @ironwall.require(Feature.FORENSICS)
        def premium_view():
            return "OK"
    """

    def __init__(self, app=None):
        self.client: Optional[IronWallClient] = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        license_file = app.config.get("IRONWALL_LICENSE_FILE") or os.getenv("IRONWALL_LICENSE_FILE")
        api_url      = app.config.get("IRONWALL_API_URL")     or os.getenv("IRONWALL_API_URL")
        self.client  = IronWallClient(license_file=license_file, api_url=api_url)
        app.ironwall = self

    def require(self, feature: Feature):
        """Route decorator that requires a specific feature."""
        from functools import wraps
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                self.client.assert_feature(feature)
                return fn(*args, **kwargs)
            return wrapper
        return decorator
