"""Tests for ScanModule and ModuleRegistry."""

from __future__ import annotations

import pytest

from strix.core.tci import ApiSurface, TargetFingerprint
from strix.modules.registry import (
    ModuleRegistry,
    PriorityTier,
    ScanModule,
    default_registry,
    get_module,
    list_modules,
    register_module,
)


def test_default_registry_has_builtins() -> None:
    modules = list_modules()
    assert len(modules) >= 10

    auth_enum = get_module("auth-enum")
    assert auth_enum is not None
    assert auth_enum.category == "authentication"
    assert auth_enum.default_priority == PriorityTier.HIGH
    assert auth_enum.requires_auth is True

    id_or = get_module("id_or")
    assert id_or is not None
    assert id_or.category == "authorization"
    assert "auth-enum" in id_or.prerequisites

    sqli = get_module("sqli-fuzz")
    assert sqli is not None
    assert sqli.intrusive is True


def test_custom_module_lifecycle() -> None:
    reg = ModuleRegistry(populate_defaults=False)
    assert len(reg.list_all()) == 0

    custom = ScanModule(
        name="custom-cors-audit",
        description="Custom CORS validator",
        category="recon",
        target_types=["web_app", "api"],
        default_priority=PriorityTier.LOW,
        safe_mode_default=True,
        default_quota=25,
        default_timeout_s=120.0,
        tags=["custom", "cors"],
    )
    reg.register(custom)

    assert reg.get("custom-cors-audit") == custom
    assert reg.get_or_raise("custom-cors-audit") == custom
    assert len(reg.list_all()) == 1
    assert len(reg.list_by_category("recon")) == 1
    assert len(reg.list_by_tag("cors")) == 1

    assert reg.unregister("custom-cors-audit") is True
    assert reg.get("custom-cors-audit") is None
    assert reg.unregister("custom-cors-audit") is False

    with pytest.raises(KeyError, match="Unknown scan module"):
        reg.get_or_raise("custom-cors-audit")


def test_update_metadata_priority_quota_safe_mode() -> None:
    reg = ModuleRegistry(populate_defaults=True)

    # Initial state
    orig = reg.get_or_raise("sqli-fuzz")
    assert orig.safe_mode_default is False
    assert orig.default_quota == 50

    # Accept priority metadata, quotas, safe_mode hints, and timeouts
    updated = reg.update_metadata(
        "sqli-fuzz",
        priority=PriorityTier.CRITICAL,
        quota=120,
        safe_mode=True,
        timeout_s=600.0,
        description="Deep aggressive SQLi testing with strict rate limits",
    )

    assert updated.default_priority == PriorityTier.CRITICAL
    assert updated.default_quota == 120
    assert updated.safe_mode_default is True
    assert updated.default_timeout_s == 600.0
    assert updated.description == "Deep aggressive SQLi testing with strict rate limits"

    # String priority conversion
    updated2 = reg.update_metadata("sqli-fuzz", priority="low")
    assert updated2.default_priority == PriorityTier.LOW


def test_find_applicable_filters_irrelevant_tests() -> None:
    reg = ModuleRegistry(populate_defaults=True)

    # 1. Unauthenticated target: auth-dependent modules must be excluded
    fp_no_auth = TargetFingerprint(
        target="https://public.example.com",
        target_type="web_app",
        auth_patterns=[],
    )
    applicable_no_auth = {m.name for m in reg.find_applicable(fp_no_auth)}
    assert "auth-enum" not in applicable_no_auth
    assert "id_or" not in applicable_no_auth
    assert "jwt-analyze" not in applicable_no_auth
    assert "xss-test" in applicable_no_auth

    # 2. Authenticated target with session cookie (no JWT, no GraphQL)
    fp_cookie = TargetFingerprint(
        target="https://app.example.com",
        target_type="web_app",
        auth_patterns=["session_cookie"],
    )
    applicable_cookie = {m.name for m in reg.find_applicable(fp_cookie)}
    assert "auth-enum" in applicable_cookie
    assert "id_or" in applicable_cookie
    assert "jwt-analyze" not in applicable_cookie
    assert "graphql-audit" not in applicable_cookie

    # 3. Authenticated API with JWT and GraphQL
    fp_jwt_graphql = TargetFingerprint(
        target="https://api.example.com",
        target_type="api",
        auth_patterns=["jwt"],
        api_surface=ApiSurface(
            endpoints_count=10,
            api_types=["rest", "graphql"],
        ),
    )
    applicable_jwt_graphql = {m.name for m in reg.find_applicable(fp_jwt_graphql)}
    assert "jwt-analyze" in applicable_jwt_graphql
    assert "graphql-audit" in applicable_jwt_graphql
    assert "id_or" in applicable_jwt_graphql


def test_register_module_helper() -> None:
    test_mod = ScanModule(
        name="test-singleton-mod",
        description="Helper test module",
        category="recon",
    )
    register_module(test_mod)
    try:
        assert default_registry.get("test-singleton-mod") == test_mod
    finally:
        default_registry.unregister("test-singleton-mod")
