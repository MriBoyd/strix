"""Tests for Target Complexity Index (TCI) calculation and weighting."""

from __future__ import annotations

import pytest

from strix.core.tci import (
    ApiSurface,
    TargetComplexityIndex,
    TargetFingerprint,
    TCILevel,
    TCIResult,
    TCIWeights,
    calc_api_surface_score,
    calc_auth_score,
    calc_data_sensitivity_score,
    calc_patch_posture_score,
    calc_ports_protocols_score,
    calc_tech_stack_score,
    calc_waf_defense_score,
    calculate_tci,
)


def test_empty_fingerprint_baseline() -> None:
    fp = TargetFingerprint()
    res = calculate_tci(fp)

    assert isinstance(res, TCIResult)
    assert 0.0 <= res.score <= 30.0
    assert res.level == TCILevel.LOW
    assert "ports_protocols" in res.sub_scores
    assert "auth" in res.sub_scores
    assert res.sub_scores["auth"] == 0.0


def test_complex_enterprise_fingerprint() -> None:
    fp = TargetFingerprint(
        target="https://api.enterprise.local",
        target_type="api",
        open_ports=[80, 443, 8080, 8443, 5432],
        protocols=["https", "grpc", "wss"],
        auth_patterns=["jwt", "oauth2", "mfa", "rbac"],
        api_surface=ApiSurface(
            endpoints_count=65,
            parameters_count=120,
            api_types=["rest", "graphql", "grpc"],
            has_spec=True,
            dynamic_routes=True,
        ),
        frontend_technologies=["react", "nextjs"],
        backend_technologies=["fastapi", "postgres", "redis"],
        waf_cdn=["cloudflare", "aws_waf"],
        data_sensitivity="critical",
        patch_posture="patch_lag",
    )

    res = calculate_tci(fp)

    assert res.score >= 70.0
    assert res.level in (TCILevel.COMPLEX, TCILevel.CRITICAL)
    assert res.sub_scores["auth"] >= 80.0
    assert res.sub_scores["api_surface"] >= 80.0
    assert res.sub_scores["waf_defense"] >= 80.0
    assert res.sub_scores["data_sensitivity"] >= 90.0

    # Serialization
    d = res.to_dict()
    assert d["score"] == res.score
    assert d["level"] == res.level.value
    assert isinstance(d["sub_scores"], dict)
    assert isinstance(d["breakdown"], dict)


def test_dict_coercion_and_target_complexity_index_helper() -> None:
    payload = {
        "target": "https://service.local",
        "open_ports": [443],
        "protocols": ["https"],
        "auth_patterns": ["session_cookie"],
        "api_surface": {
            "endpoints_count": 10,
            "api_types": ["rest"],
        },
    }

    res1 = calculate_tci(payload)
    res2 = TargetComplexityIndex.calculate(payload)

    assert res1.score == res2.score
    assert res1.level == res2.level
    assert res1.sub_scores == res2.sub_scores


def test_weights_normalization_and_customization() -> None:
    w = TCIWeights(
        ports_protocols=0.0,
        auth=1.0,
        api_surface=0.0,
        tech_stack=0.0,
        waf_defense=0.0,
        data_sensitivity=0.0,
        patch_posture=0.0,
    )
    norm = w.normalized_weights()
    assert norm["auth"] == 1.0
    assert norm["ports_protocols"] == 0.0

    fp_no_auth = TargetFingerprint(open_ports=[443, 8080, 9000])
    res_no_auth = calculate_tci(fp_no_auth, weights=w)
    assert res_no_auth.score == 0.0

    fp_jwt = TargetFingerprint(auth_patterns=["jwt"])
    res_jwt = calculate_tci(fp_jwt, weights=w)
    assert res_jwt.score == res_jwt.sub_scores["auth"]


def test_zero_weights_fallback() -> None:
    w = TCIWeights(
        ports_protocols=0.0,
        auth=0.0,
        api_surface=0.0,
        tech_stack=0.0,
        waf_defense=0.0,
        data_sensitivity=0.0,
        patch_posture=0.0,
    )
    norm = w.normalized_weights()
    assert len(norm) == 7
    assert sum(norm.values()) == pytest.approx(1.0)


def test_ports_protocols_scoring() -> None:
    s0, _ = calc_ports_protocols_score([], [])
    assert s0 == 10.0

    s1, _ = calc_ports_protocols_score([80, 443], ["https"])
    assert s1 == 20.0

    s2, _ = calc_ports_protocols_score([80, 443, 8080, 8443, 3306], ["https", "grpc"])
    assert s2 > s1
    assert s2 <= 100.0


def test_auth_scoring() -> None:
    s_none, _ = calc_auth_score([])
    assert s_none == 0.0

    s_basic, _ = calc_auth_score(["basic"])
    s_jwt, _ = calc_auth_score(["jwt"])
    s_oauth, _ = calc_auth_score(["oauth2", "mfa"])

    assert s_basic < s_jwt < s_oauth
    assert s_oauth <= 100.0


def test_api_surface_scoring() -> None:
    s_minimal, _ = calc_api_surface_score(ApiSurface(endpoints_count=0))
    s_small, _ = calc_api_surface_score(ApiSurface(endpoints_count=4))
    s_large, _ = calc_api_surface_score(
        ApiSurface(endpoints_count=60, api_types=["graphql"], has_spec=True)
    )

    assert s_minimal < s_small < s_large
    assert s_large <= 100.0


def test_tech_stack_scoring() -> None:
    s_static, _ = calc_tech_stack_score([], [])
    s_spa, _ = calc_tech_stack_score(["react", "nextjs"], [])
    s_polyglot, _ = calc_tech_stack_score(["react"], ["fastapi", "spring", "postgres", "redis"])

    assert s_static < s_spa < s_polyglot
    assert s_polyglot <= 100.0


def test_waf_defense_scoring() -> None:
    s_none, _ = calc_waf_defense_score([])
    assert s_none == 0.0

    s_cdn, _ = calc_waf_defense_score(["cloudfront"])
    s_waf, _ = calc_waf_defense_score(["cloudflare_waf", "aws_waf"])

    assert s_cdn < s_waf
    assert s_waf <= 100.0


def test_data_sensitivity_scoring() -> None:
    s_pub, _ = calc_data_sensitivity_score("public")
    s_std, _ = calc_data_sensitivity_score("standard")
    s_admin, _ = calc_data_sensitivity_score("admin_panel")
    s_crit, _ = calc_data_sensitivity_score("financial")

    assert s_pub < s_std < s_admin < s_crit
    assert s_crit == 95.0


def test_patch_posture_scoring() -> None:
    s_mod, _ = calc_patch_posture_score("modern")
    s_cur, _ = calc_patch_posture_score("current")
    s_unk, _ = calc_patch_posture_score("unknown")
    s_lag, _ = calc_patch_posture_score("patch_lag")
    s_eol, _ = calc_patch_posture_score("legacy")

    assert s_mod < s_cur < s_unk < s_lag < s_eol
    assert s_eol == 95.0
