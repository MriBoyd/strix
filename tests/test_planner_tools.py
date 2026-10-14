"""Tests for planner agent tools."""

from __future__ import annotations

import json

from agents.tool_context import ToolContext

from strix.tools.planner.tools import (
    calculate_target_complexity,
    create_scan_plan,
    list_scan_modules,
)


def _make_ctx(tool_name: str) -> ToolContext:
    return ToolContext(
        context={"agent_id": "test-agent"},
        tool_name=tool_name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )


async def test_calculate_target_complexity_tool() -> None:
    fp_json = json.dumps(
        {
            "open_ports": [443, 8080],
            "auth_patterns": ["jwt"],
            "api_surface": {"endpoints_count": 20},
            "waf_cdn": ["cloudflare"],
        }
    )

    result_raw = await calculate_target_complexity.on_invoke_tool(
        _make_ctx("calculate_target_complexity"),
        json.dumps({"target": "https://test.local", "fingerprint": fp_json}),
    )

    data = json.loads(result_raw)
    assert data["target"] == "https://test.local"
    assert "tci" in data
    assert 0.0 <= data["tci"] <= 100.0
    assert "sub_scores" in data
    assert "breakdown" in data
    assert "level" in data


async def test_create_scan_plan_tool() -> None:
    fp_json = json.dumps(
        {
            "target_type": "api",
            "open_ports": [443],
            "auth_patterns": ["jwt", "oauth2"],
            "api_surface": {"endpoints_count": 40, "api_types": ["rest"]},
            "data_sensitivity": "high",
        }
    )

    result_raw = await create_scan_plan.on_invoke_tool(
        _make_ctx("create_scan_plan"),
        json.dumps(
            {
                "target": "https://api.test.local",
                "fingerprint": fp_json,
                "scan_mode": "quick",
            }
        ),
    )

    data = json.loads(result_raw)
    assert data["target"] == "https://api.test.local"
    assert "tci" in data
    assert "plan" in data
    assert isinstance(data["plan"], list)
    assert len(data["plan"]) > 0

    step1 = data["plan"][0]
    assert "step" in step1
    assert "module" in step1
    assert "priority" in step1
    assert "safe_mode" in step1


async def test_list_scan_modules_tool() -> None:
    result_raw = await list_scan_modules.on_invoke_tool(
        _make_ctx("list_scan_modules"),
        json.dumps({}),
    )

    data = json.loads(result_raw)
    assert isinstance(data, list)
    assert len(data) >= 10

    names = [m["name"] for m in data]
    assert "auth-enum" in names
    assert "id_or" in names
    assert "sqli-fuzz" in names

    # Filtered by category
    filtered_raw = await list_scan_modules.on_invoke_tool(
        _make_ctx("list_scan_modules"),
        json.dumps({"category": "authentication"}),
    )
    filtered = json.loads(filtered_raw)
    for m in filtered:
        assert m["category"] == "authentication"
