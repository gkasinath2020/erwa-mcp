"""Tests for the Asgard MCP server tools."""

import json
import types

import pytest
import respx
from httpx import Response
from starlette.requests import Request

from asgard_mcp import server
from asgard_mcp.server import (
    PathKeyASGIApp,
    check_content,
    check_input_output,
    extract_path_key,
    guardrail_stats,
    list_guardrails,
    recent_activity,
)


def _make_ctx(headers: dict[str, str]):
    """Build a fake FastMCP Context whose request carries the given headers."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "query_string": b"",
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
    }
    request = Request(scope)
    return types.SimpleNamespace(
        request_context=types.SimpleNamespace(request=request)
    )


async def _drive_http(app, scope):
    """Invoke an ASGI app for one HTTP request and capture the sent messages."""
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


@pytest.fixture(autouse=True)
def _set_api_url(monkeypatch):
    monkeypatch.setenv("DNEY_API_URL", "http://test-asgard:8000")


API_KEY = "asg_test_key_12345"


class TestCheckContent:
    @respx.mock
    @pytest.mark.asyncio
    async def test_missing_api_key(self):
        result = json.loads(await check_content("hello"))
        assert "error" in result
        assert "api_key" in result["error"].lower() or "DNEY_API_KEY" in result["error"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_input_check(self):
        respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(200, json={
                "action_taken": "allowed",
                "input_result": {"action": "allowed", "text": "hello"},
                "rails_triggered": [],
                "latency_ms": 1.5,
            })
        )
        result = json.loads(await check_content("hello", api_key=API_KEY))
        assert result["action_taken"] == "allowed"

    @respx.mock
    @pytest.mark.asyncio
    async def test_output_check(self):
        respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(200, json={
                "action_taken": "blocked",
                "output_result": {"action": "blocked"},
                "rails_triggered": ["toxicity"],
                "latency_ms": 5.0,
            })
        )
        result = json.loads(await check_content("bad text", direction="output", api_key=API_KEY))
        assert result["action_taken"] == "blocked"

    @respx.mock
    @pytest.mark.asyncio
    async def test_api_error(self):
        respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(500)
        )
        result = json.loads(await check_content("hello", api_key=API_KEY))
        assert "error" in result


class TestCheckInputOutput:
    @respx.mock
    @pytest.mark.asyncio
    async def test_both(self):
        respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(200, json={
                "action_taken": "allowed",
                "input_result": {"action": "allowed"},
                "output_result": {"action": "allowed"},
                "rails_triggered": [],
                "latency_ms": 2.0,
            })
        )
        result = json.loads(await check_input_output("hi", "hello!", api_key=API_KEY))
        assert result["action_taken"] == "allowed"


class TestListGuardrails:
    @respx.mock
    @pytest.mark.asyncio
    async def test_list(self):
        respx.get("http://test-asgard:8000/api/v1/guardrails").mock(
            return_value=Response(200, json=[
                {
                    "name": "PII Filter",
                    "mode": "enforce",
                    "category": "privacy",
                    "rules": [{"id": "1"}, {"id": "2"}],
                    "description": "Blocks PII",
                },
            ])
        )
        result = json.loads(await list_guardrails(api_key=API_KEY))
        assert len(result) == 1
        assert result[0]["name"] == "PII Filter"
        assert result[0]["rule_count"] == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_surfaces_per_rule_actions(self):
        respx.get("http://test-asgard:8000/api/v1/guardrails").mock(
            return_value=Response(200, json=[
                {
                    "name": "PII Filter",
                    "mode": "enforce",
                    "category": "privacy",
                    "rules": [
                        {
                            "name": "Credit Card",
                            "rule_type": "builtin_action",
                            "config": {"action": "block"},
                        },
                        {
                            "name": "SSN",
                            "rule_type": "builtin_action",
                            "config": {"action": "mask"},
                        },
                    ],
                    "description": "Blocks/masks PII",
                },
            ])
        )
        result = json.loads(await list_guardrails(api_key=API_KEY))
        rules = result[0]["rules"]
        assert result[0]["rule_count"] == 2
        assert rules[0] == {
            "name": "Credit Card",
            "type": "builtin_action",
            "action": "block",
        }
        assert rules[1] == {
            "name": "SSN",
            "type": "builtin_action",
            "action": "mask",
        }

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_handles_missing_config_gracefully(self):
        respx.get("http://test-asgard:8000/api/v1/guardrails").mock(
            return_value=Response(200, json=[
                {
                    "name": "Sparse",
                    "mode": "monitor",
                    "category": "safety",
                    "rules": [
                        {"name": "No Config", "rule_type": "pattern_match"},
                        {"name": "Null Config", "rule_type": "pattern_match", "config": None},
                        {"name": "No Action", "rule_type": "pattern_match", "config": {}},
                    ],
                    "description": None,
                },
            ])
        )
        result = json.loads(await list_guardrails(api_key=API_KEY))
        rules = result[0]["rules"]
        assert result[0]["rule_count"] == 3
        assert all(r["action"] == "n/a" for r in rules)
        assert rules[0]["name"] == "No Config"


class TestGuardrailStats:
    @respx.mock
    @pytest.mark.asyncio
    async def test_stats(self):
        respx.get("http://test-asgard:8000/api/v1/audit/stats").mock(
            return_value=Response(200, json={"total": 100, "blocked": 5})
        )
        result = json.loads(await guardrail_stats(api_key=API_KEY))
        assert result["total"] == 100


class TestRecentActivity:
    @respx.mock
    @pytest.mark.asyncio
    async def test_activity(self):
        respx.get("http://test-asgard:8000/api/v1/audit").mock(
            return_value=Response(200, json={"items": [], "total": 0})
        )
        result = json.loads(await recent_activity(api_key=API_KEY))
        assert result["total"] == 0


class TestToolErrorPaths:
    """Cover the missing-key and API-error branches of every tool."""

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_content_both_direction(self):
        respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(200, json={"action_taken": "allowed"})
        )
        result = json.loads(await check_content("hi", direction="both", api_key=API_KEY))
        assert result["action_taken"] == "allowed"

    @pytest.mark.asyncio
    async def test_check_input_output_missing_key(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        result = json.loads(await check_input_output("hi", "yo"))
        assert "error" in result

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_input_output_api_error(self):
        respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(500)
        )
        result = json.loads(await check_input_output("hi", "yo", api_key=API_KEY))
        assert "error" in result

    @pytest.mark.asyncio
    async def test_list_guardrails_missing_key(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        assert "error" in json.loads(await list_guardrails())

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_guardrails_api_error(self):
        respx.get("http://test-asgard:8000/api/v1/guardrails").mock(
            return_value=Response(500)
        )
        assert "error" in json.loads(await list_guardrails(api_key=API_KEY))

    @pytest.mark.asyncio
    async def test_stats_missing_key(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        assert "error" in json.loads(await guardrail_stats())

    @respx.mock
    @pytest.mark.asyncio
    async def test_stats_api_error(self):
        respx.get("http://test-asgard:8000/api/v1/audit/stats").mock(
            return_value=Response(500)
        )
        assert "error" in json.loads(await guardrail_stats(api_key=API_KEY))

    @pytest.mark.asyncio
    async def test_recent_activity_missing_key(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        assert "error" in json.loads(await recent_activity())

    @respx.mock
    @pytest.mark.asyncio
    async def test_recent_activity_api_error(self):
        respx.get("http://test-asgard:8000/api/v1/audit").mock(
            return_value=Response(500)
        )
        assert "error" in json.loads(await recent_activity(api_key=API_KEY))


class TestExtractPathKey:
    def test_key_and_mcp(self):
        assert extract_path_key("/asg_abc123/mcp") == ("asg_abc123", "/mcp")

    def test_bare_mcp_has_no_key(self):
        assert extract_path_key("/mcp") == ("", "/mcp")

    def test_trailing_slash_variant(self):
        # "/mcp/" collapses to a single segment -> treated as bare mcp
        assert extract_path_key("/mcp/") == ("", "/mcp/")

    def test_unrelated_path_untouched(self):
        assert extract_path_key("/health") == ("", "/health")


class TestKeyResolution:
    @pytest.mark.asyncio
    async def test_explicit_arg_wins(self, monkeypatch):
        monkeypatch.setenv("DNEY_API_KEY", "env_key")
        ctx = _make_ctx({"x-dney-key": "hdr_key"})
        assert server._resolve_key(ctx, "arg_key") == "arg_key"

    @pytest.mark.asyncio
    async def test_header_x_dney_key(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        ctx = _make_ctx({"x-dney-key": "hdr_key"})
        assert server._resolve_key(ctx, "") == "hdr_key"

    @pytest.mark.asyncio
    async def test_header_x_api_key_fallback(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        ctx = _make_ctx({"x-api-key": "legacy_key"})
        assert server._resolve_key(ctx, "") == "legacy_key"

    @pytest.mark.asyncio
    async def test_env_var_fallback(self, monkeypatch):
        monkeypatch.setenv("DNEY_API_KEY", "env_key")
        ctx = _make_ctx({})
        assert server._resolve_key(ctx, "") == "env_key"

    @pytest.mark.asyncio
    async def test_no_key_anywhere(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        assert server._resolve_key(None, "") == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_check_content_uses_header_key(self, monkeypatch):
        # No explicit api_key, no env var — key comes from the request header.
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        route = respx.post("http://test-asgard:8000/api/v1/guardrails/check").mock(
            return_value=Response(200, json={"action_taken": "allowed"})
        )
        ctx = _make_ctx({"x-dney-key": API_KEY})
        result = json.loads(await check_content("hi", ctx=ctx))
        assert result["action_taken"] == "allowed"
        assert route.calls.last.request.headers["X-Api-Key"] == API_KEY


class TestPathKeyASGIApp:
    @pytest.mark.asyncio
    async def test_health_short_circuits(self):
        app = PathKeyASGIApp(_unreachable_inner)
        sent = await _drive_http(app, {"type": "http", "path": "/health", "headers": []})
        assert sent[0]["status"] == 200
        assert b'"ok"' in sent[1]["body"]

    @pytest.mark.asyncio
    async def test_path_key_injected_and_rewritten(self):
        captured = {}

        async def inner(scope, receive, send):
            captured["scope"] = scope
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        app = PathKeyASGIApp(inner)
        await _drive_http(
            app,
            {
                "type": "http",
                "path": "/asg_secret/mcp",
                "headers": [(b"host", b"mcp.dney.dev"), (b"x-dney-key", b"old")],
            },
        )
        assert captured["scope"]["path"] == "/mcp"
        hdrs = dict(captured["scope"]["headers"])
        # Client-sent key header replaced with the path-derived one.
        assert hdrs[b"x-dney-key"] == b"asg_secret"
        assert sum(1 for k, _ in captured["scope"]["headers"] if k == b"x-dney-key") == 1

    @pytest.mark.asyncio
    async def test_lifespan_passed_through(self):
        seen = {}

        async def inner(scope, receive, send):
            seen["type"] = scope["type"]

        app = PathKeyASGIApp(inner)
        await app({"type": "lifespan"}, None, None)
        assert seen["type"] == "lifespan"


async def _unreachable_inner(scope, receive, send):  # pragma: no cover
    raise AssertionError("inner app should not be called for /health")


def test_main_invokes_uvicorn(monkeypatch):
    calls = {}

    def fake_run(app, host, port, timeout_keep_alive):
        calls["host"] = host
        calls["port"] = port
        calls["keep_alive"] = timeout_keep_alive

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("MCP_PORT", "3999")
    server.main()
    assert calls["port"] == 3999
    assert calls["keep_alive"] > 300  # outlasts the ALB idle timeout


# --- SCRUM-374 (Assay C4): a 429 names the limit ------------------------------------


def _status_error(code, body, headers=None):
    import httpx

    req = httpx.Request("POST", "https://internal-alb.example/api/v1/guardrails/check")
    resp = httpx.Response(code, json=body, headers=headers or {}, request=req)
    return httpx.HTTPStatusError("x", request=req, response=resp)


def test_a_429_from_dney_names_the_limit_and_when_it_resets():
    import json

    from asgard_mcp import server

    msg = "This key has reached its daily guardrail spend limit. It resets at 00:00 UTC."
    err = _status_error(429, {"detail": msg}, {"Retry-After": "3600"})
    out = json.loads(server._tool_error(err))
    assert out == {"error": msg, "limit": True, "retry_after_seconds": 3600}


def test_other_status_errors_stay_generic_and_never_leak_the_url():
    import json

    from asgard_mcp import server

    cases = [(500, {"detail": "boom"}), (429, {"detail": {"n": 1}}), (429, {"detail": "x" * 301})]
    for code, body in cases:
        out = server._tool_error(_status_error(code, body))
        assert json.loads(out) == {"error": server._GENERIC_TOOL_ERROR}
        assert "internal-alb" not in out
