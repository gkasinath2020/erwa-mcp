"""Tests for the OAuth/service-mode layer of the MCP server."""

import json
import types

import pytest
import respx
from httpx import Response
from starlette.requests import Request

from asgard_mcp import auth0, server
from asgard_mcp.auth0 import Auth0Config, Auth0Verifier
from asgard_mcp.server import PathKeyASGIApp, check_content

from ._keys import (
    AUDIENCE,
    EMAIL_CLAIM,
    ISSUER,
    FakeJWKClient,
    jwks_for,
    make_token,
)

BASE = "http://test-asgard:8000"


def _make_ctx(headers: dict[str, str]):
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "query_string": b"",
        "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
    }
    return types.SimpleNamespace(
        request_context=types.SimpleNamespace(request=Request(scope))
    )


async def _drive_http(app, scope):
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def _headers_dict(sent):
    return {k.decode().lower(): v.decode() for k, v in sent[0]["headers"]}


@pytest.fixture
def enable_oauth(monkeypatch):
    monkeypatch.setenv("AUTH0_ISSUER", ISSUER)
    monkeypatch.setenv("MCP_AUDIENCE", AUDIENCE)
    monkeypatch.delenv("MCP_PUBLIC_URL", raising=False)
    verifier = Auth0Verifier(
        config=Auth0Config(issuer=ISSUER, audience=AUDIENCE, email_claim=EMAIL_CLAIM),
        jwk_client=FakeJWKClient(jwks_for()),
    )
    auth0.set_verifier(verifier)
    yield
    auth0.set_verifier(None)


async def _capturing_inner(captured):
    async def inner(scope, receive, send):
        captured["scope"] = scope
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"inner"})

    return inner


class TestOAuthMetadata:
    @pytest.mark.asyncio
    async def test_metadata_json(self, enable_oauth):
        app = PathKeyASGIApp(_unreachable_inner)
        sent = await _drive_http(
            app, {"type": "http", "path": "/.well-known/oauth-protected-resource", "headers": []}
        )
        assert sent[0]["status"] == 200
        assert _headers_dict(sent)["content-type"] == "application/json"
        body = json.loads(sent[1]["body"])
        assert body == {
            "resource": AUDIENCE,
            "authorization_servers": [ISSUER],
            "bearer_methods_supported": ["header"],
        }

    @pytest.mark.asyncio
    async def test_metadata_not_served_when_disabled(self, monkeypatch):
        monkeypatch.delenv("AUTH0_ISSUER", raising=False)
        monkeypatch.delenv("MCP_AUDIENCE", raising=False)
        captured = {}
        app = PathKeyASGIApp(await _capturing_inner(captured))
        await _drive_http(
            app,
            {"type": "http", "path": "/.well-known/oauth-protected-resource", "headers": []},
        )
        assert captured["scope"]["path"] == "/.well-known/oauth-protected-resource"


class TestChallenge:
    @pytest.mark.asyncio
    async def test_401_with_www_authenticate(self, enable_oauth):
        app = PathKeyASGIApp(_unreachable_inner)
        sent = await _drive_http(app, {"type": "http", "path": "/mcp", "headers": []})
        assert sent[0]["status"] == 401
        hdrs = _headers_dict(sent)
        assert hdrs["www-authenticate"] == (
            'Bearer resource_metadata='
            '"https://mcp.dney.dev/.well-known/oauth-protected-resource"'
        )
        body = json.loads(sent[1]["body"])
        assert body["error"] == "unauthorized"
        assert "error_description" in body

    @pytest.mark.asyncio
    async def test_401_on_invalid_bearer(self, enable_oauth):
        app = PathKeyASGIApp(_unreachable_inner)
        sent = await _drive_http(
            app,
            {
                "type": "http",
                "path": "/mcp",
                "headers": [(b"authorization", b"Bearer not-a-real-token")],
            },
        )
        assert sent[0]["status"] == 401


class TestBearerInjection:
    @pytest.mark.asyncio
    async def test_valid_bearer_injects_and_strips(self, enable_oauth):
        captured = {}
        app = PathKeyASGIApp(await _capturing_inner(captured))
        token = make_token(email="carol@dney.dev")
        await _drive_http(
            app,
            {
                "type": "http",
                "path": "/mcp",
                "headers": [
                    (b"authorization", f"Bearer {token}".encode()),
                    (b"x-dney-email", b"attacker@evil.com"),  # must be stripped
                ],
            },
        )
        hdrs = captured["scope"]["headers"]
        emails = [v for k, v in hdrs if k == b"x-dney-email"]
        assert emails == [b"carol@dney.dev"]

    @pytest.mark.asyncio
    async def test_header_key_passthrough_strips_email(self, enable_oauth):
        captured = {}
        app = PathKeyASGIApp(await _capturing_inner(captured))
        await _drive_http(
            app,
            {
                "type": "http",
                "path": "/mcp",
                "headers": [
                    (b"x-dney-key", b"asg_key"),
                    (b"x-dney-email", b"attacker@evil.com"),
                ],
            },
        )
        hdrs = dict(captured["scope"]["headers"])
        assert hdrs[b"x-dney-key"] == b"asg_key"
        assert b"x-dney-email" not in hdrs

    @pytest.mark.asyncio
    async def test_path_key_works_under_oauth(self, enable_oauth):
        captured = {}
        app = PathKeyASGIApp(await _capturing_inner(captured))
        await _drive_http(
            app, {"type": "http", "path": "/asg_secret/mcp", "headers": []}
        )
        assert captured["scope"]["path"] == "/mcp"
        assert dict(captured["scope"]["headers"])[b"x-dney-key"] == b"asg_secret"


class TestOAuthDisabled:
    @pytest.mark.asyncio
    async def test_keyless_passes_through_legacy(self, monkeypatch):
        monkeypatch.delenv("AUTH0_ISSUER", raising=False)
        monkeypatch.delenv("MCP_AUDIENCE", raising=False)
        captured = {}
        app = PathKeyASGIApp(await _capturing_inner(captured))
        await _drive_http(
            app,
            {
                "type": "http",
                "path": "/mcp",
                "headers": [(b"x-dney-email", b"attacker@evil.com")],
            },
        )
        # Reached inner (no challenge) and the client-supplied email was stripped.
        assert "scope" in captured
        assert b"x-dney-email" not in dict(captured["scope"]["headers"])


class TestServiceModeClient:
    @respx.mock
    @pytest.mark.asyncio
    async def test_check_content_service_mode(self, monkeypatch):
        monkeypatch.setenv("DNEY_API_URL", BASE)
        monkeypatch.setenv("MCP_SERVICE_TOKEN", "svc-secret")
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        resolve = respx.post(f"{BASE}/api/v1/internal/resolve-org").mock(
            return_value=Response(200, json={"org_id": "org-42", "org_name": "Acme", "email": "d@e.com"})
        )
        check = respx.post(f"{BASE}/api/v1/guardrails/check").mock(
            return_value=Response(200, json={"action_taken": "allowed"})
        )
        ctx = _make_ctx({"x-dney-email": "d@e.com"})
        result = json.loads(await check_content("hi", ctx=ctx))
        assert result["action_taken"] == "allowed"
        assert resolve.called
        assert check.calls.last.request.headers["X-Service-Token"] == "svc-secret"
        assert check.calls.last.request.headers["X-Org-Id"] == "org-42"

    @respx.mock
    @pytest.mark.asyncio
    async def test_resolve_404_returns_error_naming_email(self, monkeypatch):
        monkeypatch.setenv("DNEY_API_URL", BASE)
        monkeypatch.setenv("MCP_SERVICE_TOKEN", "svc-secret")
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        respx.post(f"{BASE}/api/v1/internal/resolve-org").mock(
            return_value=Response(404, json={"detail": "No organization found for email"})
        )
        ctx = _make_ctx({"x-dney-email": "nobody@dney.dev"})
        result = json.loads(await check_content("hi", ctx=ctx))
        assert "nobody@dney.dev" in result["error"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_api_key_priority_over_email(self, monkeypatch):
        monkeypatch.setenv("DNEY_API_URL", BASE)
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        check = respx.post(f"{BASE}/api/v1/guardrails/check").mock(
            return_value=Response(200, json={"action_taken": "allowed"})
        )
        ctx = _make_ctx({"x-dney-key": "asg_key", "x-dney-email": "d@e.com"})
        await check_content("hi", ctx=ctx)
        assert check.calls.last.request.headers["X-Api-Key"] == "asg_key"

    @pytest.mark.asyncio
    async def test_no_key_no_email_errors(self, monkeypatch):
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        ctx = _make_ctx({})
        result = json.loads(await check_content("hi", ctx=ctx))
        assert "error" in result

    @respx.mock
    @pytest.mark.asyncio
    async def test_backend_error_is_genericized(self, monkeypatch):
        # A non-ValueError (httpx HTTPStatusError embeds the backend URL) must
        # NOT leak internal detail; the caller gets a generic message (L4).
        monkeypatch.setenv("DNEY_API_URL", BASE)
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        respx.post(f"{BASE}/api/v1/guardrails/check").mock(
            return_value=Response(500, json={"detail": "boom"})
        )
        ctx = _make_ctx({"x-dney-key": "asg_key"})
        result = json.loads(await check_content("hi", ctx=ctx))
        assert result["error"] == server._GENERIC_TOOL_ERROR
        assert BASE not in result["error"]
        assert "500" not in result["error"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_resolve_500_is_genericized(self, monkeypatch):
        # resolve-org failures other than 404 also must not leak the URL.
        monkeypatch.setenv("DNEY_API_URL", BASE)
        monkeypatch.setenv("MCP_SERVICE_TOKEN", "svc-secret")
        monkeypatch.delenv("DNEY_API_KEY", raising=False)
        respx.post(f"{BASE}/api/v1/internal/resolve-org").mock(
            return_value=Response(503, json={"detail": "down"})
        )
        ctx = _make_ctx({"x-dney-email": "d@e.com"})
        result = json.loads(await check_content("hi", ctx=ctx))
        assert result["error"] == server._GENERIC_TOOL_ERROR
        assert BASE not in result["error"]

    @pytest.mark.asyncio
    async def test_email_from_request_none(self):
        assert server._email_from_request(None) == ""


async def _unreachable_inner(scope, receive, send):  # pragma: no cover
    raise AssertionError("inner app should not be called")
