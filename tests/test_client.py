"""Tests for DneyClient auth modes and resolve_org_id."""

import pytest
import respx
from httpx import Response

from asgard_mcp.asgard_client import DneyClient, resolve_org_id

BASE = "http://test-asgard:8000"


class TestDneyClientModes:
    @respx.mock
    @pytest.mark.asyncio
    async def test_api_key_mode(self):
        route = respx.get(f"{BASE}/api/v1/guardrails").mock(
            return_value=Response(200, json=[])
        )
        client = DneyClient(base_url=BASE, api_key="asg_123")
        await client.list_guardrails()
        await client.close()
        assert route.calls.last.request.headers["X-Api-Key"] == "asg_123"

    @respx.mock
    @pytest.mark.asyncio
    async def test_service_mode(self):
        route = respx.get(f"{BASE}/api/v1/guardrails").mock(
            return_value=Response(200, json=[])
        )
        client = DneyClient(base_url=BASE, service_token="svc", org_id="org-uuid")
        await client.list_guardrails()
        await client.close()
        req = route.calls.last.request
        assert req.headers["X-Service-Token"] == "svc"
        assert req.headers["X-Org-Id"] == "org-uuid"
        assert "X-Api-Key" not in req.headers

    def test_requires_a_mode(self):
        with pytest.raises(ValueError):
            DneyClient(base_url=BASE)

    def test_service_mode_needs_org(self):
        with pytest.raises(ValueError):
            DneyClient(base_url=BASE, service_token="svc")


class TestResolveOrgId:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self):
        route = respx.post(f"{BASE}/api/v1/internal/resolve-org").mock(
            return_value=Response(
                200, json={"org_id": "org-9", "org_name": "Acme", "email": "a@b.com"}
            )
        )
        org_id = await resolve_org_id(BASE, "svc-token", "a@b.com")
        assert org_id == "org-9"
        req = route.calls.last.request
        assert req.headers["X-Service-Token"] == "svc-token"
        import json as _json

        assert _json.loads(req.content) == {"email": "a@b.com"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_not_found_names_email(self):
        respx.post(f"{BASE}/api/v1/internal/resolve-org").mock(
            return_value=Response(404, json={"detail": "No organization found for email"})
        )
        with pytest.raises(ValueError) as exc:
            await resolve_org_id(BASE, "svc-token", "missing@dney.dev")
        assert "missing@dney.dev" in str(exc.value)

    @respx.mock
    @pytest.mark.asyncio
    async def test_other_error_raises(self):
        respx.post(f"{BASE}/api/v1/internal/resolve-org").mock(
            return_value=Response(401)
        )
        with pytest.raises(Exception):
            await resolve_org_id(BASE, "bad-token", "a@b.com")
