"""SCRUM-552: report_decision lets an agent mark one of its own decisions as wrong.

Pins: the verdict maps to the backend label; the request body is exactly the label
(metadata only, no text); unknown verdicts and non-UUID ids are refused before any
request; another org's id (backend 404) is a clear, caller-safe error; a 5xx does not
leak backend detail.
"""

import json

import pytest
import respx
from httpx import Response

from asgard_mcp.server import report_decision


@pytest.fixture(autouse=True)
def _set_api_url(monkeypatch):
    monkeypatch.setenv("DNEY_API_URL", "http://test-asgard:8000")


API_KEY = "asg_test_key_12345"
AUDIT_ID = "3f2b8c1e-9a4d-4e6b-8c2a-1d5e7f9a0b3c"
FEEDBACK_URL = f"http://test-asgard:8000/api/v1/audit/{AUDIT_ID}/feedback"


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verdict,label", [("false_block", "false_positive"), ("miss", "false_negative")]
)
async def test_verdict_maps_to_label_and_sends_nothing_else(verdict, label):
    route = respx.patch(FEEDBACK_URL).mock(
        return_value=Response(200, json={"id": AUDIT_ID, "feedback": label})
    )
    result = json.loads(
        await report_decision(audit_id=AUDIT_ID, verdict=verdict, api_key=API_KEY)
    )
    assert result == {"audit_id": AUDIT_ID, "verdict": verdict, "recorded": True}
    assert route.call_count == 1
    assert json.loads(route.calls[0].request.content) == {"feedback": label}
    assert route.calls[0].request.headers["x-api-key"] == API_KEY


@respx.mock
@pytest.mark.asyncio
async def test_other_orgs_id_is_a_clear_error():
    respx.patch(FEEDBACK_URL).mock(return_value=Response(404, json={"detail": "nf"}))
    result = json.loads(
        await report_decision(audit_id=AUDIT_ID, verdict="miss", api_key=API_KEY)
    )
    assert result == {"error": "No decision with that audit_id in your organization."}


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "verdict", ["correct", "false_positive", "", "MISS", "miss; drop"]
)
async def test_unknown_verdict_refused_before_any_call(verdict):
    route = respx.route().mock(return_value=Response(200))
    result = json.loads(
        await report_decision(audit_id=AUDIT_ID, verdict=verdict, api_key=API_KEY)
    )
    assert "error" in result
    assert route.call_count == 0


@respx.mock
@pytest.mark.asyncio
@pytest.mark.parametrize("bad_id", ["not-a-uuid", "../guardrails", "", f"{AUDIT_ID}/x"])
async def test_non_uuid_id_refused_before_any_call(bad_id):
    route = respx.route().mock(return_value=Response(200))
    result = json.loads(
        await report_decision(audit_id=bad_id, verdict="miss", api_key=API_KEY)
    )
    assert "error" in result
    assert route.call_count == 0


@respx.mock
@pytest.mark.asyncio
async def test_server_error_is_generic():
    respx.patch(FEEDBACK_URL).mock(
        return_value=Response(500, text="internal host db-1")
    )
    result = json.loads(
        await report_decision(audit_id=AUDIT_ID, verdict="miss", api_key=API_KEY)
    )
    assert "error" in result
    assert "db-1" not in result["error"]


@pytest.mark.asyncio
async def test_missing_key(monkeypatch):
    monkeypatch.delenv("DNEY_API_KEY", raising=False)
    result = json.loads(await report_decision(audit_id=AUDIT_ID, verdict="miss"))
    assert "error" in result
