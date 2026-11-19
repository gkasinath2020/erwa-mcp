"""Thin async HTTP client for the Dney REST API."""

import httpx


class DneyClient:
    """Calls the Dney backend in one of two auth modes.

    - ``DneyClient(base_url, api_key=...)`` sends ``X-Api-Key`` (per-user key).
    - ``DneyClient(base_url, service_token=..., org_id=...)`` sends
      ``X-Service-Token`` + ``X-Org-Id`` (service-to-service, org resolved by
      email via :func:`resolve_org_id`).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        service_token: str | None = None,
        org_id: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        if api_key:
            headers = {"X-Api-Key": api_key}
        elif service_token and org_id:
            headers = {"X-Service-Token": service_token, "X-Org-Id": org_id}
        else:
            raise ValueError(
                "DneyClient requires either api_key or both service_token and org_id"
            )
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=30.0,
        )

    async def check_input(self, text: str) -> dict:
        resp = await self._client.post(
            "/api/v1/guardrails/check",
            json={"input_text": text},
        )
        resp.raise_for_status()
        return resp.json()

    async def check_output(self, text: str) -> dict:
        resp = await self._client.post(
            "/api/v1/guardrails/check",
            json={"output_text": text},
        )
        resp.raise_for_status()
        return resp.json()

    async def check_both(self, input_text: str, output_text: str) -> dict:
        resp = await self._client.post(
            "/api/v1/guardrails/check",
            json={"input_text": input_text, "output_text": output_text},
        )
        resp.raise_for_status()
        return resp.json()

    async def list_guardrails(self) -> list[dict]:
        resp = await self._client.get("/api/v1/guardrails")
        resp.raise_for_status()
        return resp.json()

    async def get_audit_logs(self, limit: int = 20) -> dict:
        resp = await self._client.get(
            "/api/v1/audit",
            params={"size": limit},
        )
        resp.raise_for_status()
        return resp.json()

    async def set_feedback(self, audit_id: str, feedback: str) -> dict:
        """Label one of the caller's own decisions (PATCH /audit/{id}/feedback).

        The backend scopes the lookup to the caller's org and answers 404 for any
        other org's id. Only the label is sent: no text of any kind.
        """
        resp = await self._client.patch(
            f"/api/v1/audit/{audit_id}/feedback",
            json={"feedback": feedback},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_stats(self) -> dict:
        resp = await self._client.get("/api/v1/audit/stats")
        resp.raise_for_status()
        return resp.json()

    async def close(self):
        await self._client.aclose()


async def resolve_org_id(base_url: str, service_token: str, email: str) -> str:
    """Resolve a Dney org id for ``email`` via the internal service endpoint.

    POSTs to ``/api/v1/internal/resolve-org`` with an ``X-Service-Token`` header.
    Raises ``ValueError`` (naming the email) when the backend returns 404, i.e.
    no Dney account is linked to that email.
    """
    base = base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{base}/api/v1/internal/resolve-org",
            headers={"X-Service-Token": service_token},
            json={"email": email},
        )
    if resp.status_code == 404:
        raise ValueError(
            f"No Dney organization is linked to '{email}'. "
            "Link your Dney account to this email to use the guardrails connector."
        )
    resp.raise_for_status()
    return resp.json()["org_id"]
