"""Dney Guardrails MCP Server.

Exposes Dney's guardrail engine as MCP tools for Claude Desktop,
Claude.ai, and Claude Code.

Multi-tenant auth: each user's Dney API key is supplied per request. The
first-class, recommended connection methods are:

  * **OAuth Bearer** — a keyless ``/mcp`` request with
    ``Authorization: Bearer <Auth0 access token>`` (enabled when Auth0 is
    configured). The secret never appears in the URL.
  * **Header key** — ``x-dney-key`` (or legacy ``x-api-key``), or the
    ``DNEY_API_KEY`` env var for single-user/local use.

DEPRECATED — path-key form (avoid; use only when unavoidable):

    https://mcp.dney.dev/<your-asg_key>/mcp

Because some connector UIs (e.g. Claude Desktop's) accept only a URL and no
custom headers, the key may be carried as the first URL *path* segment. This is
a security risk: unlike a header or Bearer token, a path segment is written into
ALB/CloudFront/proxy access logs, APM traces, and browser history — i.e. the API
key leaks into logs. Prefer OAuth or the header key wherever the client allows
it. Path keys should be treated as low-privilege and rotated readily, and never
pasted into referrer-leaking contexts. (Log redaction for this path is handled
at the infra layer.)

The ``PathKeyASGIApp`` wrapper strips the leading ``<key>`` segment, injects it
as an ``x-dney-key`` header, and rewrites the path to ``/mcp`` so the FastMCP
app matches. Tools then read the key from the incoming request.
"""

import json
import logging
import os
import uuid

import httpx
from mcp.server.fastmcp import Context, FastMCP
from starlette.requests import Request

from asgard_mcp import auth0
from asgard_mcp.asgard_client import DneyClient, resolve_org_id

# Headers the injected/native key may arrive under (checked in order).
_KEY_HEADERS = ("x-dney-key", "x-api-key")
# Header carrying a *verified* end-user email (service-mode auth). Only ever set
# by this server after a successful Bearer-JWT verification; any client-supplied
# value is stripped at the ASGI boundary to prevent impersonation.
_EMAIL_HEADER = "x-dney-email"
# OAuth 2.0 Protected Resource Metadata (RFC 9728) discovery path.
OAUTH_METADATA_PATH = "/.well-known/oauth-protected-resource"

logger = logging.getLogger(__name__)

# Generic message returned for unexpected tool failures. We never surface the
# raw exception text to the caller because httpx transport/status errors embed
# internal details (the backend URL, resolved hostnames) that must not leak.
_GENERIC_TOOL_ERROR = (
    "The Dney guardrails service is temporarily unavailable. Please try again."
)


#: The longest 429 detail passed through; ours are one sentence (daily caps,
#: SCRUM-558; the per-key spend budget, SCRUM-374; the per-minute rate limit).
_MAX_LIMIT_DETAIL = 300


def _limit_detail(exc: Exception) -> dict | None:
    """SCRUM-374 (Assay C4): a 429 from the Dney service is a LIMIT, not an outage.
    Its ``detail`` is the service's own one-sentence message (no URL, no host), so
    it reaches the agent as-is with ``retry_after_seconds`` instead of "temporarily
    unavailable". Anything else, or a detail that is not a short string, is None."""
    if not isinstance(exc, httpx.HTTPStatusError) or exc.response.status_code != 429:
        return None
    try:
        detail = exc.response.json().get("detail")
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(detail, str) or not detail or len(detail) > _MAX_LIMIT_DETAIL:
        return None
    out: dict = {"error": detail, "limit": True}
    retry = exc.response.headers.get("Retry-After")
    if retry and retry.isdigit():
        out["retry_after_seconds"] = int(retry)
    return out


def _tool_error(exc: Exception) -> str:
    """Serialize a tool error, surfacing only caller-safe messages.

    Our own ``ValueError``s carry intentional, caller-safe guidance (e.g. the
    'link your Dney account' message, which reveals only the caller's own
    email, or 'no API key provided'). Any other exception may embed internal
    infrastructure detail, so it is logged server-side and replaced with a
    generic message.
    """
    if isinstance(exc, ValueError):
        return json.dumps({"error": str(exc)})
    limited = _limit_detail(exc)
    if limited is not None:
        return json.dumps(limited)
    logger.warning("Dney MCP tool error", exc_info=exc)
    return json.dumps({"error": _GENERIC_TOOL_ERROR})

mcp = FastMCP(
    "Dney Guardrails",
    instructions=(
        "You MUST call the check_content tool on EVERY user message before "
        "composing your response. If the check returns action='blocked', "
        "relay the guardrail message to the user instead of answering. "
        "If action='modified', use the modified text as the user's message. "
        "After composing your response, call check_content with direction='output' "
        "on your response text. If blocked, tell the user your response was "
        "filtered by a guardrail policy. If modified, send the modified version."
    ),
    host=os.environ.get("MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("MCP_PORT", "3001")),
    stateless_http=True,
    json_response=True,
)


def _key_from_request(request: Request | None) -> str:
    """Extract a Dney API key from the incoming HTTP request headers."""
    if request is None:
        return ""
    for header in _KEY_HEADERS:
        value = request.headers.get(header)
        if value:
            return value
    return ""


def _resolve_key(ctx: Context | None, api_key: str) -> str:
    """Resolve the Dney API key: explicit arg > request header > env var."""
    if api_key:
        return api_key
    request = ctx.request_context.request if ctx is not None else None
    key = _key_from_request(request)
    if key:
        return key
    return os.environ.get("DNEY_API_KEY", "")


def _email_from_request(request: Request | None) -> str:
    """Return the verified end-user email injected by the OAuth layer, if any."""
    if request is None:
        return ""
    return request.headers.get(_EMAIL_HEADER, "")


async def _get_client(ctx: Context | None, api_key: str) -> DneyClient:
    """Resolve a Dney client: api-key mode first, then service-mode by email.

    api-key mode (explicit arg / ``x-dney-key`` / ``x-api-key`` / ``DNEY_API_KEY``)
    takes priority. Otherwise, if a verified ``x-dney-email`` header is present,
    the org is resolved via the internal service endpoint and a service-mode
    client is returned. Raises ``ValueError`` when neither is available (or when
    the email has no linked Dney org).
    """
    base_url = os.environ.get("DNEY_API_URL", "http://localhost:8000")
    key = _resolve_key(ctx, api_key)
    if key:
        return DneyClient(base_url=base_url, api_key=key)

    request = ctx.request_context.request if ctx is not None else None
    email = _email_from_request(request)
    if email:
        service_token = os.environ.get("MCP_SERVICE_TOKEN", "")
        org_id = await resolve_org_id(base_url, service_token, email)
        return DneyClient(base_url=base_url, service_token=service_token, org_id=org_id)

    raise ValueError(
        "No API key provided. Authenticate with OAuth, send an x-dney-key "
        "(or x-api-key) header, pass api_key, or set the DNEY_API_KEY env var. "
        "As a last resort connect via https://mcp.dney.dev/<your-key>/mcp "
        "(deprecated: the key leaks into request logs)."
    )


@mcp.tool()
async def check_content(
    text: str,
    direction: str = "input",
    api_key: str = "",
    ctx: Context | None = None,
) -> str:
    """Check text against your organization's active guardrails.

    IMPORTANT: You must call this tool on every user message (direction="input")
    before responding, and on your response (direction="output") before sending.

    Args:
        text: The text to check (a user message, LLM response, etc.)
        direction: "input" for user messages, "output" for AI responses, "both" for both
        api_key: Your Dney API key (optional if supplied via the connector URL/header)

    Returns:
        JSON with action (allowed/blocked/modified), triggered rails, text, and
        audit_id: pass that id to report_decision if this decision was wrong.
    """
    try:
        client = await _get_client(ctx, api_key)
    except Exception as e:
        return _tool_error(e)

    try:
        if direction == "output":
            result = await client.check_output(text)
        elif direction == "both":
            result = await client.check_both(text, text)
        else:
            result = await client.check_input(text)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _tool_error(e)
    finally:
        await client.close()


@mcp.tool()
async def check_input_output(
    input_text: str,
    output_text: str,
    api_key: str = "",
    ctx: Context | None = None,
) -> str:
    """Check both a user's input and the AI's output against guardrails.

    Useful for validating a complete exchange — e.g., before sending
    an AI response to the user.

    Args:
        input_text: The user's message / prompt
        output_text: The AI's response
        api_key: Your Dney API key (optional if supplied via the connector URL/header)
    """
    try:
        client = await _get_client(ctx, api_key)
    except Exception as e:
        return _tool_error(e)

    try:
        result = await client.check_both(input_text, output_text)
        return json.dumps(result, indent=2)
    except Exception as e:
        return _tool_error(e)
    finally:
        await client.close()


@mcp.tool()
async def list_guardrails(api_key: str = "", ctx: Context | None = None) -> str:
    """List all guardrails configured for your organization.

    Shows each guardrail's name, mode (enforce/monitor/disabled),
    category, and number of rules. Each guardrail also includes a
    per-rule breakdown surfacing every rule's name, type, and effective
    action (e.g. "mask"/"block"/"allow"), so you can see, for example,
    that credit-card data is blocked while SSNs are masked.

    Args:
        api_key: Your Dney API key (optional if supplied via the connector URL/header)
    """
    try:
        client = await _get_client(ctx, api_key)
    except Exception as e:
        return _tool_error(e)

    try:
        guardrails = await client.list_guardrails()
        summary = []
        for g in guardrails:
            rules = g.get("rules", []) or []
            rule_details = []
            for r in rules:
                config = r.get("config") or {}
                rule_details.append({
                    "name": r.get("name"),
                    "type": r.get("rule_type"),
                    "action": config.get("action", "n/a"),
                })
            summary.append({
                "name": g["name"],
                "mode": g["mode"],
                "category": g["category"],
                "rule_count": len(rules),
                "rules": rule_details,
                "description": g.get("description"),
            })
        return json.dumps(summary, indent=2)
    except Exception as e:
        return _tool_error(e)
    finally:
        await client.close()


@mcp.tool()
async def guardrail_stats(api_key: str = "", ctx: Context | None = None) -> str:
    """Get a summary of your guardrail activity — total requests, blocks,
    modifications, and average latency.

    Args:
        api_key: Your Dney API key (optional if supplied via the connector URL/header)
    """
    try:
        client = await _get_client(ctx, api_key)
    except Exception as e:
        return _tool_error(e)

    try:
        stats = await client.get_stats()
        return json.dumps(stats, indent=2)
    except Exception as e:
        return _tool_error(e)
    finally:
        await client.close()


@mcp.tool()
async def recent_activity(
    limit: int = 10,
    api_key: str = "",
    ctx: Context | None = None,
) -> str:
    """Get recent guardrail activity logs — what was checked, what triggered,
    what action was taken.

    Args:
        limit: Number of recent entries to return (default 10, max 50)
        api_key: Your Dney API key (optional if supplied via the connector URL/header)
    """
    try:
        client = await _get_client(ctx, api_key)
    except Exception as e:
        return _tool_error(e)

    try:
        logs = await client.get_audit_logs(min(limit, 50))
        return json.dumps(logs, indent=2)
    except Exception as e:
        return _tool_error(e)
    finally:
        await client.close()


# SCRUM-552: the agent-facing verdicts and the backend feedback labels they set.
# A fixed list on purpose: report_decision takes no free text, so a report can
# never carry the prompt or response it is about (Dney stores no raw text).
REPORT_VERDICTS = {"false_block": "false_positive", "miss": "false_negative"}


@mcp.tool()
async def report_decision(
    audit_id: str,
    verdict: str,
    api_key: str = "",
    ctx: Context | None = None,
) -> str:
    """Report that one of your Dney decisions was wrong.

    Use the audit_id returned by check_content (or listed by recent_activity).
    Only your own organization's decisions can be reported. The report carries
    no text: just the id and the verdict.

    Args:
        audit_id: The decision's audit_id
        verdict: "false_block" (blocked or changed something it should have
            allowed) or "miss" (allowed something it should have stopped)
        api_key: Your Dney API key (optional if supplied via the connector URL/header)
    """
    label = REPORT_VERDICTS.get(verdict)
    if label is None:
        return json.dumps({"error": 'verdict must be "false_block" or "miss".'})
    try:
        audit_uuid = str(uuid.UUID(audit_id))
    except (ValueError, AttributeError, TypeError):
        return json.dumps(
            {"error": "audit_id must be the UUID returned by check_content."}
        )

    try:
        client = await _get_client(ctx, api_key)
    except Exception as e:
        return _tool_error(e)

    try:
        await client.set_feedback(audit_uuid, label)
        return json.dumps(
            {"audit_id": audit_uuid, "verdict": verdict, "recorded": True}
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return json.dumps(
                {"error": "No decision with that audit_id in your organization."}
            )
        return _tool_error(e)
    except Exception as e:
        return _tool_error(e)
    finally:
        await client.close()


def extract_path_key(path: str) -> tuple[str, str]:
    """Split a request path of the form ``/<key>/mcp`` into (key, "/mcp").

    Returns ("", path) unchanged when there is no leading key segment
    (e.g. the bare ``/mcp`` path or a trailing-slash variant).
    """
    segments = [s for s in path.split("/") if s]
    mcp_path = mcp.settings.streamable_http_path  # "/mcp"
    suffix = mcp_path.strip("/")
    if len(segments) >= 2 and segments[-1] == suffix:
        # Everything before the final "mcp" segment is the key.
        return segments[0], mcp_path
    return "", path


def _strip_headers(headers, names) -> list:
    """Return ``headers`` (list of (bytes, bytes)) with ``names`` removed."""
    lowered = {n.lower() for n in names}
    return [(k, v) for (k, v) in headers if k.decode().lower() not in lowered]


def _header_value(headers, name: str) -> str:
    """Case-insensitive lookup of a header from an ASGI (bytes, bytes) list."""
    target = name.lower()
    for k, v in headers:
        if k.decode().lower() == target:
            return v.decode()
    return ""


class PathKeyASGIApp:
    """ASGI wrapper adding path/header/OAuth auth and a health endpoint.

    - ``GET /health`` -> 200 (for ALB/ECS health checks; FastMCP has none).
    - ``GET /.well-known/oauth-protected-resource`` -> RFC 9728 metadata (OAuth on).
    - ``/<key>/mcp`` -> injects ``x-dney-key: <key>`` and forwards to ``/mcp``.
    - When OAuth is enabled, a keyless ``/mcp`` request must carry a valid
      ``Authorization: Bearer <Auth0 JWT>``; the verified email is injected as
      ``x-dney-email``. Otherwise a 401 challenge is returned. When OAuth is
      disabled the legacy behavior is preserved (no challenge, keyless pass-through).
    - Any client-supplied ``x-dney-email`` is always stripped so only verified
      emails ever reach the tool layer.
    - Everything else (including lifespan) passes through untouched.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            # lifespan / websocket -> delegate unchanged (keeps session manager alive)
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in ("/health", "/healthz"):
            await self._health(send)
            return

        if auth0.oauth_enabled() and path == OAUTH_METADATA_PATH:
            await self._oauth_metadata(send)
            return

        # Never trust a client-supplied verified-email header.
        scope = dict(scope)
        headers = _strip_headers(scope.get("headers", []), (_EMAIL_HEADER,))
        scope["headers"] = headers

        key, new_path = extract_path_key(path)
        if key:
            scope["path"] = new_path
            scope["raw_path"] = new_path.encode()
            # Drop any client-sent key header, then inject the path key.
            headers = _strip_headers(headers, _KEY_HEADERS)
            headers.append((b"x-dney-key", key.encode()))
            scope["headers"] = headers
            await self.app(scope, receive, send)
            return

        # No path key. When OAuth is on, enforce header-key OR Bearer JWT.
        if auth0.oauth_enabled() and not any(
            _header_value(headers, h) for h in _KEY_HEADERS
        ):
            authorization = _header_value(headers, "authorization")
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
                try:
                    email = await auth0.get_verifier().email_from_token_async(token)
                except Exception:
                    await self._challenge(send, "The access token is invalid or expired.")
                    return
                headers.append((_EMAIL_HEADER.encode(), email.encode()))
                scope["headers"] = headers
            else:
                await self._challenge(send, "Authentication required.")
                return

        await self.app(scope, receive, send)

    @staticmethod
    async def _send_json(send, status: int, payload: dict, extra_headers=()):
        body = json.dumps(payload).encode()
        response_headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        response_headers.extend(extra_headers)
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": response_headers,
        })
        await send({"type": "http.response.body", "body": body})

    @staticmethod
    async def _health(send):
        await PathKeyASGIApp._send_json(send, 200, {"status": "ok"})

    @staticmethod
    async def _oauth_metadata(send):
        await PathKeyASGIApp._send_json(
            send,
            200,
            {
                "resource": os.environ.get("MCP_AUDIENCE", ""),
                "authorization_servers": [os.environ.get("AUTH0_ISSUER", "")],
                "bearer_methods_supported": ["header"],
            },
        )

    @staticmethod
    async def _challenge(send, description: str):
        challenge = (
            f'Bearer resource_metadata="{auth0.public_url()}{OAUTH_METADATA_PATH}"'
        )
        await PathKeyASGIApp._send_json(
            send,
            401,
            {"error": "unauthorized", "error_description": description},
            extra_headers=[(b"www-authenticate", challenge.encode())],
        )


def build_app():
    """Build the wrapped ASGI application (FastMCP + path auth + health)."""
    return PathKeyASGIApp(mcp.streamable_http_app())


# Module-level app for `uvicorn asgard_mcp.server:app`.
app = build_app()


def main() -> None:
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("MCP_HOST", "0.0.0.0"),
        port=int(os.environ.get("MCP_PORT", "3001")),
        # Must outlast the ALB idle timeout (300 s); see the Dockerfile CMD.
        timeout_keep_alive=310,
    )


if __name__ == "__main__":
    main()
