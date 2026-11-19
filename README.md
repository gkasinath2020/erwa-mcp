# dney-mcp

Dney Guardrails MCP server. Exposes Dney's guardrail engine as MCP tools for
Claude Desktop, Claude.ai, and Claude Code — check content for policy
violations, PII, toxicity, and more.

## Tools

- `check_content(text, direction)` — check a message against active guardrails.
- `check_input_output(input_text, output_text)` — check a full exchange.
- `list_guardrails()` — list configured guardrails.
- `guardrail_stats()` — activity summary.
- `recent_activity(limit)` — recent guardrail decisions (metadata only).
- `report_decision(audit_id, verdict)` — report that a decision was wrong
  (`false_block` or `miss`). Carries no text: only the decision's id and the verdict.

## Auth

The server resolves the caller's Dney org in one of three ways. Prefer the
first two — they keep the secret out of URLs and logs:

1. **Header key (recommended)** — `x-dney-key` (or legacy `x-api-key`), or the
   `DNEY_API_KEY` env var for single-user/local use.
2. **Auth0 OAuth (recommended, optional)** — a keyless `/mcp` request with
   `Authorization: Bearer <Auth0 access token>`. The server verifies the token
   (RS256, issuer, audience, expiry), requires `email_verified: true`, extracts
   the user's email from the namespaced `AUTH0_EMAIL_CLAIM`, and resolves the
   org by email via the backend's internal service endpoint using
   `MCP_SERVICE_TOKEN`. If no Dney account is linked to that email, the tool
   returns a clear "link your Dney account" error.
3. **Path key (deprecated)** — `https://mcp.dney.dev/<your-asg-key>/mcp`. The
   `PathKeyASGIApp` wrapper strips the leading key segment, injects it as
   `x-dney-key`, and rewrites the path to `/mcp`. This exists only for connector
   UIs that accept a URL and no custom headers.

   > ⚠️ **Security risk — avoid when possible.** A key in the URL *path* is
   > written to ALB/CloudFront/proxy access logs, APM traces, and browser
   > history, i.e. **the key leaks into logs**. Use OAuth or a header key
   > wherever the client allows it. Treat path keys as low-privilege, rotate
   > them readily, and never paste the URL into referrer-leaking contexts.

OAuth is **enforced only when both `AUTH0_ISSUER` and `MCP_AUDIENCE` are set**.
When either is unset the server runs in legacy path-key-only mode. When OAuth is
enabled, a keyless `/mcp` request without a valid Bearer token receives a `401`
with a `WWW-Authenticate: Bearer resource_metadata="…"` challenge pointing at
`GET /.well-known/oauth-protected-resource` (RFC 9728 protected-resource
metadata).

Any client-supplied `x-dney-email` header is always stripped at the ASGI
boundary; only an email verified from a Bearer JWT is ever trusted.

## Environment variables

| Var | Default | Purpose |
| --- | --- | --- |
| `DNEY_API_URL` | `http://localhost:8000` | Dney backend base URL |
| `DNEY_API_KEY` | — | Single-user/local API key |
| `MCP_HOST` / `MCP_PORT` | `0.0.0.0` / `3001` | Bind address |
| `AUTH0_ISSUER` | — | Auth0 issuer (trailing slash), e.g. `https://YOUR-TENANT.us.auth0.com/` |
| `MCP_AUDIENCE` | — | Expected token audience, e.g. `https://mcp.dney.dev` |
| `AUTH0_EMAIL_CLAIM` | `https://dney.dev/email` | Namespaced claim holding the verified user email (bare `email` is **not** used unless `AUTH0_ALLOW_BARE_EMAIL` is set) |
| `AUTH0_EMAIL_VERIFIED_CLAIM` | `https://dney.dev/email_verified` | Namespaced claim asserting the email is verified; must be `true`. Falls back to the bare `email_verified` claim if the namespaced one is absent. (JWKS mode only.) |
| `AUTH0_USERINFO_VALIDATION` | `false` | When `true`, validate the bearer token by calling Auth0 `/userinfo` (reads standard `email`/`email_verified`) instead of JWKS + custom audience. **Required for Dynamic Client Registration** — DCR clients are third-party apps and can't obtain access tokens for a custom API audience, so remove the tenant Default Audience and enable this. |
| `AUTH0_ALLOW_BARE_EMAIL` | `false` | ⚠️ If `true`, fall back to the standard `email` claim when the namespaced claim is absent. Widens the impersonation surface — leave off unless you fully control every identity source in the Auth0 tenant. |
| `MCP_PUBLIC_URL` | `https://mcp.dney.dev` | Public base URL advertised in the 401 challenge |
| `MCP_SERVICE_TOKEN` | — | Shared secret for the backend `resolve-org` service call |

The OAuth email is trusted only when the token asserts `email_verified: true`;
tokens with a missing/false `email_verified` are rejected.

`AUTH0_ISSUER` + `MCP_AUDIENCE` together enable OAuth; `MCP_SERVICE_TOKEN` must
match the backend's `MCP_SERVICE_SECRET`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Run

```bash
# ASGI app (FastMCP + path/header/OAuth auth + /health)
python -m asgard_mcp.server
# or via uvicorn: uvicorn asgard_mcp.server:app
```

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), never in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).
