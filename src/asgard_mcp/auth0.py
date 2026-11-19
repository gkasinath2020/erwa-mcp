"""Auth0 JWT verification for the Dney MCP server.

OAuth is *enforced* only when both ``AUTH0_ISSUER`` and ``MCP_AUDIENCE`` are set
in the environment. When either is missing, the server runs in the legacy
path-key-only mode and this module's verifier is never exercised. Importing this
module never requires the Auth0 environment to be present.

Verification uses PyJWT (``pyjwt[crypto]``) with a cached :class:`PyJWKClient`
that fetches the JWKS from ``<AUTH0_ISSUER>.well-known/jwks.json``. Tokens are
checked for an RS256 signature, ``iss == AUTH0_ISSUER``, ``MCP_AUDIENCE in aud``
and a valid ``exp``.

Identity (the tenant-resolution decision in service mode) is derived from the
token's email, but only when the token asserts ``email_verified is True``. The
email is read *exclusively* from the namespaced custom claim
(``AUTH0_EMAIL_CLAIM``, default ``https://dney.dev/email``). The bare, standard
``email`` claim is **not** trusted by default — a second app or connection in
the same Auth0 tenant can populate it with an unverified/attacker-controlled
value, which would allow cross-tenant impersonation. Falling back to the bare
``email`` claim can be re-enabled (at your own risk) with
``AUTH0_ALLOW_BARE_EMAIL=true``, but this is off by default.
"""

_TRUTHY = {"1", "true", "yes", "on"}

import os

import httpx
import jwt
from jwt import InvalidTokenError, PyJWKClient

DEFAULT_EMAIL_CLAIM = "https://dney.dev/email"
DEFAULT_EMAIL_VERIFIED_CLAIM = "https://dney.dev/email_verified"
DEFAULT_PUBLIC_URL = "https://mcp.dney.dev"


def oauth_enabled() -> bool:
    """True when Auth0 OAuth is configured (issuer + audience both set)."""
    return bool(os.environ.get("AUTH0_ISSUER") and os.environ.get("MCP_AUDIENCE"))


def public_url() -> str:
    """Externally reachable base URL used to advertise resource metadata."""
    return os.environ.get("MCP_PUBLIC_URL", DEFAULT_PUBLIC_URL).rstrip("/")


class Auth0Config:
    """Auth0 verification settings, sourced from the environment by default."""

    def __init__(
        self,
        issuer: str | None = None,
        audience: str | None = None,
        email_claim: str | None = None,
        email_verified_claim: str | None = None,
        allow_bare_email: bool | None = None,
        userinfo_validation: bool | None = None,
    ):
        self.issuer = issuer if issuer is not None else os.environ.get("AUTH0_ISSUER", "")
        self.audience = (
            audience if audience is not None else os.environ.get("MCP_AUDIENCE", "")
        )
        self.email_claim = email_claim or os.environ.get(
            "AUTH0_EMAIL_CLAIM", DEFAULT_EMAIL_CLAIM
        )
        # Auth0 only reliably passes NAMESPACED custom claims into the access
        # token (a post-login Action sets ``https://dney.dev/email_verified``),
        # so the verified flag is read from that namespaced claim first, then
        # the standard bare ``email_verified`` as a fallback.
        self.email_verified_claim = email_verified_claim or os.environ.get(
            "AUTH0_EMAIL_VERIFIED_CLAIM", DEFAULT_EMAIL_VERIFIED_CLAIM
        )
        # Trusting the bare, standard ``email`` claim widens the impersonation
        # surface; it is OFF unless explicitly enabled.
        if allow_bare_email is not None:
            self.allow_bare_email = allow_bare_email
        else:
            self.allow_bare_email = (
                os.environ.get("AUTH0_ALLOW_BARE_EMAIL", "").strip().lower() in _TRUTHY
            )
        # Validate the bearer token by calling Auth0's /userinfo instead of
        # verifying a JWT signature + custom audience. Required for Dynamic
        # Client Registration: DCR clients are third-party apps and cannot
        # obtain access tokens for a custom API audience, so they present a
        # standard (opaque) OIDC token that only /userinfo can validate.
        if userinfo_validation is not None:
            self.userinfo_validation = userinfo_validation
        else:
            self.userinfo_validation = (
                os.environ.get("AUTH0_USERINFO_VALIDATION", "").strip().lower() in _TRUTHY
            )

    @property
    def jwks_uri(self) -> str:
        return self.issuer.rstrip("/") + "/.well-known/jwks.json"

    @property
    def userinfo_url(self) -> str:
        return self.issuer.rstrip("/") + "/userinfo"


class Auth0Verifier:
    """Verifies Auth0-issued RS256 access tokens and extracts the user email.

    A :class:`PyJWKClient` is created lazily and cached for the verifier's
    lifetime so the JWKS is fetched (and its keys cached) once. Tests may inject
    a pre-built ``jwk_client`` to exercise real RS256 verification against a
    self-generated keypair without any network access.
    """

    def __init__(self, config: Auth0Config | None = None, jwk_client: PyJWKClient | None = None):
        self.config = config or Auth0Config()
        self._jwk_client = jwk_client

    @property
    def jwk_client(self) -> PyJWKClient:
        if self._jwk_client is None:
            self._jwk_client = PyJWKClient(self.config.jwks_uri, cache_keys=True)
        return self._jwk_client

    def verify(self, token: str) -> dict:
        """Verify ``token`` and return its claims, or raise ``InvalidTokenError``."""
        signing_key = self.jwk_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.config.audience,
            issuer=self.config.issuer,
            options={"require": ["exp", "iss", "aud"]},
        )

    def extract_email(self, claims: dict) -> str:
        """Return the verified email from ``claims`` or raise ``InvalidTokenError``.

        The email is trusted only when ``email_verified is True`` and is read
        from the namespaced custom claim (``AUTH0_EMAIL_CLAIM``). The bare
        ``email`` claim is used only if ``AUTH0_ALLOW_BARE_EMAIL`` is enabled.
        """
        verified = claims.get(self.config.email_verified_claim)
        if verified is None:
            verified = claims.get("email_verified")
        if verified is not True:
            raise InvalidTokenError("token email is not verified")
        email = claims.get(self.config.email_claim)
        if not email and self.config.allow_bare_email:
            email = claims.get("email")
        if not email:
            raise InvalidTokenError("token has no verified email claim")
        return email

    def email_from_token(self, token: str) -> str:
        """Verify ``token`` (JWKS) and return the user's email (raises on failure)."""
        return self.extract_email(self.verify(token))

    async def email_from_userinfo(self, token: str) -> str:
        """Validate ``token`` via Auth0's /userinfo endpoint and return the email.

        Auth0 rejects the token with 401 if it's invalid/expired. The response
        carries the standard OIDC ``email`` / ``email_verified`` claims (Google
        supplies ``email_verified: true`` for real accounts). Raises
        ``InvalidTokenError`` on any failure or an unverified/absent email.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    self.config.userinfo_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.HTTPError as e:
            raise InvalidTokenError(f"userinfo request failed: {e}") from e
        if resp.status_code != 200:
            raise InvalidTokenError(f"userinfo rejected the token ({resp.status_code})")
        claims = resp.json()
        if claims.get("email_verified") is not True:
            raise InvalidTokenError("userinfo email is not verified")
        email = claims.get("email")
        if not email:
            raise InvalidTokenError("userinfo has no email")
        return email

    async def email_from_token_async(self, token: str) -> str:
        """Resolve the user's email, using /userinfo or JWKS per configuration."""
        if self.config.userinfo_validation:
            return await self.email_from_userinfo(token)
        return self.email_from_token(token)


_verifier: Auth0Verifier | None = None


def get_verifier() -> Auth0Verifier:
    """Return the process-wide verifier, building (and caching) it on first use."""
    global _verifier
    if _verifier is None:
        _verifier = Auth0Verifier()
    return _verifier


def set_verifier(verifier: Auth0Verifier | None) -> None:
    """Inject or reset the cached verifier (used by tests)."""
    global _verifier
    _verifier = verifier
