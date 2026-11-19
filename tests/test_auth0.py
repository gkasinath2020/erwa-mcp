"""Tests for Auth0 JWT verification (real RS256, JWKS-injected)."""

import jwt
import pytest
import respx
from httpx import Response

from asgard_mcp import auth0
from asgard_mcp.auth0 import Auth0Config, Auth0Verifier

from ._keys import (
    AUDIENCE,
    EMAIL_CLAIM,
    ISSUER,
    OTHER_PRIVATE_KEY,
    FakeJWKClient,
    jwks_for,
    make_token,
)


def _verifier(allow_bare_email=False):
    config = Auth0Config(
        issuer=ISSUER,
        audience=AUDIENCE,
        email_claim=EMAIL_CLAIM,
        allow_bare_email=allow_bare_email,
    )
    return Auth0Verifier(config=config, jwk_client=FakeJWKClient(jwks_for()))


class TestConfig:
    def test_defaults_from_env(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ISSUER", ISSUER)
        monkeypatch.setenv("MCP_AUDIENCE", AUDIENCE)
        monkeypatch.delenv("AUTH0_EMAIL_CLAIM", raising=False)
        cfg = Auth0Config()
        assert cfg.issuer == ISSUER
        assert cfg.audience == AUDIENCE
        assert cfg.email_claim == "https://dney.dev/email"
        assert cfg.jwks_uri == "https://example-tenant.us.auth0.com/.well-known/jwks.json"

    def test_email_claim_override(self, monkeypatch):
        monkeypatch.setenv("AUTH0_EMAIL_CLAIM", "https://custom/email")
        assert Auth0Config().email_claim == "https://custom/email"

    def test_email_verified_claim_default(self, monkeypatch):
        monkeypatch.delenv("AUTH0_EMAIL_VERIFIED_CLAIM", raising=False)
        assert Auth0Config().email_verified_claim == "https://dney.dev/email_verified"

    def test_email_verified_claim_override(self, monkeypatch):
        monkeypatch.setenv("AUTH0_EMAIL_VERIFIED_CLAIM", "https://custom/verified")
        assert Auth0Config().email_verified_claim == "https://custom/verified"

    def test_userinfo_validation_defaults_off(self, monkeypatch):
        monkeypatch.delenv("AUTH0_USERINFO_VALIDATION", raising=False)
        assert Auth0Config().userinfo_validation is False

    def test_userinfo_validation_env_on(self, monkeypatch):
        monkeypatch.setenv("AUTH0_USERINFO_VALIDATION", "true")
        assert Auth0Config().userinfo_validation is True

    def test_userinfo_url_derived_from_issuer(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ISSUER", ISSUER)
        assert Auth0Config().userinfo_url == "https://example-tenant.us.auth0.com/userinfo"

    def test_allow_bare_email_defaults_off(self, monkeypatch):
        monkeypatch.delenv("AUTH0_ALLOW_BARE_EMAIL", raising=False)
        assert Auth0Config().allow_bare_email is False

    def test_allow_bare_email_env_on(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ALLOW_BARE_EMAIL", "TRUE")
        assert Auth0Config().allow_bare_email is True

    def test_allow_bare_email_env_junk_is_off(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ALLOW_BARE_EMAIL", "maybe")
        assert Auth0Config().allow_bare_email is False

    def test_allow_bare_email_explicit_arg_wins(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ALLOW_BARE_EMAIL", "true")
        assert Auth0Config(allow_bare_email=False).allow_bare_email is False


class TestOAuthEnabled:
    def test_enabled_when_both_set(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ISSUER", ISSUER)
        monkeypatch.setenv("MCP_AUDIENCE", AUDIENCE)
        assert auth0.oauth_enabled() is True

    def test_disabled_when_missing(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ISSUER", ISSUER)
        monkeypatch.delenv("MCP_AUDIENCE", raising=False)
        assert auth0.oauth_enabled() is False


class TestPublicUrl:
    def test_default(self, monkeypatch):
        monkeypatch.delenv("MCP_PUBLIC_URL", raising=False)
        assert auth0.public_url() == "https://mcp.dney.dev"

    def test_override_strips_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("MCP_PUBLIC_URL", "https://mcp.example.com/")
        assert auth0.public_url() == "https://mcp.example.com"


class TestVerify:
    def test_valid_primary_claim(self):
        email = _verifier().email_from_token(make_token(email="alice@dney.dev"))
        assert email == "alice@dney.dev"

    def test_bare_email_rejected_by_default(self):
        # No namespaced claim; only the standard `email` claim. With the
        # fallback OFF (default), this must be rejected (M1 hardening).
        token = make_token(include_email_claim=False, fallback_email="bob@dney.dev")
        with pytest.raises(jwt.InvalidTokenError):
            _verifier().email_from_token(token)

    def test_bare_email_allowed_when_gated_on(self):
        # Same token, but the operator explicitly opted into the fallback.
        token = make_token(include_email_claim=False, fallback_email="bob@dney.dev")
        email = _verifier(allow_bare_email=True).email_from_token(token)
        assert email == "bob@dney.dev"

    def test_bare_email_ignored_when_namespaced_present(self):
        # Even with the fallback on, the namespaced claim takes priority.
        token = make_token(email="alice@dney.dev", fallback_email="bob@dney.dev")
        assert _verifier(allow_bare_email=True).email_from_token(token) == "alice@dney.dev"

    def test_no_email_claim_raises(self):
        token = make_token(include_email_claim=False, fallback_email=None)
        with pytest.raises(jwt.InvalidTokenError):
            _verifier().email_from_token(token)

    def test_unverified_email_rejected(self):
        # Valid signature + namespaced email, but email_verified is False.
        token = make_token(email="alice@dney.dev", email_verified=False)
        with pytest.raises(jwt.InvalidTokenError):
            _verifier().email_from_token(token)

    def test_missing_email_verified_rejected(self):
        # No email_verified claim at all -> not trusted.
        token = make_token(email="alice@dney.dev", email_verified=None)
        with pytest.raises(jwt.InvalidTokenError):
            _verifier().email_from_token(token)

    def test_email_verified_non_bool_truthy_rejected(self):
        # A truthy-but-not-True value (e.g. the string "true") must not pass.
        claims = {"email_verified": "true", EMAIL_CLAIM: "alice@dney.dev"}
        with pytest.raises(jwt.InvalidTokenError):
            _verifier().extract_email(claims)

    def test_namespaced_email_verified_accepted(self):
        # Real Auth0 shape: only the namespaced verified claim is present (the
        # bare standard one is omitted, as Auth0 drops non-namespaced customs).
        token = make_token(
            email="alice@dney.dev", email_verified=None, namespaced_verified=True
        )
        assert _verifier().email_from_token(token) == "alice@dney.dev"

    def test_namespaced_email_verified_false_rejected(self):
        # Namespaced verified=False and no bare claim -> not trusted.
        token = make_token(
            email="alice@dney.dev", email_verified=None, namespaced_verified=False
        )
        with pytest.raises(jwt.InvalidTokenError):
            _verifier().email_from_token(token)

    def test_bare_email_verified_fallback_still_accepted(self):
        # Only the bare standard claim (no namespaced) -> honored as a fallback.
        token = make_token(email="alice@dney.dev", email_verified=True)
        assert _verifier().email_from_token(token) == "alice@dney.dev"

    def test_expired(self):
        token = make_token(exp_offset=-10)
        with pytest.raises(jwt.ExpiredSignatureError):
            _verifier().verify(token)

    def test_wrong_audience(self):
        token = make_token(aud="https://not-mcp.dney.dev")
        with pytest.raises(jwt.InvalidAudienceError):
            _verifier().verify(token)

    def test_wrong_issuer(self):
        token = make_token(iss="https://evil.example.com/")
        with pytest.raises(jwt.InvalidIssuerError):
            _verifier().verify(token)

    def test_bad_signature(self):
        # Signed by a different key than the JWKS advertises (same kid).
        token = make_token(private_key=OTHER_PRIVATE_KEY)
        with pytest.raises(jwt.InvalidSignatureError):
            _verifier().verify(token)

    def test_unknown_kid(self):
        token = make_token(kid="does-not-exist")
        with pytest.raises(jwt.PyJWKClientError):
            _verifier().verify(token)


class TestVerifierCaching:
    def test_get_verifier_is_cached(self, monkeypatch):
        monkeypatch.setenv("AUTH0_ISSUER", ISSUER)
        monkeypatch.setenv("MCP_AUDIENCE", AUDIENCE)
        auth0.set_verifier(None)
        v1 = auth0.get_verifier()
        v2 = auth0.get_verifier()
        assert v1 is v2
        assert isinstance(v1, Auth0Verifier)
        auth0.set_verifier(None)

    def test_lazy_jwk_client_built_once(self):
        v = Auth0Verifier(config=Auth0Config(issuer=ISSUER, audience=AUDIENCE))
        client = v.jwk_client
        assert client is v.jwk_client  # cached


def _userinfo_verifier():
    return Auth0Verifier(
        config=Auth0Config(issuer=ISSUER, audience=AUDIENCE, userinfo_validation=True)
    )


USERINFO = "https://example-tenant.us.auth0.com/userinfo"


class TestUserinfoValidation:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self):
        respx.get(USERINFO).mock(
            return_value=Response(200, json={"email": "alice@dney.dev", "email_verified": True})
        )
        email = await _userinfo_verifier().email_from_userinfo("opaque-token")
        assert email == "alice@dney.dev"

    @respx.mock
    @pytest.mark.asyncio
    async def test_unverified_rejected(self):
        respx.get(USERINFO).mock(
            return_value=Response(200, json={"email": "alice@dney.dev", "email_verified": False})
        )
        with pytest.raises(jwt.InvalidTokenError):
            await _userinfo_verifier().email_from_userinfo("opaque-token")

    @respx.mock
    @pytest.mark.asyncio
    async def test_missing_email_rejected(self):
        respx.get(USERINFO).mock(return_value=Response(200, json={"email_verified": True}))
        with pytest.raises(jwt.InvalidTokenError):
            await _userinfo_verifier().email_from_userinfo("opaque-token")

    @respx.mock
    @pytest.mark.asyncio
    async def test_401_rejected(self):
        respx.get(USERINFO).mock(return_value=Response(401, json={"error": "invalid_token"}))
        with pytest.raises(jwt.InvalidTokenError):
            await _userinfo_verifier().email_from_userinfo("bad-token")

    @respx.mock
    @pytest.mark.asyncio
    async def test_transport_error_rejected(self):
        import httpx as _httpx

        respx.get(USERINFO).mock(side_effect=_httpx.ConnectError("boom"))
        with pytest.raises(jwt.InvalidTokenError):
            await _userinfo_verifier().email_from_userinfo("token")

    @respx.mock
    @pytest.mark.asyncio
    async def test_async_dispatch_uses_userinfo_when_configured(self):
        respx.get(USERINFO).mock(
            return_value=Response(200, json={"email": "bob@dney.dev", "email_verified": True})
        )
        email = await _userinfo_verifier().email_from_token_async("opaque-token")
        assert email == "bob@dney.dev"

    @pytest.mark.asyncio
    async def test_async_dispatch_uses_jwks_by_default(self):
        # Default (userinfo off) path resolves via JWKS + the injected key client.
        v = Auth0Verifier(
            config=Auth0Config(issuer=ISSUER, audience=AUDIENCE, email_claim=EMAIL_CLAIM),
            jwk_client=FakeJWKClient(jwks_for()),
        )
        email = await v.email_from_token_async(make_token(email="carol@dney.dev"))
        assert email == "carol@dney.dev"
