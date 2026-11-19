"""Test helpers: a self-generated RSA keypair, JWKS, and RS256 token minting.

These let the suite exercise *real* RS256 verification (via PyJWT + cryptography)
without any network access, by injecting a JWKS-backed key client into the
verifier.
"""

import json
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ISSUER = "https://example-tenant.us.auth0.com/"
AUDIENCE = "https://mcp.dney.dev"
EMAIL_CLAIM = "https://dney.dev/email"
KID = "test-key-1"


def _generate():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# One keypair for the "trusted" JWKS, plus a second for bad-signature tests.
PRIVATE_KEY = _generate()
OTHER_PRIVATE_KEY = _generate()


def jwks_for(private_key=PRIVATE_KEY, kid=KID) -> dict:
    """Build a JWKS dict advertising ``private_key``'s public key under ``kid``."""
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return {"keys": [jwk]}


def make_token(
    *,
    private_key=PRIVATE_KEY,
    kid=KID,
    iss=ISSUER,
    aud=AUDIENCE,
    email="user@example.com",
    email_claim=EMAIL_CLAIM,
    include_email_claim=True,
    fallback_email=None,
    email_verified=True,
    namespaced_verified=None,
    email_verified_claim="https://dney.dev/email_verified",
    exp_offset=3600,
) -> str:
    """Mint a signed RS256 token with configurable claims.

    ``email_verified`` sets the *bare* standard claim (defaults ``True``; ``None``
    omits it). ``namespaced_verified`` sets the *namespaced* claim
    (``https://dney.dev/email_verified``) that an Auth0 Action injects — this
    mirrors real Auth0 access tokens, where only namespaced custom claims survive.
    """
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "sub": "auth0|abc", "iat": now, "exp": now + exp_offset}
    if email_verified is not None:
        claims["email_verified"] = email_verified
    if namespaced_verified is not None:
        claims[email_verified_claim] = namespaced_verified
    if include_email_claim and email is not None:
        claims[email_claim] = email
    if fallback_email is not None:
        claims["email"] = fallback_email
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


class FakeJWKClient:
    """A drop-in for ``PyJWKClient`` that serves keys from an in-memory JWKS."""

    def __init__(self, jwks: dict):
        self._jwks = jwks

    def get_signing_key_from_jwt(self, token: str):
        kid = jwt.get_unverified_header(token)["kid"]
        for entry in self._jwks["keys"]:
            if entry["kid"] == kid:
                return jwt.PyJWK.from_dict(entry)
        raise jwt.PyJWKClientError("no matching key")
