"""M4: JwtIdentityVerifier (optional extra ``adk-memshield[jwt]``)."""

from __future__ import annotations

import time

import pytest

from adk_memshield import MemShieldIdentity, MemShieldIdentityError

APP = "identity_app"

jwt = pytest.importorskip("jwt")


@pytest.fixture(scope="module")
def rsa_keys():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public_pem


def _jwt(private, **overrides) -> str:
    claims = {"sub": "alice", "tenant": "tenant_a", "clearance": 2, "aud": APP,
              "exp": int(time.time()) + 300, "iss": "https://issuer.example"}
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256")


def test_jwt_verifier(rsa_keys) -> None:
    from adk_memshield import JwtIdentityVerifier

    private, public_pem = rsa_keys
    verifier = JwtIdentityVerifier(key=public_pem, issuer="https://issuer.example")
    assert verifier.verify(_jwt(private), audience=APP) == MemShieldIdentity("tenant_a", "alice", 2)
    with pytest.raises(MemShieldIdentityError, match="expired"):
        verifier.verify(_jwt(private, exp=int(time.time()) - 60), audience=APP)
    with pytest.raises(MemShieldIdentityError, match="another application"):
        verifier.verify(_jwt(private, aud="other"), audience=APP)
    with pytest.raises(MemShieldIdentityError, match="invalid"):
        verifier.verify(_jwt(private, iss="https://evil.example"), audience=APP)
    # Algorithm confusion: an HS256 token "signed" with the public key must be refused.
    forged = jwt.encode({"sub": "bob", "tenant": "tenant_a", "aud": APP,
                         "exp": int(time.time()) + 300, "iss": "https://issuer.example"},
                        "x" * 32, algorithm="HS256")
    with pytest.raises(MemShieldIdentityError, match="invalid"):
        verifier.verify(forged, audience=APP)
    with pytest.raises(ValueError, match="none"):
        JwtIdentityVerifier(key=public_pem, issuer=None, algorithms=["none"])


def test_jwt_issuer_is_required(rsa_keys) -> None:
    from adk_memshield import JwtIdentityVerifier

    private, public_pem = rsa_keys
    with pytest.raises(TypeError):
        JwtIdentityVerifier(key=public_pem)  # issuer must be given explicitly
    strict = JwtIdentityVerifier(key=public_pem, issuer="https://issuer.example")
    claims = {"sub": "alice", "tenant": "tenant_a", "aud": APP, "exp": int(time.time()) + 300}
    no_iss = jwt.encode(claims, private, algorithm="RS256")
    with pytest.raises(MemShieldIdentityError, match="invalid"):
        strict.verify(no_iss, audience=APP)
    opted_out = JwtIdentityVerifier(key=public_pem, issuer=None)
    assert opted_out.verify(no_iss, audience=APP).user_id == "alice"
