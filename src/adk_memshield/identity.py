"""Verified caller identity.

By default memshield trusts the ``user_id`` the framework passes and takes tenant,
clearance and compartments from its own configuration ("trusted caller mode", the 0.1.x
behaviour). With an :class:`IdentityVerifier` configured, every memory operation needs a
signed identity token bound for the current request with :func:`bind_identity`. Tenant,
clearance and compartments then come from the verified token, and the framework's
``user_id`` must match the token's subject.

This stops spoofed identity from prompts, tool arguments and application-layer bugs. It
does not stop a compromised process that holds both the database credentials and the
token signing key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .errors import MemShieldIdentityError

COMPARTMENT_RE = re.compile(r"^[a-z0-9_-]{1,64}$")

_CURRENT_TOKEN: ContextVar[str | None] = ContextVar("adk_memshield_identity_token", default=None)


def validate_compartments(values: Sequence[str] | None) -> tuple[str, ...]:
    """Validate and normalise compartment names (sorted, de-duplicated).

    Names must match ``^[a-z0-9_-]{1,64}$`` so a comma, brace or quote can never change
    how PostgreSQL parses the bound compartment list.
    """
    if values is None:
        return ()
    if isinstance(values, str):
        raise ValueError("compartments must be a list of names, not a string")
    out: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not COMPARTMENT_RE.fullmatch(value):
            raise ValueError(f"invalid compartment name: {value!r}")
        out.add(value)
    return tuple(sorted(out))


@dataclass(frozen=True)
class MemShieldIdentity:
    """The identity an operation runs under."""

    tenant_id: str
    user_id: str
    clearance: int = 1
    compartments: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.tenant_id or not str(self.tenant_id).strip():
            raise ValueError("tenant_id must be a non-empty string")
        if not self.user_id or not str(self.user_id).strip():
            raise ValueError("user_id must be a non-empty string")
        if isinstance(self.clearance, bool) or not isinstance(self.clearance, int):
            raise ValueError("clearance must be an integer")
        if not 1 <= self.clearance <= 5:
            raise ValueError("clearance must be between 1 and 5")
        object.__setattr__(self, "compartments", validate_compartments(self.compartments))


@runtime_checkable
class IdentityVerifier(Protocol):
    """Turns a bound token into a verified :class:`MemShieldIdentity`.

    ``audience`` is the application name of the operation; a token issued for another
    application must be refused. Implementations raise :class:`MemShieldIdentityError`
    (or any exception, which memshield converts) and must never include the token in
    error messages or logs.
    """

    def verify(self, token: str, *, audience: str) -> MemShieldIdentity: ...


@contextmanager
def bind_identity(token: str) -> Iterator[None]:
    """Bind an identity token for the code running inside the ``with`` block.

    The binding lives in a :class:`contextvars.ContextVar`, so it is per request (per
    thread and per asyncio task) and is copied into ``asyncio.to_thread`` workers.
    """
    if not isinstance(token, str) or not token:
        raise MemShieldIdentityError("identity token must be a non-empty string")
    reset_token = _CURRENT_TOKEN.set(token)
    try:
        yield
    finally:
        _CURRENT_TOKEN.reset(reset_token)


def current_identity_token() -> str | None:
    """Return the token bound by :func:`bind_identity` in this context, if any."""
    return _CURRENT_TOKEN.get()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", data):
        raise ValueError("not base64url")
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _identity_from_claims(
    claims: Mapping[str, Any],
    *,
    tenant_claim: str,
    clearance_claim: str,
    compartments_claim: str,
) -> MemShieldIdentity:
    try:
        sub = claims["sub"]
        tenant = claims[tenant_claim]
    except KeyError as exc:
        raise MemShieldIdentityError(f"identity token is missing the {exc.args[0]!r} claim") from None
    clearance = claims.get(clearance_claim, 1)
    compartments = claims.get(compartments_claim, [])
    if not isinstance(sub, str) or not isinstance(tenant, str):
        raise MemShieldIdentityError("identity token subject and tenant must be strings")
    if isinstance(clearance, bool) or not isinstance(clearance, int):
        raise MemShieldIdentityError("identity token clearance must be an integer")
    if not isinstance(compartments, list):
        raise MemShieldIdentityError("identity token compartments must be a list")
    try:
        return MemShieldIdentity(
            tenant_id=tenant,
            user_id=sub,
            clearance=clearance,
            compartments=tuple(compartments),
        )
    except ValueError as exc:
        raise MemShieldIdentityError(f"identity token claims are invalid: {exc}") from None


class HmacIdentityVerifier:
    """Verifies compact HMAC-SHA256 identity tokens (standard library only).

    Token format: ``base64url(json_payload) + "." + base64url(hmac_sha256(key, payload_part))``.
    The payload carries ``sub``, ``tenant``, ``clearance``, ``compartments``, ``aud`` (the
    application name), ``exp`` (Unix seconds) and ``kid`` (which key signed it), so keys can
    be rotated by keeping the old and new key in ``keys`` for a while.

    Use :meth:`issue` (or :func:`issue_hmac_token`) in your auth layer to mint tokens.
    """

    def __init__(
        self,
        keys: Mapping[str, bytes | str],
        *,
        leeway_seconds: int = 0,
        max_ttl_seconds: int = 86_400,
        tenant_claim: str = "tenant",
        clearance_claim: str = "clearance",
        compartments_claim: str = "compartments",
    ) -> None:
        if not keys:
            raise ValueError("HmacIdentityVerifier needs at least one key")
        if max_ttl_seconds <= 0:
            raise ValueError("max_ttl_seconds must be positive")
        self._max_ttl = int(max_ttl_seconds)
        self._keys: dict[str, bytes] = {}
        for kid, key in keys.items():
            raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
            if len(raw) < 32:
                raise ValueError(f"HMAC key {kid!r} must be at least 32 bytes")
            self._keys[str(kid)] = raw
        self._leeway = int(leeway_seconds)
        self._tenant_claim = tenant_claim
        self._clearance_claim = clearance_claim
        self._compartments_claim = compartments_claim

    def verify(self, token: str, *, audience: str) -> MemShieldIdentity:
        if not isinstance(token, str) or token.count(".") != 1:
            raise MemShieldIdentityError("identity token is malformed")
        payload_part, sig_part = token.split(".", 1)
        try:
            payload_bytes = _b64url_decode(payload_part)
            signature = _b64url_decode(sig_part)
            claims = json.loads(payload_bytes)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            raise MemShieldIdentityError("identity token is malformed") from None
        if not isinstance(claims, dict):
            raise MemShieldIdentityError("identity token is malformed")

        kid = claims.get("kid")
        key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise MemShieldIdentityError("identity token was signed with an unknown key")
        expected = hmac.new(key, payload_part.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise MemShieldIdentityError("identity token signature is invalid")

        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            raise MemShieldIdentityError("identity token has no valid expiry")
        now = time.time()
        if now > float(exp) + self._leeway:
            raise MemShieldIdentityError("identity token has expired")
        if float(exp) - now > self._max_ttl + self._leeway:
            raise MemShieldIdentityError("identity token lifetime exceeds the verifier's maximum")
        if claims.get("aud") != audience:
            raise MemShieldIdentityError("identity token was issued for another application")

        return _identity_from_claims(
            claims,
            tenant_claim=self._tenant_claim,
            clearance_claim=self._clearance_claim,
            compartments_claim=self._compartments_claim,
        )

    def issue(
        self,
        *,
        kid: str,
        user_id: str,
        tenant_id: str,
        audience: str,
        clearance: int = 1,
        compartments: Sequence[str] = (),
        ttl_seconds: int = 300,
    ) -> str:
        """Mint a token with key ``kid`` (for your auth layer and for tests)."""
        if kid not in self._keys:
            raise ValueError(f"unknown key id {kid!r}")
        return issue_hmac_token(
            self._keys[kid],
            kid=kid,
            user_id=user_id,
            tenant_id=tenant_id,
            audience=audience,
            clearance=clearance,
            compartments=compartments,
            ttl_seconds=ttl_seconds,
        )


def issue_hmac_token(
    key: bytes | str,
    *,
    kid: str,
    user_id: str,
    tenant_id: str,
    audience: str,
    clearance: int = 1,
    compartments: Sequence[str] = (),
    ttl_seconds: int = 300,
    now: float | None = None,
) -> str:
    """Create an HMAC-SHA256 identity token readable by :class:`HmacIdentityVerifier`."""
    identity = MemShieldIdentity(
        tenant_id=tenant_id, user_id=user_id, clearance=clearance, compartments=tuple(compartments)
    )
    issued = time.time() if now is None else now
    payload = {
        "sub": identity.user_id,
        "tenant": identity.tenant_id,
        "clearance": identity.clearance,
        "compartments": list(identity.compartments),
        "aud": audience,
        "exp": int(issued + ttl_seconds),
        "kid": kid,
    }
    raw_key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    payload_part = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac.new(raw_key, payload_part.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_part}.{_b64url_encode(signature)}"


class JwtIdentityVerifier:
    """Verifies OIDC / JWT identity tokens with PyJWT (install ``adk-memshield[jwt]``).

    Works with Firebase Auth, Google Cloud Identity Platform and any OIDC provider that
    publishes a JWKS. Pass ``jwks_url`` (keys fetched and cached by PyJWT) or a fixed
    ``key`` (a public key, for tests or a single static key). The token's ``aud`` must equal
    the application name of the operation unless ``audience`` is given explicitly.

    ``issuer`` is required: with a JWKS shared by many issuers (multi-tenant Entra ID, the
    Firebase key set shared by all projects), a token from another issuer signed by the same
    keys would otherwise be accepted. Pass ``issuer=None`` only for a key set that belongs
    to your issuer alone. Prefer an ``audience`` your identity provider owns (a client or
    project id) over the ADK app name.
    """

    def __init__(
        self,
        *,
        jwks_url: str | None = None,
        key: Any | None = None,
        issuer: str | None,
        algorithms: Sequence[str] = ("RS256",),
        audience: str | None = None,
        leeway_seconds: int = 0,
        tenant_claim: str = "tenant",
        clearance_claim: str = "clearance",
        compartments_claim: str = "compartments",
    ) -> None:
        try:
            import jwt  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "JwtIdentityVerifier needs PyJWT: pip install 'adk-memshield[jwt]'"
            ) from exc
        if (jwks_url is None) == (key is None):
            raise ValueError("pass exactly one of jwks_url or key")
        if not algorithms or any(a.lower() == "none" for a in algorithms):
            raise ValueError("algorithms must be non-empty and must not include 'none'")
        self._jwks_client = None
        if jwks_url is not None:
            import jwt

            self._jwks_client = jwt.PyJWKClient(jwks_url)
        self._key = key
        self._algorithms = list(algorithms)
        self._issuer = issuer
        self._audience = audience
        self._leeway = int(leeway_seconds)
        self._tenant_claim = tenant_claim
        self._clearance_claim = clearance_claim
        self._compartments_claim = compartments_claim

    def verify(self, token: str, *, audience: str) -> MemShieldIdentity:
        import jwt

        try:
            if self._jwks_client is not None:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token).key
            else:
                signing_key = self._key
            options = {"require": ["exp", "sub", "aud"] + (["iss"] if self._issuer else [])}
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=self._algorithms,
                audience=self._audience or audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options=options,
            )
        except jwt.ExpiredSignatureError:
            raise MemShieldIdentityError("identity token has expired") from None
        except jwt.InvalidAudienceError:
            raise MemShieldIdentityError("identity token was issued for another application") from None
        except jwt.PyJWTError as exc:
            raise MemShieldIdentityError(f"identity token is invalid ({type(exc).__name__})") from None
        return _identity_from_claims(
            claims,
            tenant_claim=self._tenant_claim,
            clearance_claim=self._clearance_claim,
            compartments_claim=self._compartments_claim,
        )
