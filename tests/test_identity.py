"""M4: verified identity. Tokens must verify, match the requested user, and never leak."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Callable

import pytest
from conftest import APP_DSN, fake_embed
from google.adk.agents.llm_agent import LlmAgent
from google.adk.memory.memory_entry import MemoryEntry
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.preload_memory_tool import preload_memory_tool
from google.genai import types
from psycopg_pool import ConnectionPool

from adk_memshield import (
    HmacIdentityVerifier,
    MemShieldIdentity,
    MemShieldIdentityError,
    MemShieldMemoryService,
    bind_identity,
    current_identity_token,
    issue_hmac_token,
)

APP = "identity_app"
KEY_OLD = b"k" * 32
KEY_NEW = b"n" * 32


def _entry(text: str, **meta) -> MemoryEntry:
    return MemoryEntry(
        content=types.Content(parts=[types.Part(text=text)], role="user"),
        author="user",
        custom_metadata=dict(meta),
    )


def _verifier(**keys: bytes) -> HmacIdentityVerifier:
    return HmacIdentityVerifier(keys or {"old": KEY_OLD, "new": KEY_NEW})


def _token(user: str, tenant: str = "tenant_a", *, kid: str = "new", key: bytes = KEY_NEW,
           aud: str = APP, clearance: int = 1, compartments: tuple[str, ...] = (),
           ttl: int = 300, now: float | None = None) -> str:
    return issue_hmac_token(key, kid=kid, user_id=user, tenant_id=tenant, audience=aud,
                            clearance=clearance, compartments=compartments, ttl_seconds=ttl, now=now)


def _svc(pool: ConnectionPool, verifier=None, **kwargs) -> MemShieldMemoryService:
    return MemShieldMemoryService(
        dsn=APP_DSN,
        tenant_id="config_tenant_is_ignored",
        embed_fn=fake_embed,
        pool=pool,
        identity_verifier=verifier if verifier is not None else _verifier(),
        **kwargs,
    )


async def _seed(pool: ConnectionPool) -> None:
    """alice and bob in tenant_a, carol in tenant_b, written in trusted mode."""
    for tenant, user, text in [
        ("tenant_a", "alice", "alice note: locker 12"),
        ("tenant_a", "bob", "bob note: locker 44"),
        ("tenant_b", "carol", "carol note: locker 90"),
    ]:
        svc = MemShieldMemoryService(dsn=APP_DSN, tenant_id=tenant, embed_fn=fake_embed, pool=pool)
        await svc.add_memory(app_name=APP, user_id=user, memories=[_entry(text)])


# ---------------------------------------------------------------- verifier unit tests
def test_valid_token_yields_identity_from_claims() -> None:
    ident = _verifier().verify(_token("alice", clearance=3, compartments=("hr", "finance")), audience=APP)
    assert ident == MemShieldIdentity("tenant_a", "alice", 3, ("finance", "hr"))


@pytest.mark.parametrize(
    ("token_factory", "message"),
    [
        (lambda: _token("alice", ttl=-10), "expired"),
        (lambda: _token("alice", aud="other_app"), "another application"),
        (lambda: _token("alice", kid="ghost", key=b"g" * 32), "unknown key"),
        (lambda: _token("alice")[:-4] + "AAAA", "signature"),
        (lambda: "not-a-token", "malformed"),
        (lambda: "a.b.c", "malformed"),
        (lambda: "!!!.###", "malformed"),
    ],
)
def test_invalid_tokens_are_refused(token_factory: Callable[[], str], message: str) -> None:
    token = token_factory()
    with pytest.raises(MemShieldIdentityError, match=message) as exc:
        _verifier().verify(token, audience=APP)
    assert token not in str(exc.value)


def test_tampered_payload_is_refused() -> None:
    import base64
    import json

    token = _token("alice")
    payload_b64, sig = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    payload["sub"] = "bob"
    forged = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(MemShieldIdentityError, match="signature"):
        _verifier().verify(f"{forged}.{sig}", audience=APP)


def test_key_rotation() -> None:
    old_token = _token("alice", kid="old", key=KEY_OLD)
    both = _verifier()
    assert both.verify(old_token, audience=APP).user_id == "alice"
    assert both.verify(_token("alice"), audience=APP).user_id == "alice"
    retired = HmacIdentityVerifier({"new": KEY_NEW})
    with pytest.raises(MemShieldIdentityError, match="unknown key"):
        retired.verify(old_token, audience=APP)


def test_short_keys_and_bad_claims_are_rejected() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        HmacIdentityVerifier({"k": b"short"})
    with pytest.raises(ValueError):
        _token("alice", compartments=("Bad,Name",))
    with pytest.raises(ValueError):
        _token("alice", clearance=9)


def test_bind_identity_is_scoped() -> None:
    assert current_identity_token() is None
    with bind_identity("t1"):
        assert current_identity_token() == "t1"
        with bind_identity("t2"):
            assert current_identity_token() == "t2"
        assert current_identity_token() == "t1"
    assert current_identity_token() is None


# ---------------------------------------------------------------- service behaviour
async def test_operations_refused_without_token(make_pool: Callable[..., ConnectionPool]) -> None:
    svc = _svc(make_pool())
    with pytest.raises(MemShieldIdentityError, match="no identity token"):
        await svc.search_memory(app_name=APP, user_id="alice", query="locker")
    with pytest.raises(MemShieldIdentityError):
        await svc.add_memory(app_name=APP, user_id="alice", memories=[_entry("x")])
    with pytest.raises(MemShieldIdentityError):
        await svc.delete_memory(app_name=APP, user_id="alice")


async def test_identity_comes_from_the_token(make_pool: Callable[..., ConnectionPool]) -> None:
    pool = make_pool()
    await _seed(pool)
    svc = _svc(pool)
    with bind_identity(_token("alice", "tenant_a")):
        resp = await svc.search_memory(app_name=APP, user_id="alice", query="locker")
    assert [m.content.parts[0].text for m in resp.memories] == ["alice note: locker 12"]
    ctx = svc.last_query_telemetry.session_context
    assert ctx["app.current_tenant_id"] == "tenant_a"  # not the config tenant


async def test_spoofed_user_id_under_valid_token(make_pool: Callable[..., ConnectionPool]) -> None:
    """S3 regression: a tool passes bob's id while alice's token is bound."""
    pool = make_pool()
    await _seed(pool)
    svc = _svc(pool)
    with bind_identity(_token("alice")):
        with pytest.raises(MemShieldIdentityError, match="does not match"):
            await svc.search_memory(app_name=APP, user_id="bob", query="locker")
        with pytest.raises(MemShieldIdentityError, match="does not match"):
            await svc.add_memory(app_name=APP, user_id="bob", memories=[_entry("planted for bob")])
        with pytest.raises(MemShieldIdentityError, match="does not match"):
            await svc.delete_memory(app_name=APP, user_id="bob")


async def test_token_for_other_app_is_refused(make_pool: Callable[..., ConnectionPool]) -> None:
    svc = _svc(make_pool())
    with bind_identity(_token("alice", aud="some_other_app")):
        with pytest.raises(MemShieldIdentityError, match="another application"):
            await svc.search_memory(app_name=APP, user_id="alice", query="locker")


async def test_concurrent_requests_with_different_tokens(make_pool: Callable[..., ConnectionPool]) -> None:
    pool = make_pool(max_size=3)
    await _seed(pool)
    svc = _svc(pool)

    async def request(user: str, tenant: str, expected: str) -> None:
        with bind_identity(_token(user, tenant)):
            await asyncio.sleep(0)
            resp = await svc.search_memory(app_name=APP, user_id=user, query="locker")
            assert [m.content.parts[0].text for m in resp.memories] == [expected]

    jobs = []
    for _ in range(30):
        jobs.append(request("alice", "tenant_a", "alice note: locker 12"))
        jobs.append(request("bob", "tenant_a", "bob note: locker 44"))
        jobs.append(request("carol", "tenant_b", "carol note: locker 90"))
    await asyncio.gather(*jobs)


async def test_verifier_exception_is_wrapped_without_token(make_pool: Callable[..., ConnectionPool]) -> None:
    class Exploding:
        def verify(self, token: str, *, audience: str) -> MemShieldIdentity:
            raise RuntimeError(f"boom {token}")

    svc = _svc(make_pool(), verifier=Exploding())
    with bind_identity("SECRET-TOKEN-VALUE"):
        with pytest.raises(MemShieldIdentityError) as exc:
            await svc.search_memory(app_name=APP, user_id="alice", query="x")
    assert "SECRET-TOKEN-VALUE" not in str(exc.value)
    assert exc.value.__cause__ is None


class _PreloadLlm(BaseLlm):
    model: str = "scripted"
    requests: list[LlmRequest] = []

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self.requests.append(llm_request)
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part.from_text(text="ok")]))


async def test_adk_runner_with_bound_identity(make_pool: Callable[..., ConnectionPool]) -> None:
    """preload_memory runs inside ADK; the token bound around run_async reaches it."""
    pool = make_pool()
    await _seed(pool)
    svc = _svc(pool)
    llm = _PreloadLlm()
    sessions = InMemorySessionService()
    runner = Runner(
        app_name=APP,
        agent=LlmAgent(name="a", model=llm, instruction="x", tools=[preload_memory_tool]),
        session_service=sessions,
        memory_service=svc,
    )
    session = await sessions.create_session(app_name=APP, user_id="alice")
    with bind_identity(_token("alice")):
        async for _ in runner.run_async(
            user_id="alice",
            session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part.from_text(text="my locker?")]),
        ):
            pass
    preloaded = "\n".join(p.text or "" for c in llm.requests[0].contents for p in (c.parts or []))
    assert "locker 12" in preloaded
    assert "locker 44" not in preloaded and "locker 90" not in preloaded


def _signed(payload: dict, key: bytes = KEY_NEW) -> str:
    import base64
    import hashlib
    import hmac
    import json

    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = hmac.new(key, body.encode(), hashlib.sha256).digest()
    return body + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


@pytest.mark.parametrize("exp", [float("nan"), float("inf"), "never", True])
def test_non_finite_or_invalid_expiry_is_refused(exp) -> None:
    payload = {"sub": "alice", "tenant": "tenant_a", "aud": APP, "kid": "new", "exp": exp}
    raw = _signed(payload).replace("NaN", "NaN").replace("Infinity", "Infinity")
    with pytest.raises(MemShieldIdentityError, match="expiry"):
        _verifier().verify(raw, audience=APP)


def test_overlong_lifetime_is_refused() -> None:
    import time as _time

    token = _signed({"sub": "alice", "tenant": "tenant_a", "aud": APP, "kid": "new",
                     "exp": int(_time.time()) + 30 * 86_400})
    with pytest.raises(MemShieldIdentityError, match="lifetime"):
        _verifier().verify(token, audience=APP)
    relaxed = HmacIdentityVerifier({"new": KEY_NEW}, max_ttl_seconds=31 * 86_400)
    assert relaxed.verify(token, audience=APP).user_id == "alice"


def test_rls_transaction_always_resolves_identity(make_pool: Callable[..., ConnectionPool]) -> None:
    """The public rls_transaction takes no pre-built identity: with a verifier it needs a token."""
    import inspect

    svc = _svc(make_pool())
    assert "identity" not in inspect.signature(svc.store.rls_transaction).parameters
    with pytest.raises(MemShieldIdentityError, match="no identity token"):
        with svc.rls_transaction(app_name=APP, user_id="alice"):
            pass
