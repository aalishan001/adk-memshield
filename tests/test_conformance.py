"""M6: one conformance suite over every way into memshield.

The same isolation cases run through the Google ADK service, the framework-neutral core
store and the MCP tools (with verified tokens). Every target shares ONE pooled connection,
so each case also exercises connection reuse across tenants and users.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import pytest
from conftest import APP_DSN, fake_embed
from google.adk.memory.memory_entry import MemoryEntry
from google.genai import types
from psycopg_pool import ConnectionPool

from adk_memshield import (
    HmacIdentityVerifier,
    MemoryRecord,
    MemShieldConfig,
    MemShieldMemoryService,
    MemShieldStore,
    issue_hmac_token,
)
from adk_memshield.adapters.mcp import MemShieldMcpTools

APP = "conformance_app"
KEY = b"c" * 32


@dataclass(frozen=True)
class Caller:
    tenant: str
    user: str
    clearance: int = 1
    compartments: tuple[str, ...] = ()


class Target(Protocol):
    async def add(self, who: Caller, text: str, *, shared: bool = False, min_clearance: int = 1,
                  tags: tuple[str, ...] = ()) -> None: ...

    async def search(self, who: Caller, query: str) -> list[tuple[str, str, str]]: ...


class AdkTarget:
    def __init__(self, pool: ConnectionPool, no_where: bool) -> None:
        self.pool, self.no_where = pool, no_where

    def _svc(self, who: Caller) -> MemShieldMemoryService:
        return MemShieldMemoryService(
            dsn=APP_DSN, tenant_id=who.tenant, agent_clearance=who.clearance,
            compartments=list(who.compartments), embed_fn=fake_embed, pool=self.pool,
            simulate_missing_app_filter=self.no_where, top_k=50,
        )

    async def add(self, who, text, *, shared=False, min_clearance=1, tags=()):
        meta: dict[str, Any] = {"scope": "tenant_shared" if shared else "private",
                                "min_clearance": min_clearance, "compartments": list(tags)}
        entry = MemoryEntry(content=types.Content(parts=[types.Part(text=text)], role="user"),
                            author="user", custom_metadata=meta)
        await self._svc(who).add_memory(app_name=APP, user_id=who.user, memories=[entry])

    async def search(self, who, query):
        resp = await self._svc(who).search_memory(app_name=APP, user_id=who.user, query=query)
        return [(m.custom_metadata["tenant_id"], m.custom_metadata["user_id"], m.content.parts[0].text)
                for m in resp.memories]


class CoreTarget:
    def __init__(self, pool: ConnectionPool, no_where: bool) -> None:
        self.pool, self.no_where = pool, no_where

    def _store(self, who: Caller) -> MemShieldStore:
        cfg = MemShieldConfig(dsn=APP_DSN, tenant_id=who.tenant, agent_clearance=who.clearance,
                              compartments=who.compartments, top_k=50,
                              simulate_missing_app_filter=self.no_where)
        return MemShieldStore(cfg, embed_fn=fake_embed, pool=self.pool)

    async def add(self, who, text, *, shared=False, min_clearance=1, tags=()):
        self._store(who).add(app_name=APP, user_id=who.user, records=[MemoryRecord(
            text=text, scope="tenant_shared" if shared else "private",
            min_clearance=min_clearance, compartments=tags)])

    async def search(self, who, query):
        return [(h.tenant_id, h.user_id, h.content)
                for h in self._store(who).search(app_name=APP, user_id=who.user, query=query)]


class McpTarget:
    """MCP tools over HTTP-style headers carrying verified HMAC tokens."""

    def __init__(self, pool: ConnectionPool, no_where: bool) -> None:
        cfg = MemShieldConfig(dsn=APP_DSN, top_k=50, simulate_missing_app_filter=no_where,
                              identity_verifier=HmacIdentityVerifier({"k": KEY}))
        self.tools = MemShieldMcpTools(MemShieldStore(cfg, embed_fn=fake_embed, pool=pool), app_name=APP,
                                       transport="http")

    @staticmethod
    def _headers(who: Caller) -> dict[str, str]:
        token = issue_hmac_token(KEY, kid="k", user_id=who.user, tenant_id=who.tenant, audience=APP,
                                 clearance=who.clearance, compartments=who.compartments)
        return {"Authorization": f"Bearer {token}"}

    async def add(self, who, text, *, shared=False, min_clearance=1, tags=()):
        await self.tools.remember(text, shared=shared, min_clearance=min_clearance,
                                  compartments=list(tags), headers=self._headers(who))

    async def search(self, who, query):
        rows = await self.tools.recall(query, top_k=50, headers=self._headers(who))
        return [(r["tenant"], r["owner"], r["text"]) for r in rows]


TARGETS = {
    "adk": AdkTarget,
    "adk-no-where": lambda pool: AdkTarget(pool, True),
    "core": CoreTarget,
    "core-no-where": lambda pool: CoreTarget(pool, True),
    "mcp": McpTarget,
    "mcp-no-where": lambda pool: McpTarget(pool, True),
}


@pytest.fixture(params=list(TARGETS))
def target(request: pytest.FixtureRequest, make_pool: Callable[..., ConnectionPool]) -> Target:
    factory = TARGETS[request.param]
    pool = make_pool()
    return factory(pool) if request.param.endswith("no-where") else factory(pool, False)


ALICE_A = Caller("tenant_a", "alice")
BOB_A = Caller("tenant_a", "bob")
ALICE_B = Caller("tenant_b", "alice")


async def test_cross_tenant(target: Target) -> None:
    await target.add(ALICE_A, "tenant A alice secret")
    await target.add(ALICE_B, "tenant B alice secret")
    assert {r[2] for r in await target.search(ALICE_A, "secret")} == {"tenant A alice secret"}
    assert {r[2] for r in await target.search(ALICE_B, "secret")} == {"tenant B alice secret"}


async def test_cross_user(target: Target) -> None:
    await target.add(BOB_A, "bob private medical note")
    await target.add(ALICE_A, "alice private note")
    assert await target.search(ALICE_A, "bob private medical note") == [
        ("tenant_a", "alice", "alice private note")
    ]


async def test_clearance(target: Target) -> None:
    exec_writer = Caller("tenant_a", "cfo", clearance=3)
    await target.add(exec_writer, "board memo L3", shared=True, min_clearance=3)
    await target.add(exec_writer, "public faq L1", shared=True, min_clearance=1)
    low = {r[2] for r in await target.search(Caller("tenant_a", "support", clearance=1), "memo")}
    high = {r[2] for r in await target.search(Caller("tenant_a", "support", clearance=3), "memo")}
    assert low == {"public faq L1"}
    assert high == {"public faq L1", "board memo L3"}


async def test_compartments(target: Target) -> None:
    hr_writer = Caller("tenant_a", "hrlead", compartments=("hr",))
    await target.add(hr_writer, "salary bands", shared=True, tags=("hr",))
    await target.add(hr_writer, "office hours", shared=True)
    finance = {r[2] for r in await target.search(Caller("tenant_a", "f", compartments=("finance",)), "x")}
    hr = {r[2] for r in await target.search(Caller("tenant_a", "h", compartments=("hr",)), "x")}
    assert finance == {"office hours"}
    assert hr == {"office hours", "salary bands"}


async def test_no_write_up_or_across(target: Target) -> None:
    import psycopg.errors

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        await target.add(Caller("tenant_a", "intern", clearance=1), "fake L3", shared=True, min_clearance=3)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        await target.add(Caller("tenant_a", "f", compartments=("finance",)), "fake hr", shared=True,
                         tags=("hr",))


async def test_fail_closed_on_the_shared_connection(target: Target, make_pool) -> None:
    """After every target has used the pooled connection, a context-free query sees nothing."""
    await target.add(ALICE_A, "alice row")
    await target.search(ALICE_A, "alice")
    pool: ConnectionPool = getattr(target, "pool", None) or target.tools.store.pool  # type: ignore[attr-defined]
    with pool.connection() as conn:
        assert conn.execute("SELECT count(*) FROM memories").fetchone()[0] == 0
