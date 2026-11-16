"""M2: pooled-connection hygiene.

"The policy can be correct while stale caller context survives on a reused connection."
Every test here runs on a pool of size 1 (or 2 for concurrency) so connection reuse is
guaranteed and checked by backend pid.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import psycopg
import psycopg.errors
import pytest
from conftest import ADMIN_DSN, APP_DSN, backend_pid, fake_embed
from google.adk.memory.memory_entry import MemoryEntry
from google.genai import types
from psycopg_pool import ConnectionPool

from adk_memshield import MemShieldMemoryService

APP = "pool_app"


def _entry(text: str) -> MemoryEntry:
    return MemoryEntry(content=types.Content(parts=[types.Part(text=text)], role="user"), author="user")


def _svc(pool: ConnectionPool, tenant: str) -> MemShieldMemoryService:
    return MemShieldMemoryService(dsn=APP_DSN, tenant_id=tenant, embed_fn=fake_embed, pool=pool)


async def _seed(pool: ConnectionPool) -> None:
    await _svc(pool, "tenant_a").add_memory(
        app_name=APP, user_id="alice", memories=[_entry("A secret: alpha-7731")]
    )
    await _svc(pool, "tenant_b").add_memory(
        app_name=APP, user_id="bob", memories=[_entry("B secret: bravo-1188")]
    )


def _raw_view(pool: ConnectionPool) -> tuple[str | None, str | None, str | None, int, int]:
    """What a context-free borrower of the pooled connection sees."""
    with pool.connection() as conn:
        return conn.execute(
            "SELECT current_setting('app.current_app_name', true),"
            " current_setting('app.current_tenant_id', true),"
            " current_setting('app.current_user_id', true),"
            " (SELECT count(*) FROM memories), pg_backend_pid()"
        ).fetchone()


async def test_rollback_leaves_no_context(make_pool: Callable[..., ConnectionPool]) -> None:
    # No reset callback: this proves the transaction-local binding on its own.
    pool = make_pool(reset=False)
    await _seed(pool)
    pid = backend_pid(pool)
    svc_a = _svc(pool, "tenant_a")

    with pytest.raises(RuntimeError):
        with svc_a.rls_transaction(app_name=APP, user_id="alice") as cur:
            cur.execute("SELECT count(*) FROM memories")
            assert cur.fetchone()[0] == 1
            raise RuntimeError("application error inside the transaction")

    app, tenant, user, visible, pid_after = _raw_view(pool)
    assert pid_after == pid
    assert (app or "", tenant or "", user or "") == ("", "", "")
    assert visible == 0


async def test_statement_timeout_then_other_tenant(make_pool: Callable[..., ConnectionPool]) -> None:
    # No reset callback: this proves the transaction-local binding on its own.
    pool = make_pool(reset=False)
    await _seed(pool)
    pid = backend_pid(pool)

    with pytest.raises(psycopg.errors.QueryCanceled):
        with _svc(pool, "tenant_a").rls_transaction(app_name=APP, user_id="alice") as cur:
            cur.execute("SET LOCAL statement_timeout = '50ms'")
            cur.execute("SELECT pg_sleep(1)")

    svc_b = _svc(pool, "tenant_b")
    resp = await svc_b.search_memory(app_name=APP, user_id="bob", query="secret")
    assert [m.custom_metadata["tenant_id"] for m in resp.memories] == ["tenant_b"]
    assert all("alpha" not in m.content.parts[0].text for m in resp.memories)
    assert svc_b.last_query_telemetry is not None
    assert svc_b.last_query_telemetry.session_context["app.current_user_id"] == "bob"

    _, tenant, user, visible, pid_after = _raw_view(pool)
    assert pid_after == pid
    assert (tenant or "", user or "", visible) == ("", "", 0)


async def test_server_killed_connection_is_replaced(make_pool: Callable[..., ConnectionPool]) -> None:
    # No reset callback: this proves the transaction-local binding on its own.
    pool = make_pool(reset=False)
    await _seed(pool)
    svc_a = _svc(pool, "tenant_a")

    with pytest.raises(psycopg.OperationalError):
        with svc_a.rls_transaction(app_name=APP, user_id="alice") as cur:
            cur.execute("SELECT pg_backend_pid()")
            victim = cur.fetchone()[0]
            with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
                admin.execute("SELECT pg_terminate_backend(%s)", (victim,))
            cur.execute("SELECT count(*) FROM memories")

    resp = await svc_a.search_memory(app_name=APP, user_id="alice", query="secret")
    assert [m.content.parts[0].text for m in resp.memories] == ["A secret: alpha-7731"]


def _session_scoped_bind(pool: ConnectionPool) -> int:
    """Custom SQL that wrongly binds alice's identity at SESSION scope (is_local => false).

    Returns the backend pid it ran on.
    """
    svc = _svc(pool, "tenant_a")
    with svc.rls_transaction(app_name=APP, user_id="alice") as cur:
        cur.execute(
            "SELECT set_config('app.current_app_name', %s, false),"
            " set_config('app.current_tenant_id', 'tenant_a', false),"
            " set_config('app.current_user_id', 'alice', false), pg_backend_pid()",
            (APP,),
        )
        return int(cur.fetchone()[3])


async def test_session_scoped_context_is_reset_on_checkin(
    make_pool: Callable[..., ConnectionPool],
) -> None:
    """memshield's pools run RESET ALL when a connection is returned.

    Same backend afterwards (the reset left the connection idle and the pool kept it), so
    the clean context really comes from the reset, not from a fresh connection.
    """
    pool = make_pool(reset=True)
    await _seed(pool)
    pid = _session_scoped_bind(pool)
    app, tenant, user, visible, pid_after = _raw_view(pool)
    assert (app or "", tenant or "", user or "", visible) == ("", "", "", 0)
    assert pid_after == pid
    assert pool.get_stats().get("returns_bad", 0) == 0


async def test_session_scoped_context_negative_control(
    make_pool: Callable[..., ConnectionPool],
) -> None:
    """Without the reset callback, a raw borrower inherits alice: the leak is real.

    memshield itself still rebinds every key locally, so its own next operation is correct.
    """
    pool = make_pool(reset=False)
    await _seed(pool)
    pid = _session_scoped_bind(pool)
    _, tenant, user, visible, pid_after = _raw_view(pool)
    assert pid_after == pid
    assert (tenant, user) == ("tenant_a", "alice")
    assert visible == 1  # a context-free query now reads alice's row

    resp = await _svc(pool, "tenant_b").search_memory(app_name=APP, user_id="bob", query="secret")
    assert [m.custom_metadata["user_id"] for m in resp.memories] == ["bob"]


async def test_concurrent_tenants_on_a_shared_pool(make_pool: Callable[..., ConnectionPool]) -> None:
    pool = make_pool(max_size=2)
    await _seed(pool)
    svc_a, svc_b = _svc(pool, "tenant_a"), _svc(pool, "tenant_b")

    async def one(svc: MemShieldMemoryService, user: str, tenant: str) -> None:
        resp = await svc.search_memory(app_name=APP, user_id=user, query="secret")
        assert [m.custom_metadata["tenant_id"] for m in resp.memories] == [tenant]

    tasks = []
    for i in range(60):
        tasks.append(one(svc_a, "alice", "tenant_a") if i % 2 else one(svc_b, "bob", "tenant_b"))
    await asyncio.gather(*tasks)


@pytest.mark.parametrize("reset", [True, False])
async def test_temp_table_cannot_shadow_memories(
    make_pool: Callable[..., ConnectionPool], reset: bool
) -> None:
    """A TEMP TABLE named memories, created on the yielded cursor, must not capture later
    writes or reads: the table is schema-qualified, and the reset callback drops temp tables."""
    pool = make_pool(reset=reset)
    await _seed(pool)
    svc_a = _svc(pool, "tenant_a")
    with svc_a.rls_transaction(app_name=APP, user_id="alice") as cur:
        cur.execute("CREATE TEMP TABLE memories (LIKE public.memories INCLUDING DEFAULTS)")
        cur.execute("SELECT pg_backend_pid()")
        pid = cur.fetchone()[0]

    # The store that already resolved its table keeps writing to the real table.
    await svc_a.add_memory(app_name=APP, user_id="alice", memories=[_entry("A second note")])
    svc_b = _svc(pool, "tenant_b")
    if reset:
        resp = await svc_b.search_memory(app_name=APP, user_id="bob", query="secret")
        assert [m.content.parts[0].text for m in resp.memories] == ["B secret: bravo-1188"]
    else:
        # Without the reset the temp table survives; a store resolving its table on this
        # connection refuses to run instead of using the shadow (fail closed).
        from adk_memshield import MemShieldConfigurationError

        with pytest.raises(MemShieldConfigurationError, match="temporary"):
            await svc_b.search_memory(app_name=APP, user_id="bob", query="secret")
    assert backend_pid(pool) == pid  # same connection throughout
    with psycopg.connect(ADMIN_DSN) as admin:
        stored = admin.execute(
            "SELECT count(*) FROM public.memories WHERE content = 'A second note'"
        ).fetchone()[0]
    assert stored == 1
    with pool.connection() as conn:
        temp_left = conn.execute("SELECT to_regclass('pg_temp.memories') IS NOT NULL").fetchone()[0]
    assert temp_left is (not reset)


async def test_set_role_is_reset_on_checkin(make_pool: Callable[..., ConnectionPool]) -> None:
    pool = make_pool(reset=True)
    with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
        admin.execute("DROP ROLE IF EXISTS memshield_pool_probe")
        admin.execute("CREATE ROLE memshield_pool_probe NOLOGIN")
        admin.execute("GRANT memshield_pool_probe TO memshield_app")
    try:
        with _svc(pool, "tenant_a").rls_transaction(app_name=APP, user_id="alice") as cur:
            cur.execute("SET SESSION ROLE memshield_pool_probe")
        with pool.connection() as conn:
            assert conn.execute("SELECT current_user").fetchone()[0] == "memshield_app"
    finally:
        pool.close()
        with psycopg.connect(ADMIN_DSN, autocommit=True) as admin:
            admin.execute("DROP ROLE IF EXISTS memshield_pool_probe")
