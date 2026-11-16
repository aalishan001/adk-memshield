"""M3: refuse to run on a connection or table that cannot enforce RLS."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator

import psycopg
import pytest
from conftest import ADMIN_DSN, APP_DSN, fake_embed
from psycopg_pool import ConnectionPool

import adk_memshield.core as core
from adk_memshield import MemShieldConfigurationError, MemShieldMemoryService

APP = "posture_app"


def _svc(pool: ConnectionPool, **kwargs) -> MemShieldMemoryService:
    return MemShieldMemoryService(dsn=APP_DSN, tenant_id="t", embed_fn=fake_embed, pool=pool, **kwargs)


async def test_superuser_connection_is_refused(make_pool: Callable[..., ConnectionPool]) -> None:
    svc = _svc(make_pool(ADMIN_DSN))
    with pytest.raises(MemShieldConfigurationError, match="superuser"):
        await svc.search_memory(app_name=APP, user_id="alice", query="anything")
    with pytest.raises(MemShieldConfigurationError, match="superuser"):
        svc.verify_rls_posture()


def test_app_role_passes(make_pool: Callable[..., ConnectionPool]) -> None:
    report = _svc(make_pool()).verify_rls_posture()
    assert report.ok, report.problems
    assert report.role == "memshield_app"
    assert (report.rolsuper, report.rolbypassrls) == (False, False)
    assert (report.row_security, report.force_row_security) == (True, True)
    assert set(report.policies) == {"SELECT", "INSERT", "UPDATE", "DELETE"}


async def test_unprotected_table_is_refused(make_pool: Callable[..., ConnectionPool]) -> None:
    svc = _svc(make_pool(), table_name="memories_unprotected")
    with pytest.raises(MemShieldConfigurationError, match="row-level security"):
        await svc.search_memory(app_name=APP, user_id="alice", query="anything")


async def test_allow_insecure_role_warns_on_every_check(
    make_pool: Callable[..., ConnectionPool], caplog: pytest.LogCaptureFixture
) -> None:
    svc = _svc(make_pool(), table_name="memories_unprotected", allow_insecure_role=True)
    with caplog.at_level(logging.WARNING, logger="adk_memshield"):
        await svc.search_memory(app_name=APP, user_id="alice", query="a")
        await svc.search_memory(app_name=APP, user_id="alice", query="b")
    warnings = [r for r in caplog.records if "WITHOUT row-level security" in r.getMessage()]
    assert len(warnings) >= 2  # at least one per operation


@pytest.fixture
def scratch_table() -> Iterator[Callable[[str], str]]:
    """Create a copy of the memories table with custom RLS settings; dropped afterwards."""
    names: list[str] = []

    def factory(setup_sql: str) -> str:
        name = f"posture_scratch_{len(names)}"
        with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {name}")
            conn.execute(f"CREATE TABLE {name} (LIKE memories INCLUDING DEFAULTS INCLUDING CONSTRAINTS)")
            conn.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO memshield_app")
            conn.execute(setup_sql.format(table=name))
        names.append(name)
        return name

    yield factory
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        for name in names:
            conn.execute(f"DROP TABLE IF EXISTS {name}")


_POLICIES = """
CREATE POLICY s ON {table} FOR SELECT TO memshield_app
    USING (tenant_id = current_setting('app.current_tenant_id', true));
CREATE POLICY i ON {table} FOR INSERT TO memshield_app
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true));
CREATE POLICY u ON {table} FOR UPDATE TO memshield_app
    USING (tenant_id = current_setting('app.current_tenant_id', true));
CREATE POLICY d ON {table} FOR DELETE TO memshield_app
    USING (tenant_id = current_setting('app.current_tenant_id', true));
"""


def test_table_without_force_is_refused(
    make_pool: Callable[..., ConnectionPool], scratch_table: Callable[[str], str]
) -> None:
    table = scratch_table("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" + _POLICIES)
    with pytest.raises(MemShieldConfigurationError, match="FORCE"):
        _svc(make_pool(), table_name=table).verify_rls_posture()


def test_missing_policy_is_refused(
    make_pool: Callable[..., ConnectionPool], scratch_table: Callable[[str], str]
) -> None:
    table = scratch_table(
        "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"
        "CREATE POLICY s ON {table} FOR SELECT TO memshield_app"
        " USING (tenant_id = current_setting('app.current_tenant_id', true));"
    )
    with pytest.raises(MemShieldConfigurationError, match="INSERT, UPDATE, DELETE"):
        _svc(make_pool(), table_name=table).verify_rls_posture()


def test_widening_permissive_policy_is_refused(
    make_pool: Callable[..., ConnectionPool], scratch_table: Callable[[str], str]
) -> None:
    table = scratch_table(
        "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"
        + _POLICIES
        + "CREATE POLICY everyone ON {table} FOR SELECT TO memshield_app USING (true);"
    )
    with pytest.raises(MemShieldConfigurationError, match="widen access"):
        _svc(make_pool(), table_name=table).verify_rls_posture()


async def test_posture_checked_once_per_pool(
    make_pool: Callable[..., ConnectionPool], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []
    real = core.enforce_rls_posture

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(core, "enforce_rls_posture", counting)
    svc = _svc(make_pool())
    for q in ("a", "b", "c"):
        await svc.search_memory(app_name=APP, user_id="alice", query=q)
    assert len(calls) == 1


def test_construction_does_no_io() -> None:
    """Building the service (e.g. from a URI at import time) must not touch the database."""
    unopened = ConnectionPool("postgresql://nobody:nothing@127.0.0.1:1/none", open=False)
    svc = MemShieldMemoryService(dsn="postgresql://nobody:nothing@127.0.0.1:1/none", pool=unopened)
    assert svc.config.table_name == "memories"
    assert unopened.closed


_FORCED = "ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY;"


def test_owning_role_is_refused(
    make_pool: Callable[..., ConnectionPool], scratch_table: Callable[[str], str]
) -> None:
    table = scratch_table(_FORCED + _POLICIES + "ALTER TABLE {table} OWNER TO memshield_app;")
    with pytest.raises(MemShieldConfigurationError, match="owns table"):
        _svc(make_pool(), table_name=table).verify_rls_posture()


def test_widening_policy_granted_to_a_group_role_is_refused(
    make_pool: Callable[..., ConnectionPool], scratch_table: Callable[[str], str]
) -> None:
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        conn.execute("DROP ROLE IF EXISTS memshield_posture_group")
        conn.execute("CREATE ROLE memshield_posture_group NOLOGIN")
        conn.execute("GRANT memshield_posture_group TO memshield_app")
    try:
        table = scratch_table(
            _FORCED + _POLICIES
            + "CREATE POLICY grp ON {table} FOR SELECT TO memshield_posture_group USING (true);"
        )
        with pytest.raises(MemShieldConfigurationError, match="grp"):
            _svc(make_pool(), table_name=table).verify_rls_posture()
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
            conn.execute("DROP TABLE IF EXISTS posture_scratch_0")
            conn.execute("DROP ROLE IF EXISTS memshield_posture_group")


def test_update_policy_checking_tenant_only_in_with_check_is_refused(
    make_pool: Callable[..., ConnectionPool], scratch_table: Callable[[str], str]
) -> None:
    table = scratch_table(
        _FORCED
        + _POLICIES.replace(
            "CREATE POLICY u ON {table} FOR UPDATE TO memshield_app\n"
            "    USING (tenant_id = current_setting('app.current_tenant_id', true));",
            "CREATE POLICY u ON {table} FOR UPDATE TO memshield_app USING (true)"
            " WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true));",
        )
    )
    with pytest.raises(MemShieldConfigurationError, match="UPDATE"):
        _svc(make_pool(), table_name=table).verify_rls_posture()
