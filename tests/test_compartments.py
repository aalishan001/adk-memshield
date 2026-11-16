"""M5: compartments add horizontal access on top of clearance."""

from __future__ import annotations

from collections.abc import Callable

import psycopg
import psycopg.errors
import pytest
from conftest import ADMIN_DSN, APP_DSN, ROOT, apply_sql, fake_embed, with_db
from google.adk.memory.memory_entry import MemoryEntry
from google.genai import types
from psycopg_pool import ConnectionPool

from adk_memshield import MemShieldConfig, MemShieldMemoryService

APP = "compartment_app"


def _entry(text: str, **meta) -> MemoryEntry:
    return MemoryEntry(
        content=types.Content(parts=[types.Part(text=text)], role="user"),
        author="user",
        custom_metadata=dict(meta),
    )


def _svc(pool: ConnectionPool, *, compartments=(), clearance=1, dsn=APP_DSN, **kw) -> MemShieldMemoryService:
    return MemShieldMemoryService(
        dsn=dsn, tenant_id="acme", agent_clearance=clearance, compartments=list(compartments),
        embed_fn=fake_embed, pool=pool, **kw,
    )


async def _seed(pool: ConnectionPool) -> None:
    writer = _svc(pool, compartments=("finance", "hr", "legal"), clearance=3)
    await writer.add_memory(
        app_name=APP,
        user_id="publisher",
        memories=[
            _entry("untagged shared runbook", scope="tenant_shared", min_clearance=1),
            _entry("hr shared: salary bands", scope="tenant_shared", min_clearance=1, compartments=["hr"]),
            _entry("finance shared: q3 forecast", scope="tenant_shared", min_clearance=1,
                   compartments=["finance"]),
            _entry("legal+hr shared: dispute file", scope="tenant_shared", min_clearance=1,
                   compartments=["legal", "hr"]),
            _entry("finance shared but clearance 3", scope="tenant_shared", min_clearance=3,
                   compartments=["finance"]),
        ],
    )


async def _visible(svc: MemShieldMemoryService, user: str = "reader") -> set[str]:
    resp = await svc.search_memory(app_name=APP, user_id=user, query="shared")
    return {m.content.parts[0].text for m in resp.memories}


@pytest.mark.parametrize("simulate_missing_filter", [False, True])
async def test_compartment_read_rules(
    make_pool: Callable[..., ConnectionPool], simulate_missing_filter: bool
) -> None:
    """Same answers with the app filter and with RLS alone (no WHERE clause)."""
    pool = make_pool()
    await _seed(pool)
    kw = {"simulate_missing_app_filter": simulate_missing_filter, "top_k": 20}

    finance = await _visible(_svc(pool, compartments=["finance"], **kw))
    assert finance == {"untagged shared runbook", "finance shared: q3 forecast"}

    hr = await _visible(_svc(pool, compartments=["hr"], **kw))
    assert hr == {"untagged shared runbook", "hr shared: salary bands", "legal+hr shared: dispute file"}

    none = await _visible(_svc(pool, compartments=[], **kw))
    assert none == {"untagged shared runbook"}

    overlap = await _visible(_svc(pool, compartments=["legal", "finance"], clearance=3, **kw))
    assert overlap == {
        "untagged shared runbook",
        "finance shared: q3 forecast",
        "legal+hr shared: dispute file",
        "finance shared but clearance 3",
    }


async def test_own_rows_are_visible_whatever_their_compartments(
    make_pool: Callable[..., ConnectionPool],
) -> None:
    pool = make_pool()
    owner = _svc(pool, compartments=["hr"])
    await owner.add_memory(
        app_name=APP, user_id="dana",
        memories=[_entry("dana private hr note", compartments=["hr"]),
                  _entry("dana shared hr note", scope="tenant_shared", compartments=["hr"])],
    )
    # Dana later loses the hr compartment: her own rows stay readable to her.
    later = await _visible(_svc(pool, compartments=[], top_k=20), user="dana")
    assert later == {"dana private hr note", "dana shared hr note"}


async def test_write_across_is_rejected(make_pool: Callable[..., ConnectionPool]) -> None:
    pool = make_pool()
    finance = _svc(pool, compartments=["finance"])
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        await finance.add_memory(
            app_name=APP, user_id="eve",
            memories=[_entry("planted into hr", scope="tenant_shared", compartments=["hr"])],
        )
    # Re-tagging an existing own row across compartments is rejected too.
    await finance.add_memory(app_name=APP, user_id="eve", memories=[_entry("eve note")])
    with pytest.raises(psycopg.errors.InsufficientPrivilege) as exc:
        with finance.rls_transaction(app_name=APP, user_id="eve") as cur:
            cur.execute("UPDATE memories SET compartments = '{hr}' WHERE user_id = 'eve'")
    assert exc.value.sqlstate == "42501"


def test_compartment_names_are_validated() -> None:
    for bad in ["Finance", "a,b", "{x}", "", "x" * 65, "sp ace", "quo'te"]:
        with pytest.raises(ValueError):
            MemShieldConfig(compartments=[bad])
    assert MemShieldConfig(compartments=["hr", "finance", "hr"]).compartments == ("finance", "hr")


async def test_bad_compartment_in_metadata_is_rejected(make_pool: Callable[..., ConnectionPool]) -> None:
    svc = _svc(make_pool(), compartments=["hr"])
    with pytest.raises(ValueError, match="invalid compartment"):
        await svc.add_memory(app_name=APP, user_id="x", memories=[_entry("t", compartments=["hr,finance"])])


# ---------------------------------------------------------------- migration
_CATALOG_SQL = """
SELECT 'policy ' || policyname || ' ' || cmd || ' ' || permissive || ' ' || roles::text
       || ' USING ' || coalesce(qual, '-') || ' CHECK ' || coalesce(with_check, '-')
FROM pg_policies WHERE tablename = 'memories'
UNION ALL
SELECT 'column ' || attname || ' ' || format_type(atttypid, atttypmod) || ' notnull=' || attnotnull
       || ' default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), '-')
FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = 'memories'::regclass AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL SELECT 'index ' || indexdef FROM pg_indexes WHERE tablename = 'memories'
UNION ALL SELECT 'constraint ' || conname || ' ' || pg_get_constraintdef(oid)
FROM pg_constraint WHERE conrelid = 'memories'::regclass
UNION ALL SELECT 'rls ' || relrowsecurity || ' force ' || relforcerowsecurity
FROM pg_class WHERE oid = 'memories'::regclass
ORDER BY 1
"""


def _catalog(dsn: str) -> list[str]:
    with psycopg.connect(dsn) as conn:
        return [r[0] for r in conn.execute(_CATALOG_SQL).fetchall()]


async def test_migration_from_0_1_1(
    temp_database: Callable[[], str], make_pool: Callable[..., ConnectionPool]
) -> None:
    old_db, fresh_db = temp_database(), temp_database()
    old_admin = with_db(ADMIN_DSN, old_db)
    apply_sql(old_admin, ROOT / "tests" / "fixtures" / "schema_0_1_1.sql")
    with psycopg.connect(old_admin, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO memories (app_name, tenant_id, user_id, scope, min_clearance, content, embedding)"
            " SELECT %s, 'acme', CASE WHEN g = 1 THEN 'alice' ELSE 'bob' END,"
            "  CASE WHEN g = 3 THEN 'tenant_shared' ELSE 'private' END, 1, 'old row ' || g,"
            "  array_fill(0.1::real, array[384])::vector FROM generate_series(1, 3) g",
            (APP,),
        )

    migration = ROOT / "sql" / "migrations" / "0.1_to_0.2.sql"
    for _ in range(2):  # idempotent
        with psycopg.connect(old_admin) as conn:
            with conn.transaction():
                conn.execute(migration.read_text(encoding="utf-8"))

    apply_sql(with_db(ADMIN_DSN, fresh_db), ROOT / "sql" / "01_schema.sql")
    assert _catalog(old_admin) == _catalog(with_db(ADMIN_DSN, fresh_db))

    # Existing rows keep exactly their 0.1.x visibility.
    pool = make_pool(with_db(APP_DSN, old_db))
    alice = await _visible(_svc(pool, dsn=with_db(APP_DSN, old_db), top_k=10), user="alice")
    assert alice == {"old row 1", "old row 3"}
    with psycopg.connect(old_admin) as conn:
        assert conn.execute("SELECT DISTINCT compartments FROM memories").fetchall() == [([],)]


async def test_low_clearance_agent_cannot_declassify_owner_row(
    make_pool: Callable[..., ConnectionPool],
) -> None:
    """A shared row written by the owner's clearance-3 hr agent cannot be relabelled by a
    clearance-1 agent without hr acting for the same owner."""
    pool = make_pool()
    high = _svc(pool, compartments=["hr"], clearance=3)
    await high.add_memory(
        app_name=APP, user_id="owner",
        memories=[_entry("restructuring plan", scope="tenant_shared", min_clearance=3, compartments=["hr"])],
    )
    low = _svc(pool, compartments=[], clearance=1)
    with low.rls_transaction(app_name=APP, user_id="owner") as cur:
        cur.execute(
            "UPDATE memories SET min_clearance = 1, compartments = '{}' WHERE user_id = 'owner'"
        )
        assert cur.rowcount == 0
    with psycopg.connect(ADMIN_DSN) as conn:
        assert conn.execute("SELECT min_clearance, compartments FROM memories").fetchall() == [(3, ["hr"])]
    # The high-clearance agent may still edit its own row.
    with high.rls_transaction(app_name=APP, user_id="owner") as cur:
        cur.execute("UPDATE memories SET content = 'restructuring plan v2' WHERE user_id = 'owner'")
        assert cur.rowcount == 1
