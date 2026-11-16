"""M1: prepared statements + HNSW must not silently collapse recall.

Reported and measured by Sunnatulla (dev.to): psycopg 3 prepares a statement after 5
executions on one connection; PostgreSQL may then cache a generic plan in which an HNSW
scan applies the RLS policy as a post-filter, so a caller with few visible rows gets an
empty result. adk-memshield binds ``plan_cache_mode = force_custom_plan`` in every RLS
transaction.

A single query per fresh connection always gets a custom plan and passes, so every test
here pins ONE connection and repeats the query.
"""

from __future__ import annotations

import importlib.util
import random
import sys
from collections.abc import Callable

import pytest
from conftest import ADMIN_DSN, APP_DSN, ROOT, fake_embed, with_db
from psycopg_pool import ConnectionPool

from adk_memshield import MemShieldMemoryService

APP = "plan_cache_app"


def _service(pool: ConnectionPool) -> MemShieldMemoryService:
    return MemShieldMemoryService(dsn=APP_DSN, tenant_id="tenant_a", embed_fn=fake_embed, pool=pool)


def test_plan_cache_mode_is_bound_per_transaction(make_pool: Callable[..., ConnectionPool]) -> None:
    # No reset callback: a session-scoped binding would survive and fail this test.
    pool = make_pool(reset=False)
    svc = _service(pool)
    with svc.rls_transaction(app_name=APP, user_id="alice") as cur:
        cur.execute("SELECT current_setting('plan_cache_mode'), pg_backend_pid()")
        mode, pid = cur.fetchone()
    assert mode == "force_custom_plan"
    # Transaction-local: gone once the transaction ends, on the same connection.
    with pool.connection() as conn:
        mode_after, pid_after = conn.execute(
            "SELECT current_setting('plan_cache_mode'), pg_backend_pid()"
        ).fetchone()
    assert pid_after == pid
    assert mode_after == "auto"


_PARAM_SQL = "SELECT count(*) FROM memories WHERE user_id = %s AND min_clearance <= %s"


def _plan_counts(pool: ConnectionPool, mode: str | None) -> tuple[int, int]:
    """Run a parameterised statement 12 times on one connection; return the prepared
    statement's (generic_plans, custom_plans) from pg_prepared_statements."""
    svc = _service(pool)
    if mode is not None:
        svc.store.plan_cache_mode = mode
    for _ in range(12):
        with svc.rls_transaction(app_name=APP, user_id="alice") as cur:
            cur.execute(_PARAM_SQL, ("alice", 3))
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT generic_plans, custom_plans FROM pg_prepared_statements"
            " WHERE statement LIKE 'SELECT count(*) FROM memories WHERE user_id = $1%'"
        ).fetchone()
    assert row is not None, "psycopg did not prepare the repeated statement"
    return int(row[0]), int(row[1])


def test_prepared_statements_never_use_a_generic_plan(make_pool: Callable[..., ConnectionPool]) -> None:
    """psycopg prepares the statement after 5 runs; every later execution is custom-planned."""
    generic, custom = _plan_counts(make_pool(), None)
    assert generic == 0
    assert custom >= 6


def test_prepared_statements_negative_control(make_pool: Callable[..., ConnectionPool]) -> None:
    """With the 0.1.x binding (auto) PostgreSQL switches to a generic plan: the test can fail."""
    generic, _ = _plan_counts(make_pool(), "auto")
    assert generic > 0


def test_override_reproduces_0_1_behaviour(make_pool: Callable[..., ConnectionPool]) -> None:
    """The class attribute that benchmarks and leak-arena override really changes the binding."""
    pool = make_pool()
    svc = _service(pool)
    svc.store.plan_cache_mode = "auto"
    with svc.rls_transaction(app_name=APP, user_id="alice") as cur:
        cur.execute("SELECT current_setting('plan_cache_mode')")
        assert cur.fetchone()[0] == "auto"


def _load_benchmark():
    path = ROOT / "benchmarks" / "plan_cache_hnsw.py"
    spec = importlib.util.spec_from_file_location("plan_cache_hnsw", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses in the module look themselves up here
    spec.loader.exec_module(module)
    return module


@pytest.mark.slow
def test_prepared_hnsw_recall_with_negative_control(temp_database: Callable[[], str]) -> None:
    """50,000 rows, HNSW, a light user with 30 visible rows, one pinned connection.

    0.2.0 returns complete results on every search; the negative control (the binding set
    back to ``auto``, i.e. 0.1.x) must collapse, or this test proves nothing.
    """
    bench = _load_benchmark()
    db = temp_database()
    bench.setup_database(ADMIN_DSN, db, 50_000, hnsw=True)
    bench_admin = with_db(ADMIN_DSN, db)
    app_dsn = with_db(APP_DSN, db)

    import psycopg

    with psycopg.connect(bench_admin) as conn:
        centres = [list(r[0]) for r in conn.execute("SELECT v FROM bench_centres ORDER BY k")]
    rng = random.Random(7)
    qvecs = [[c + rng.uniform(-bench.NOISE, bench.NOISE) for c in centres[i]] for i in range(5)]
    truths = {i: bench.ground_truth(bench_admin, "light", bench._lit(v)) for i, v in enumerate(qvecs)}

    fixed = bench.run_case(
        app_dsn, path="RLS only", user="light", plan_cache_mode="force_custom_plan",
        iterative_scan=False, qvecs=qvecs, repeats=3, truths=truths,
    )
    control = bench.run_case(
        app_dsn, path="RLS only", user="light", plan_cache_mode="auto",
        iterative_scan=False, qvecs=qvecs, repeats=3, truths=truths,
    )
    assert fixed.queries == 15
    assert fixed.counts == [10] * 15, fixed.counts
    assert fixed.recall == pytest.approx(1.0)
    assert control.empty > 0, f"negative control did not collapse: {control.counts}"
