"""Prepared statements + HNSW + RLS: recall with and without plan-cache pinning.

Reproduces the failure reported (and measured first) by Sunnatulla on dev.to: psycopg 3
prepares a statement after 5 executions on one connection; after 5 more, PostgreSQL may
cache a *generic* plan. For ``ORDER BY embedding <=> $1 LIMIT $2`` with an HNSW index that
generic plan is the HNSW scan with the whole RLS policy applied as a post-filter, so a
caller who can see only a few rows gets an empty result. Isolation holds; recall silently
collapses.

adk-memshield 0.2.0 binds ``plan_cache_mode = force_custom_plan`` in every RLS
transaction. This script measures recall@10 and latency for:

* ``0.1.x behaviour``: ``plan_cache_mode`` left at ``auto`` inside the transaction;
* ``0.2.0``: the default binding.

for a light user (30 visible rows in a large tenant) and a heavy user (most of the tenant
visible), on two query shapes:

* ``default search``: memshield's own search, whose application filter mirrors the policy;
* ``RLS only``: the same search with no ``WHERE`` clause (``simulate_missing_app_filter``),
  which is also the shape of custom SQL run on ``rls_transaction()``'s cursor.

All searches run on ONE pinned connection (a pool of size 1), each query repeated so the
plan cache has time to switch. Ground truth is an exact search (index scans off).

It creates its own database (``--db``, default ``memshield_bench_plan_cache``) on the
admin DSN and drops it afterwards unless ``--keep``; ``--reuse`` skips the load if that
database already exists.

    python benchmarks/plan_cache_hnsw.py --rows 100000
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import psycopg
from psycopg_pool import ConnectionPool

from adk_memshield import MemShieldMemoryService, reset_connection

ROOT = Path(__file__).resolve().parents[1]
DIM = 384
APP = "bench"
TOP_K = 10
CENTRES = 50
NOISE = 0.35


def _with_db(dsn: str, db: str) -> str:
    parsed = urlparse(dsn)
    return urlunparse(parsed._replace(path="/" + db))


def _lit(vec: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


def setup_database(admin_dsn: str, db: str, rows: int, hnsw: bool) -> dict[str, float]:
    timings: dict[str, float] = {}
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{db}"')
        conn.execute(f'CREATE DATABASE "{db}"')
    bench_admin = _with_db(admin_dsn, db)
    with psycopg.connect(bench_admin, autocommit=True) as conn:
        conn.execute((ROOT / "sql" / "01_schema.sql").read_text(encoding="utf-8"))
        conn.execute("SET maintenance_work_mem = '512MB'")
        # Serial build: a parallel HNSW build needs more /dev/shm than Docker's default 64 MB.
        conn.execute("SET max_parallel_maintenance_workers = 0")
        t0 = time.perf_counter()
        # Three equal tenants. In tenant t0 the heavy user owns ~90% of the rows, other
        # users own the rest; the light user owns 10 private rows and can also read 20
        # tenant_shared rows published by someone else.
        per_tenant = rows // 3
        # Embeddings are clustered (50 random centres plus noise), as real text embeddings
        # are; uniform random vectors would make any ANN index look broken on its own.
        conn.execute(
            "CREATE TABLE bench_centres AS SELECT k,"
            " (SELECT array_agg(random() * 2 - 1) FROM generate_series(1, %s) WHERE k >= 0) AS v"
            " FROM generate_series(0, %s) AS k",
            (DIM, CENTRES - 1),
        )
        row_vec = (
            "(SELECT array_agg(c.v[i] + (random() * 2 - 1) * %s ORDER BY i)::vector"
            " FROM generate_series(1, %s) AS i)"
        )
        conn.execute(
            f"""
            INSERT INTO memories (app_name, tenant_id, user_id, scope, min_clearance, content, embedding)
            SELECT %s,
                   't' || (g %% 3),
                   CASE WHEN g %% 3 = 0 AND (g / 3) < %s THEN 'heavy' ELSE 'user_' || (g %% 997) END,
                   'private', 1, 'synthetic row ' || g,
                   {row_vec}
            FROM generate_series(1, %s) AS g JOIN bench_centres c ON c.k = g %% {CENTRES}
            """,
            (APP, int(per_tenant * 0.9), NOISE, DIM, rows - 30),
        )
        conn.execute(
            f"""
            INSERT INTO memories (app_name, tenant_id, user_id, scope, min_clearance, content, embedding)
            SELECT %s, 't0',
                   CASE WHEN g <= 10 THEN 'light' ELSE 'publisher' END,
                   CASE WHEN g <= 10 THEN 'private' ELSE 'tenant_shared' END,
                   1, 'light-visible row ' || g,
                   {row_vec}
            FROM generate_series(1, 30) AS g JOIN bench_centres c ON c.k = g %% {CENTRES}
            """,
            (APP, NOISE, DIM),
        )
        timings["load_s"] = time.perf_counter() - t0
        if hnsw:
            t0 = time.perf_counter()
            conn.execute(
                "CREATE INDEX idx_memories_embedding_hnsw ON memories "
                "USING hnsw (embedding vector_cosine_ops)"
            )
            timings["hnsw_build_s"] = time.perf_counter() - t0
        conn.execute("ANALYZE memories")
    return timings


def ground_truth(bench_admin: str, user: str, qvec: str) -> list[str]:
    """Exact top-k of the rows the user may read (index scans disabled)."""
    with psycopg.connect(bench_admin) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL enable_indexscan = off")
            conn.execute("SET LOCAL enable_bitmapscan = off")
            rows = conn.execute(
                """
                SELECT id::text FROM memories
                WHERE app_name = %s AND tenant_id = 't0'
                  AND (user_id = %s OR (scope = 'tenant_shared' AND min_clearance <= 1
                       AND cardinality(compartments) = 0))
                ORDER BY embedding <=> %s::vector LIMIT %s
                """,
                (APP, user, qvec, TOP_K),
            ).fetchall()
    return [r[0] for r in rows]


@dataclass
class Result:
    path: str
    mode: str
    user: str
    iterative_scan: bool
    queries: int
    empty: int
    recall: float
    p50_ms: float
    p95_ms: float
    counts: list[int]


def run_case(
    app_dsn: str,
    *,
    path: str,
    user: str,
    plan_cache_mode: str,
    iterative_scan: bool,
    qvecs: list[list[float]],
    repeats: int,
    truths: dict[int, list[str]],
) -> Result:
    pool = ConnectionPool(app_dsn, min_size=1, max_size=1, open=True, reset=reset_connection)
    try:
        texts = {f"q{i}": v for i, v in enumerate(qvecs)}
        svc = MemShieldMemoryService(
            dsn=app_dsn,
            tenant_id="t0",
            agent_clearance=1,
            top_k=TOP_K,
            simulate_missing_app_filter=(path == "RLS only"),
            embed_fn=lambda batch: [texts[t] for t in batch],
            pool=pool,
        )
        svc.store.plan_cache_mode = plan_cache_mode
        recalls: list[float] = []
        lat: list[float] = []
        counts: list[int] = []
        for _ in range(repeats):
            for i in range(len(qvecs)):
                hits = svc.store.search(app_name=APP, user_id=user, query=f"q{i}")
                assert svc.last_query_telemetry is not None
                lat.append(svc.last_query_telemetry.latency_ms)
                truth = truths[i]
                counts.append(len(hits))
                recalls.append(len({h.id for h in hits} & set(truth)) / len(truth) if truth else 1.0)
        lat.sort()
        return Result(
            path=path,
            mode="0.2.0 force_custom_plan" if plan_cache_mode == "force_custom_plan" else "0.1.x auto",
            user=user,
            iterative_scan=iterative_scan,
            queries=len(counts),
            empty=sum(1 for c in counts if c == 0),
            recall=statistics.fmean(recalls),
            p50_ms=statistics.median(lat),
            p95_ms=lat[int(0.95 * (len(lat) - 1))],
            counts=counts,
        )
    finally:
        pool.close()


_DEFAULT_SQL = """SELECT id FROM memories
WHERE app_name = {p1} AND tenant_id = {p2}
  AND (user_id = {p3} OR (scope = 'tenant_shared' AND min_clearance <= {p4}
       AND (cardinality(compartments) = 0 OR compartments && {p5}::text[])))
ORDER BY embedding <=> {p6}::vector LIMIT {p7}"""
_RLS_ONLY_SQL = "SELECT id FROM memories ORDER BY embedding <=> {p6}::vector LIMIT {p7}"


def explain_plans(app_dsn: str, user: str, qvec: str) -> dict[str, str]:
    """EXPLAIN both query shapes as a custom plan and as PostgreSQL's generic plan."""
    out: dict[str, str] = {}
    literal = {
        "p1": f"'{APP}'",
        "p2": "'t0'",
        "p3": f"'{user}'",
        "p4": "1",
        "p5": "'{}'",
        "p6": f"'{qvec}'",
        "p7": TOP_K,
    }
    params = {f"p{i}": f"${i}" for i in range(1, 8)}
    rls_params = {"p6": "$1", "p7": "$2"}
    with psycopg.connect(app_dsn) as conn:
        with conn.transaction():
            conn.execute(
                "SELECT set_config('app.current_app_name', %s, true),"
                " set_config('app.current_tenant_id', 't0', true),"
                " set_config('app.current_user_id', %s, true),"
                " set_config('app.agent_clearance', '1', true),"
                " set_config('app.agent_compartments', '', true)",
                (APP, user),
            )
            for name, sql, gen in (
                ("default search", _DEFAULT_SQL, params),
                ("RLS only", _RLS_ONLY_SQL, rls_params),
            ):
                lines = conn.execute("EXPLAIN (COSTS OFF) " + sql.format(**literal)).fetchall()
                out[f"{name}: custom plan"] = "\n".join(r[0] for r in lines)
                try:
                    lines = conn.execute(
                        "EXPLAIN (GENERIC_PLAN, COSTS OFF) " + sql.format(**gen)
                    ).fetchall()
                    out[f"{name}: generic plan"] = "\n".join(r[0] for r in lines)
                except psycopg.Error as exc:  # PostgreSQL < 16
                    out[f"{name}: generic plan"] = f"(EXPLAIN GENERIC_PLAN unavailable: {exc.sqlstate})"
    # The query vector makes plans unreadable; elide it.
    return {k: re.sub(r"'\[[-0-9.,e]+\]'::vector", "'<query vector>'::vector", v) for k, v in out.items()}


def _db_exists(admin_dsn: str, db: str) -> bool:
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        row = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db,)).fetchone()
        return row is not None


def _set_iterative(bench_admin: str, db: str, on: bool) -> None:
    with psycopg.connect(bench_admin, autocommit=True) as conn:
        if on:
            conn.execute(
                f'ALTER ROLE memshield_app IN DATABASE "{db}" '
                "SET hnsw.iterative_scan = 'relaxed_order'"
            )
        else:
            conn.execute(f'ALTER ROLE memshield_app IN DATABASE "{db}" RESET hnsw.iterative_scan')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--queries", type=int, default=5, help="distinct query vectors")
    parser.add_argument("--repeats", type=int, default=10, help="times each query is repeated")
    parser.add_argument("--db", default="memshield_bench_plan_cache")
    parser.add_argument("--no-hnsw", action="store_true", help="control run without the index")
    parser.add_argument("--keep", action="store_true", help="keep the benchmark database")
    parser.add_argument("--reuse", action="store_true", help="reuse an existing benchmark database")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    logging.getLogger("adk_memshield").setLevel(logging.ERROR)
    admin_dsn = os.environ.get(
        "MEMSHIELD_ADMIN_DSN", "postgresql://postgres:postgres_admin_pass@localhost:54329/memshield"
    )
    app_base = os.environ.get(
        "MEMSHIELD_DB_DSN", "postgresql://memshield_app:memshield_pass@localhost:54329/memshield"
    )
    bench_admin = _with_db(admin_dsn, args.db)
    app_dsn = _with_db(app_base, args.db)

    if args.reuse and _db_exists(admin_dsn, args.db):
        timings: dict[str, float] = {}
    else:
        timings = setup_database(admin_dsn, args.db, args.rows, hnsw=not args.no_hnsw)
    try:
        _set_iterative(bench_admin, args.db, False)
        with psycopg.connect(bench_admin) as conn:
            server = conn.execute("SHOW server_version").fetchone()[0]
            pgvector = conn.execute(
                "SELECT extversion FROM pg_extension WHERE extname = 'vector'"
            ).fetchone()[0]
            counts = conn.execute(
                "SELECT count(*), count(*) FILTER (WHERE tenant_id = 't0'),"
                " count(*) FILTER (WHERE tenant_id = 't0' AND user_id = 'heavy') FROM memories"
            ).fetchone()
            has_hnsw = (
                conn.execute(
                    "SELECT count(*) FROM pg_indexes"
                    " WHERE tablename = 'memories' AND indexdef ILIKE '%%hnsw%%'"
                ).fetchone()[0]
                > 0
            )
            centres = [
                list(r[0]) for r in conn.execute("SELECT v FROM bench_centres ORDER BY k").fetchall()
            ]
        rng = random.Random(20261116)
        qvecs = [
            [c + rng.uniform(-NOISE, NOISE) for c in centres[i % CENTRES]]
            for i in range(args.queries)
        ]
        truths = {
            user: {i: ground_truth(bench_admin, user, _lit(v)) for i, v in enumerate(qvecs)}
            for user in ("light", "heavy")
        }
        results: list[Result] = []
        for path in ("default search", "RLS only"):
            for user in ("light", "heavy"):
                for mode in ("auto", "force_custom_plan"):
                    results.append(
                        run_case(
                            app_dsn,
                            path=path,
                            user=user,
                            plan_cache_mode=mode,
                            iterative_scan=False,
                            qvecs=qvecs,
                            repeats=args.repeats,
                            truths=truths[user],
                        )
                    )
        if has_hnsw:
            # pgvector iterative index scans, set as a role default in this database (it
            # survives memshield's RESET ALL on checkin).
            _set_iterative(bench_admin, args.db, True)
            for user in ("light", "heavy"):
                for mode in ("auto", "force_custom_plan"):
                    results.append(
                        run_case(
                            app_dsn,
                            path="RLS only",
                            user=user,
                            plan_cache_mode=mode,
                            iterative_scan=True,
                            qvecs=qvecs,
                            repeats=args.repeats,
                            truths=truths[user],
                        )
                    )
            _set_iterative(bench_admin, args.db, False)
        plans = explain_plans(app_dsn, "light", _lit(qvecs[0]))
    finally:
        if not args.keep:
            with psycopg.connect(admin_dsn, autocommit=True) as conn:
                conn.execute(f'DROP DATABASE IF EXISTS "{args.db}" WITH (FORCE)')

    meta = {
        "postgres": server,
        "pgvector": pgvector,
        "rows": counts[0],
        "tenant_t0_rows": counts[1],
        "heavy_user_rows": counts[2],
        "light_user_visible_rows": 30,
        "hnsw_index": has_hnsw,
        "top_k": TOP_K,
        "distinct_queries": args.queries,
        "repeats_per_query": args.repeats,
        "pool": "psycopg_pool.ConnectionPool(min_size=1, max_size=1), psycopg prepare_threshold=5",
        **{k: round(v, 1) for k, v in timings.items()},
    }
    if args.json:
        payload = {"meta": meta, "results": [r.__dict__ for r in results], "plans": plans}
        print(json.dumps(payload, indent=2))
        return 0

    print("# Plan cache + HNSW + RLS benchmark")
    for key, value in meta.items():
        print(f"{key}: {value}")
    print()
    print(
        "| Query shape | memshield | User | hnsw.iterative_scan | Searches | Empty | Recall@10 "
        "| p50 ms | p95 ms |"
    )
    print("| :--- | :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: |")
    for r in results:
        print(
            f"| {r.path} | {r.mode} | {r.user} | {'relaxed_order' if r.iterative_scan else 'off'} "
            f"| {r.queries} | {r.empty} | {r.recall:.2f} | {r.p50_ms:.1f} | {r.p95_ms:.1f} |"
        )
    print()
    print("## Rows returned per search, in order (one pinned connection)")
    for r in results:
        it = " + iterative" if r.iterative_scan else ""
        print(f"- {r.path} / {r.mode}{it} / {r.user}: {r.counts}")
    for name, plan in plans.items():
        print()
        print(f"## {name} (light user)")
        print(plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
