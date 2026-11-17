"""One-row tenants on a large table with an HNSW index: iterative scan vs the scope B-tree.

pgvector's iterative index scan (``hnsw.iterative_scan``) keeps fetching candidates until
``LIMIT`` rows pass the filter, but it stops after ``hnsw.max_scan_tuples`` (20,000 by
default). A tenant that owns one row in a large table can stay empty: reported and
measured by Sunnatulla (dev.to), who found that ``relaxed_order`` alone left about half of
the one-row tenants empty on a 200k-row table, and that a B-tree on the user key fixed it
because the planner then skips HNSW for tiny users.

This script measures that on memshield's own schema. It loads ``--rows`` rows (default
200,000) into three large tenants plus ``--tiny`` tenants that own exactly one row each,
builds an HNSW index, and searches every one-row tenant once per configuration:

* query shape: memshield's default search (application filter mirroring the policy) and
  "RLS only" (no WHERE clause, the shape of custom SQL on ``rls_transaction()``);
* ``hnsw.iterative_scan``: off or ``relaxed_order`` (role default, so it survives the
  pool's check-in reset);
* ``idx_memories_scope_lookup`` (the B-tree on ``app_name, tenant_id, user_id`` that
  memshield's schema ships): present or dropped;
* a diagnostic case with the B-tree dropped and ``enable_seqscan = off``, which forces the
  HNSW path so the ``hnsw.max_scan_tuples`` cap itself is measured (default and raised).

Each tenant's only row is the right answer, so recall per search is 0 or 1. The query
vectors sit near a cluster the tiny rows are not in, so the nearest neighbours in the whole
table belong to other tenants. It creates its own database (``--db``) on the admin DSN
and drops it afterwards unless ``--keep``.

    python benchmarks/tiny_tenant_hnsw.py --rows 200000
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import statistics
import sys
import time
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


def setup_database(admin_dsn: str, db: str, rows: int, tiny: int) -> dict[str, float]:
    timings: dict[str, float] = {}
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{db}"')
        conn.execute(f'CREATE DATABASE "{db}"')
    bench_admin = _with_db(admin_dsn, db)
    with psycopg.connect(bench_admin, autocommit=True) as conn:
        conn.execute((ROOT / "sql" / "01_schema.sql").read_text(encoding="utf-8"))
        conn.execute("SET maintenance_work_mem = '512MB'")
        conn.execute("SET max_parallel_maintenance_workers = 0")  # Docker's /dev/shm is small
        conn.execute("SELECT setseed(0.42)")
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
        t0 = time.perf_counter()
        # Large tenants: clustered embeddings over all centres, many users.
        conn.execute(
            f"""
            INSERT INTO memories (app_name, tenant_id, user_id, scope, min_clearance, content, embedding)
            SELECT %s, 't' || (g %% 3), 'user_' || (g %% 997), 'private', 1, 'synthetic row ' || g,
                   {row_vec}
            FROM generate_series(1, %s) AS g JOIN bench_centres c ON c.k = g %% {CENTRES}
            """,
            (APP, NOISE, DIM, rows - tiny),
        )
        # One-row tenants: each owns a single private row, all in centre 0.
        conn.execute(
            f"""
            INSERT INTO memories (app_name, tenant_id, user_id, scope, min_clearance, content, embedding)
            SELECT %s, 'tiny_' || lpad(g::text, 3, '0'), 'solo', 'private', 1, 'tiny tenant row ' || g,
                   {row_vec}
            FROM generate_series(1, %s) AS g JOIN bench_centres c ON c.k = 0
            """,
            (APP, NOISE, DIM, tiny),
        )
        timings["load_s"] = round(time.perf_counter() - t0, 1)
        t0 = time.perf_counter()
        conn.execute(
            "CREATE INDEX idx_memories_embedding_hnsw ON memories USING hnsw (embedding vector_cosine_ops)"
        )
        timings["hnsw_build_s"] = round(time.perf_counter() - t0, 1)
        conn.execute("ANALYZE memories")
    return timings


_ROLE_SETTINGS = ("hnsw.iterative_scan", "hnsw.max_scan_tuples", "enable_seqscan")


def _set_role_options(bench_admin: str, db: str, **settings: str) -> None:
    """Role defaults for the app role in this database (they survive the check-in reset)."""
    with psycopg.connect(bench_admin, autocommit=True) as conn:
        for name in _ROLE_SETTINGS:
            key = name.replace(".", "_")
            if key in settings:
                conn.execute(f"ALTER ROLE memshield_app IN DATABASE \"{db}\" SET {name} = '{settings[key]}'")
            else:
                conn.execute(f'ALTER ROLE memshield_app IN DATABASE "{db}" RESET {name}')


def _set_scope_index(bench_admin: str, present: bool) -> None:
    with psycopg.connect(bench_admin, autocommit=True) as conn:
        if present:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memories_scope_lookup ON memories (app_name, tenant_id, user_id)"
            )
        else:
            conn.execute("DROP INDEX IF EXISTS idx_memories_scope_lookup")
        conn.execute("ANALYZE memories")


def _scan_node(plan: dict) -> str:
    node = plan
    while True:
        kind = node.get("Node Type", "")
        if "Scan" in kind:
            return f"{kind} using {node['Index Name']}" if node.get("Index Name") else kind
        children = node.get("Plans") or []
        if not children:
            return kind
        node = children[0]


def run_config(app_dsn: str, tenants: list[str], qvec: list[float], *, rls_only: bool) -> dict:
    pool = ConnectionPool(app_dsn, min_size=1, max_size=1, open=True, reset=reset_connection)
    try:
        lat: list[float] = []
        found = 0
        plan = ""
        settings = ""
        for tenant in tenants:
            svc = MemShieldMemoryService(
                dsn=app_dsn, tenant_id=tenant, agent_clearance=1, top_k=TOP_K,
                simulate_missing_app_filter=rls_only, embed_fn=lambda batch: [qvec for _ in batch], pool=pool,
            )
            hits = svc.store.search(app_name=APP, user_id="solo", query="q")
            assert svc.last_query_telemetry is not None
            lat.append(svc.last_query_telemetry.latency_ms)
            found += 1 if any(h.tenant_id == tenant and h.user_id == "solo" for h in hits) else 0
            if not plan:
                with svc.rls_transaction(app_name=APP, user_id="solo") as cur:
                    settings = cur.execute(
                        "SELECT current_setting('hnsw.iterative_scan', true), current_setting('hnsw.max_scan_tuples', true),"
                        " current_setting('enable_seqscan')"
                    ).fetchone()
                    where = "" if rls_only else (
                        "WHERE app_name = %(a)s AND tenant_id = %(t)s AND (user_id = %(u)s OR (scope = 'tenant_shared' "
                        "AND min_clearance <= 1 AND (cardinality(compartments) = 0 OR compartments && '{}'::text[])))"
                    )
                    cur.execute(
                        f"EXPLAIN (FORMAT JSON) SELECT id FROM memories {where} "
                        "ORDER BY embedding <=> %(v)s::vector LIMIT %(k)s",
                        {"a": APP, "t": tenant, "u": "solo", "v": _lit(qvec), "k": TOP_K},
                    )
                    plan = _scan_node(cur.fetchone()[0][0]["Plan"])
        lat.sort()
        return {
            "searches": len(tenants),
            "found": found,
            "empty_or_missing": len(tenants) - found,
            "recall": round(found / len(tenants), 2),
            "plan": plan,
            "iterative_scan": settings[0] or "off",
            "max_scan_tuples": settings[1],
            "enable_seqscan": settings[2],
            "p50_ms": round(statistics.median(lat), 2),
            "p95_ms": round(lat[int(0.95 * (len(lat) - 1))], 2),
        }
    finally:
        pool.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rows", type=int, default=200_000)
    parser.add_argument("--tiny", type=int, default=20, help="number of one-row tenants")
    parser.add_argument("--db", default="memshield_bench_tiny_tenant")
    parser.add_argument("--keep", action="store_true")
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
    timings = setup_database(admin_dsn, args.db, args.rows, args.tiny)
    try:
        with psycopg.connect(bench_admin) as conn:
            server = conn.execute("SHOW server_version").fetchone()[0]
            pgvector = conn.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector'").fetchone()[0]
            total = conn.execute("SELECT count(*) FROM memories").fetchone()[0]
            centre = list(conn.execute("SELECT v FROM bench_centres WHERE k = 25").fetchone()[0])
        rng = random.Random(7)
        qvec = [x + rng.uniform(-NOISE, NOISE) for x in centre]  # near another cluster
        tenants = [f"tiny_{i:03d}" for i in range(1, args.tiny + 1)]
        results = []

        def measure(scope_index: bool, case: str, **settings: str) -> None:
            _set_role_options(bench_admin, args.db, **settings)
            for rls_only in (True, False):
                r = run_config(app_dsn, tenants, qvec, rls_only=rls_only)
                r.update(
                    case=case,
                    shape="RLS only" if rls_only else "default search",
                    scope_index="present" if scope_index else "dropped",
                )
                results.append(r)

        # 1. What the planner does on its own, with and without the shipped scope B-tree.
        for scope_index in (False, True):
            _set_scope_index(bench_admin, scope_index)
            measure(scope_index, "planner's choice")
            measure(scope_index, "planner's choice", hnsw_iterative_scan="relaxed_order")
        # 2. Diagnostic: no B-tree and sequential scans disabled, so the planner must use HNSW.
        #    This isolates the iterative scan's hnsw.max_scan_tuples cap (20,000 by default).
        _set_scope_index(bench_admin, False)
        measure(False, "HNSW forced", enable_seqscan="off")
        measure(False, "HNSW forced", enable_seqscan="off", hnsw_iterative_scan="relaxed_order")
        measure(False, "HNSW forced", enable_seqscan="off", hnsw_iterative_scan="relaxed_order",
                hnsw_max_scan_tuples=str(args.rows + 50_000))
        _set_role_options(bench_admin, args.db)
    finally:
        if not args.keep:
            with psycopg.connect(admin_dsn, autocommit=True) as conn:
                conn.execute(f'DROP DATABASE IF EXISTS "{args.db}" WITH (FORCE)')
    report = {
        "postgres": server, "pgvector": pgvector, "rows": total, "one_row_tenants": args.tiny,
        "top_k": TOP_K, "timings": timings, "results": results,
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print("# One-row tenants + HNSW: hnsw.iterative_scan vs idx_memories_scope_lookup")
    print(f"postgres {server}, pgvector {pgvector}, {total} rows, {args.tiny} one-row tenants, top_k {TOP_K}, "
          f"load {timings['load_s']} s, HNSW build {timings['hnsw_build_s']} s")
    print()
    print("| Case | Query shape | `idx_memories_scope_lookup` | `hnsw.iterative_scan` | `hnsw.max_scan_tuples` | One-row tenants found | Recall | Plan | p50 / p95 ms |")
    print("| :--- | :--- | :--- | :--- | ---: | ---: | ---: | :--- | ---: |")
    for r in results:
        case = r["case"] + (" (enable_seqscan off)" if r["enable_seqscan"] == "off" else "")
        print(f"| {case} | {r['shape']} | {r['scope_index']} | {r['iterative_scan']} | {r['max_scan_tuples']} | "
              f"{r['found']} / {r['searches']} | {r['recall']:.2f} | {r['plan']} | {r['p50_ms']} / {r['p95_ms']} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
