"""AlloyDB Express (PostgreSQL 18): ScaNN vs HNSW vs B-tree under Row-Level Security.

Creates a temporary database on MEMSHIELD_ADMIN_DSN, generates clustered 384-d vectors
server-side, and measures recall@10 (against exact ground truth), empty results, leaked
rows, plan choice, and server-side EXPLAIN ANALYZE execution time for:
  - light user (30 visible rows in tenant t0)
  - heavy user (~90% of tenant t0)
across:
  1. Shipped schema (B-tree idx_memories_scope_lookup, no ANN index)
  2. HNSW (hnsw.iterative_scan = off)
  3. HNSW (hnsw.iterative_scan = relaxed_order)
  4. ScaNN (alloydb_scann, default planner choice; inline filtering off & on)
  5. ScaNN forced (B-tree/seqscan disabled so ScaNN handles the RLS filter directly; inline filtering off & on)

Drops the temporary database on exit unless --keep is passed.
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import psycopg

ROOT = Path(__file__).resolve().parents[1]
DIM = 384
APP = "bench_scann"
TOP_K = 10
CENTRES = 50
NOISE = 0.35


def _with_db(dsn: str, db: str) -> str:
    parsed = urlparse(dsn)
    return urlunparse(parsed._replace(path="/" + db))


def _vec_lit(vec: list[float]) -> str:
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"


def setup_db(admin_dsn: str, db: str, rows: int) -> tuple[list[list[float]], dict[str, float]]:
    timings: dict[str, float] = {}
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{db}"')
    bench_admin = _with_db(admin_dsn, db)
    with psycopg.connect(bench_admin, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        conn.execute("CREATE EXTENSION IF NOT EXISTS alloydb_scann CASCADE")
        conn.execute(f'GRANT CONNECT ON DATABASE "{db}" TO memshield_app')
        conn.execute((ROOT / "sql" / "01_schema.sql").read_text(encoding="utf-8"))
        # On AlloyDB, postgres (alloydbsuperuser) has rolsuper=false, so FORCE RLS blocks
        # admin bulk seeding unless lifted temporarily for the synthetic load, then re-forced.
        conn.execute("ALTER TABLE memories NO FORCE ROW LEVEL SECURITY")
        conn.execute("SET maintenance_work_mem = '512MB'")

        t0 = time.perf_counter()
        per_tenant = rows // 3
        conn.execute(
            "CREATE TABLE bench_centres AS SELECT k, "
            "(SELECT array_agg(random() * 2 - 1) FROM generate_series(1, %s) WHERE k >= 0) AS v "
            "FROM generate_series(0, %s) AS k",
            (DIM, CENTRES - 1),
        )
        row_vec = (
            "(SELECT array_agg(c.v[i] + (random() * 2 - 1) * %s ORDER BY i)::vector "
            "FROM generate_series(1, %s) AS i)"
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
        timings["load_s"] = round(time.perf_counter() - t0, 2)
        conn.execute("ALTER TABLE memories FORCE ROW LEVEL SECURITY")
        forced = conn.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = to_regclass('memories')"
        ).fetchone()
        assert forced == (True, True), f"expected FORCE RLS, got {forced}"
        conn.execute("ANALYZE memories")

        # Sample 10 query vectors near random centres (deterministic RNG)
        centres = [r[0] for r in conn.execute("SELECT v FROM bench_centres ORDER BY k").fetchall()]
        rng = random.Random(20261119)
        queries = [
            [c + rng.uniform(-NOISE, NOISE) for c in centres[rng.randrange(len(centres))]]
            for _ in range(10)
        ]
    return queries, timings


def _run_query(
    conn: psycopg.Connection,
    *,
    user_id: str,
    qvec: str,
    rls_only: bool,
    session_sets: list[str],
) -> tuple[list[tuple[str, str, str, str]], float, str]:
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT set_config('app.current_app_name', %s, true),
                       set_config('app.current_tenant_id', 't0', true),
                       set_config('app.current_user_id', %s, true),
                       set_config('app.agent_clearance', '1', true),
                       set_config('app.agent_compartments', '', true),
                       set_config('plan_cache_mode', 'force_custom_plan', true)
                """,
                (APP, user_id),
            )
            for stmt in session_sets:
                cur.execute(stmt)
            where = (
                ""
                if rls_only
                else "WHERE app_name = %s AND tenant_id = 't0' AND (user_id = %s OR (scope = 'tenant_shared' AND min_clearance <= 1))"
            )
            sql = f"SELECT id::text, tenant_id, user_id, scope FROM memories {where} ORDER BY embedding <=> %s::vector LIMIT {TOP_K}"
            params = (qvec,) if rls_only else (APP, user_id, qvec)
            rows = cur.execute(sql, params).fetchall()
            plan_json = cur.execute(f"EXPLAIN (ANALYZE, FORMAT JSON) {sql}", params).fetchone()[0]
            exec_ms = float(plan_json[0]["Execution Time"])
            plan_str = _summarize_plan(plan_json[0]["Plan"])
            return rows, exec_ms, plan_str


def _summarize_plan(node: dict) -> str:
    scans: list[str] = []

    def walk(n: dict) -> None:
        nt = n.get("Node Type", "")
        idx = n.get("Index Name")
        if "Scan" in nt:
            scans.append(f"{nt}({idx})" if idx else nt)
        for ch in n.get("Plans") or ():
            walk(ch)

    walk(node)
    return " + ".join(scans) or node.get("Node Type", "unknown")


def _check_leaks(rows: list[tuple[str, str, str, str]], user_id: str) -> int:
    leaks = 0
    for _id, tenant, owner, scope in rows:
        if tenant != "t0":
            leaks += 1
        elif owner != user_id and scope != "tenant_shared":
            leaks += 1
    return leaks


def measure_config(
    app_dsn: str,
    queries: list[str],
    truth: dict[str, list[set[str]]],
    *,
    label: str,
    rls_only: bool,
    session_sets: list[str],
) -> list[dict]:
    results = []
    with psycopg.connect(app_dsn) as conn:
        for user_id in ("light", "heavy"):
            recalls: list[float] = []
            empties = 0
            leaks = 0
            times: list[float] = []
            plans: list[str] = []
            for qi, qvec in enumerate(queries):
                rows, exec_ms, plan = _run_query(
                    conn, user_id=user_id, qvec=qvec, rls_only=rls_only, session_sets=session_sets
                )
                got = {r[0] for r in rows}
                exp = truth[user_id][qi]
                recalls.append(len(got & exp) / max(1, len(exp)))
                if not rows:
                    empties += 1
                leaks += _check_leaks(rows, user_id)
                times.append(exec_ms)
                plans.append(plan)
            results.append(
                {
                    "config": label,
                    "shape": "rls_only" if rls_only else "default",
                    "user": user_id,
                    "recall_at_10": round(statistics.fmean(recalls), 3),
                    "empty": f"{empties}/{len(queries)}",
                    "leaks": leaks,
                    "p50_exec_ms": round(statistics.median(times), 2),
                    "plan": plans[0],
                }
            )
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=50000)
    ap.add_argument("--db", default="memshield_bench_scann")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    admin_dsn = os.environ["MEMSHIELD_ADMIN_DSN"]
    app_dsn = os.environ["MEMSHIELD_DB_DSN"]

    print(f"# AlloyDB Express ScaNN vs HNSW vs B-tree under RLS (rows={args.rows}, top_k={TOP_K}, queries=10)")
    queries_raw, timings = setup_db(admin_dsn, args.db, args.rows)
    queries = [_vec_lit(q) for q in queries_raw]
    bench_admin = _with_db(admin_dsn, args.db)
    bench_app = _with_db(app_dsn, args.db)

    try:
        with psycopg.connect(bench_admin, autocommit=True) as conn:
            ver = conn.execute("SELECT version()").fetchone()[0]
            exts = conn.execute(
                "SELECT extname, extversion FROM pg_extension WHERE extname IN ('vector','alloydb_scann') ORDER BY extname"
            ).fetchall()
            scann_gucs = conn.execute(
                "SELECT name, setting FROM pg_settings WHERE name LIKE 'scann.%' ORDER BY name"
            ).fetchall()
            print(f"# version: {ver}")
            print(f"# extensions: {exts}")
            print(f"# scann GUCs: {scann_gucs}")
            print(f"# load_s: {timings['load_s']}")

        # Exact ground truth (no ANN index, seqscan forced)
        truth: dict[str, list[set[str]]] = {"light": [], "heavy": []}
        with psycopg.connect(bench_app) as conn:
            for user_id in ("light", "heavy"):
                for qvec in queries:
                    rows, _, _ = _run_query(
                        conn, user_id=user_id, qvec=qvec, rls_only=True,
                        session_sets=["SET LOCAL enable_indexscan = off", "SET LOCAL enable_bitmapscan = off"],
                    )
                    truth[user_id].append({r[0] for r in rows})

        all_rows: list[dict] = []

        # 1. Shipped B-tree (no ANN index)
        for rls_only in (True, False):
            all_rows.extend(measure_config(bench_app, queries, truth, label="Shipped B-tree (no ANN)", rls_only=rls_only, session_sets=[]))

        # 2. HNSW index
        with psycopg.connect(bench_admin, autocommit=True) as conn:
            conn.execute("SET maintenance_work_mem = '512MB'")
            t0 = time.perf_counter()
            conn.execute("CREATE INDEX idx_bench_hnsw ON memories USING hnsw (embedding vector_cosine_ops)")
            hnsw_s = round(time.perf_counter() - t0, 2)
            conn.execute("ANALYZE memories")
            print(f"# hnsw_build_s: {hnsw_s}")

        for label, sets in (
            ("HNSW (iterative_scan=off)", []),
            ("HNSW (iterative_scan=relaxed_order)", ["SET LOCAL hnsw.iterative_scan = 'relaxed_order'"]),
            ("HNSW forced (iterative_scan=off)", ["SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"]),
            ("HNSW forced (iterative_scan=relaxed_order)", ["SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off", "SET LOCAL hnsw.iterative_scan = 'relaxed_order'"]),
        ):
            all_rows.extend(measure_config(bench_app, queries, truth, label=label, rls_only=True, session_sets=sets))

        # Drop HNSW, build ScaNN
        num_leaves = max(50, int(args.rows ** 0.5))
        with psycopg.connect(bench_admin, autocommit=True) as conn:
            conn.execute("DROP INDEX idx_bench_hnsw")
            conn.execute("SET maintenance_work_mem = '512MB'")
            t0 = time.perf_counter()
            conn.execute(
                f"CREATE INDEX idx_bench_scann ON memories USING scann (embedding cosine) WITH (num_leaves={num_leaves})"
            )
            scann_s = round(time.perf_counter() - t0, 2)
            conn.execute("ANALYZE memories")
            print(f"# scann_build_s (num_leaves={num_leaves}): {scann_s}")

        # Check which scann GUC names exist on this instance
        guc_names = {g[0] for g in scann_gucs}
        inline_guc = "scann.enable_inline_filtering" if "scann.enable_inline_filtering" in guc_names else None

        scann_configs: list[tuple[str, list[str]]] = [
            ("ScaNN (default planner)", []),
            ("ScaNN forced (inline_filtering=off)", ["SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off"] + (["SET LOCAL scann.enable_inline_filtering = off"] if inline_guc else [])),
        ]
        if inline_guc:
            scann_configs.append(("ScaNN (inline_filtering=on)", ["SET LOCAL scann.enable_inline_filtering = on"]))
            scann_configs.append(("ScaNN forced (inline_filtering=on)", ["SET LOCAL enable_seqscan = off", "SET LOCAL enable_bitmapscan = off", "SET LOCAL scann.enable_inline_filtering = on"]))

        for label, sets in scann_configs:
            all_rows.extend(measure_config(bench_app, queries, truth, label=label, rls_only=True, session_sets=sets))

        print("")
        print("| Configuration | Shape | User | Recall@10 | Empty | Leaks | p50 Server Exec | Plan |")
        print("| :--- | :--- | :--- | :---: | :---: | :---: | ---: | :--- |")
        for r in all_rows:
            print(
                f"| {r['config']} | {r['shape']} | {r['user']} | {r['recall_at_10']:.3f} | "
                f"{r['empty']} | {r['leaks']} | {r['p50_exec_ms']:.2f} ms | `{r['plan']}` |"
            )
    finally:
        if not args.keep:
            with psycopg.connect(admin_dsn, autocommit=True) as conn:
                conn.execute(f'DROP DATABASE IF EXISTS "{args.db}" WITH (FORCE)')
            print(f"\n# dropped temporary database {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
