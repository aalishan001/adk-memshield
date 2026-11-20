# Scaling `adk-memshield`

Every claim below is marked **measured** (linked to a saved run), **designed for** (backed by the current implementation), or **not tested**.

## Measured

- **Row-Level Security transaction overhead (baseline 36–60 rows):**
  - Local Docker PostgreSQL 16 (live `gemini-3.1-flash-lite` run, 2026-11-19): net RLS SQL delta **p50 +0.25 ms** (1.51 ms unprotected vs 1.76 ms `adk-memshield`; S1 p50 +0.59 ms). Raw output: [`adk-leak-arena/benchmarks/runs/2026-11-19/eval-gemini.txt`](https://github.com/aalishan001/adk-leak-arena/blob/main/benchmarks/runs/2026-11-19/eval-gemini.txt).
  - Local Docker PostgreSQL 16 (`benchmarks/run_memleak_eval.py`, 60 rows): p50 overhead 0.00–0.16 ms across S1–S5 and Control. Raw output: [`benchmarks/runs/2026-11-16/memleak-eval-pg16.txt`](../benchmarks/runs/2026-11-16/memleak-eval-pg16.txt).
  - Cost of check-in pool reset (`RESET ALL; RESET ROLE; DISCARD TEMP`): measured at **0.58 ms** per checkout on local Docker (`benchmarks/pool_reset_cost.py`).
- **100,000 rows — HNSW + RLS prepared-statement plan-cache collapse and fix:**
  - Without plan pinning (`auto`), a prepared RLS-only HNSW search switched to a generic plan on execution 11 and returned **0 rows on 10 of 20 searches** (recall@10 dropped to **0.50**).
  - With `plan_cache_mode = force_custom_plan` (shipped in `adk-memshield` 0.2.0): **0/20 empty**, recall@10 **1.00** on PostgreSQL 16.15 and 17.12. Raw outputs: [`benchmarks/runs/2026-11-16/plan-cache-hnsw-pg16-100k.txt`](../benchmarks/runs/2026-11-16/plan-cache-hnsw-pg16-100k.txt), [`plan-cache-hnsw-pg17-100k.txt`](../benchmarks/runs/2026-11-16/plan-cache-hnsw-pg17-100k.txt).
- **100,000 rows — HNSW post-filter starvation and iterative scan fix:**
  - Under custom plans with HNSW and no iterative scan, a light caller (~1.5% visibility) got **20/20 empty results** (recall@10 **0.00**) on both RLS-only and unprotected app-`WHERE` queries (`hnsw.ef_search = 40` candidates all filtered out).
  - Enabling `hnsw.iterative_scan = relaxed_order` (pgvector 0.8+) restored **0/20 empty** and **1.00** recall@10 at **5.3–5.6 ms** p50. Raw outputs: `adk-leak-arena/benchmarks/runs/2026-11-16/prepared-100k-*`.
- **200,000 rows — One-row tenants and the shipped scope B-tree:**
  - Iterative scan alone hits `hnsw.max_scan_tuples` and memory limits on tiny tenants (**0/20** found when forced onto HNSW even at `max_scan_tuples = 250,000`).
  - Keeping the shipped B-tree `idx_memories_scope_lookup (app_name, tenant_id, user_id)` found **20/20** one-row tenants at **1.3–1.7 ms** p50 on PostgreSQL 16 and 17. Raw outputs: [`benchmarks/runs/2026-11-17/tiny-tenant-hnsw-pg16-200k.txt`](../benchmarks/runs/2026-11-17/tiny-tenant-hnsw-pg16-200k.txt), [`tiny-tenant-hnsw-pg17-200k.txt`](../benchmarks/runs/2026-11-17/tiny-tenant-hnsw-pg17-200k.txt).
- **Managed PostgreSQL 18 (AlloyDB Express, `asia-southeast1`, synthetic data):**
  - `adk-memshield` posture enforcement (`FORCE ROW LEVEL SECURITY` + `NOSUPERUSER NOBYPASSRLS` non-owner `memshield_app`) and `leak-arena eval` (39/40 unprotected leaks vs **0/40** on `adk-memshield`, **100.0%** recall) verified on AlloyDB Express PostgreSQL 18.4 (`vector 0.8.7.google-1`, `alloydb_scann 0.1.4`). 113 of 122 tests pass on AlloyDB Express (PG 18.4); the 9 failures are test fixtures that expect a true superuser, which AlloyDB doesn't hand out (0 product bugs). Raw outputs: [`benchmarks/runs/2026-11-19/pytest-alloydb-express.txt`](../benchmarks/runs/2026-11-19/pytest-alloydb-express.txt) and `adk-leak-arena/benchmarks/runs/2026-11-19/eval-alloydb-express.txt`.
  - **Region note:** The prototype and benchmarks run in `asia-southeast1` (Singapore) on synthetic data because AlloyDB Express is not yet available in Mumbai; production AlloyDB and Cloud Run run in `asia-south1` (Mumbai) for India DPDP data residency.
- **50,000 rows on AlloyDB Express (PG 18.4) — ScaNN vs HNSW vs shipped B-tree under RLS:**
  - **0 leaks** across all 20 configurations (B-tree, HNSW, ScaNN). ScaNN built 2.3x faster than HNSW (`16.28 s` for `num_leaves=223` vs `38.14 s`).
  - **Heavy user (~30k rows of 50k, `rls_only`):** ScaNN beat HNSW on both recall and speed: **0.890** recall@10 at **0.53–0.56 ms** server exec vs HNSW **0.820–0.850** at **0.79–0.91 ms** (exact shipped B-tree: **1.000** at **27.73 ms**).
  - **Light user (30 rows of 50k, `rls_only`):** shipped B-tree and HNSW (planner chose the B-tree) kept **1.000** recall@10 (`0/10` empty, `14.18–20.68 ms`). Default ScaNN (`scann.enable_inline_filtering = on`, `scann.enable_stable_recall = off`, `scann.num_leaves_to_search = 0`) picked `Custom Scan + Bitmap Index Scan(idx_memories_scope_lookup)` at `1.08–1.13 ms`, yet recall@10 dropped to **0.090** with **2/10 empty results** (identical `0.090` / `2/10` empty with `inline_filtering = off`). Tuning `scann.enable_stable_recall` / `num_leaves_to_search` is not yet benchmarked. Raw output: [`benchmarks/runs/2026-11-19/scann-vs-hnsw-alloydb-50k.txt`](../benchmarks/runs/2026-11-19/scann-vs-hnsw-alloydb-50k.txt).
- **Known measured limit (heavy user under HNSW):**
  - Recall@10 was **0.84** (PG 16) / **0.80** (PG 17) for a heavy user owning 30,000 of 100,000 rows under default HNSW parameters (`relaxed_order` kept it at 0.84). Tune `hnsw.ef_search` or partition very large tenants.

## Designed for (verified in code, not benchmarked at enterprise scale)

- **Transaction-mode connection pooling:** `MemShieldStore._transaction` (`src/adk_memshield/core.py`) opens an explicit transaction and binds all six session variables (`app.current_app_name`, `app.current_tenant_id`, `app.current_user_id`, `app.agent_clearance`, `app.agent_compartments`, `plan_cache_mode`) using `set_config(..., true)` (`SET LOCAL`), so PostgreSQL discards them automatically on `COMMIT` or `ROLLBACK`. When placed behind an external transaction-mode pooler (such as PgBouncer `pool_mode = transaction`), disable client-side prepared statements (`prepare_threshold=None`) or enable PgBouncer 1.21+ protocol-level prepared statement tracking.
- **Read-heavy scaling via read replicas / AlloyDB read pools:** Every `search_memory` call is read-only inside an explicit transaction (`SELECT set_config(..., true)` + `SELECT ... FROM memories`), so searches can route to PostgreSQL read replicas or AlloyDB read-pool instances without schema or policy changes.
- **Cell-based / dedicated instances for large enterprises:** Large regulated customers can be placed on dedicated Cloud SQL or AlloyDB instances (or list-partitioned `memories` tables by `tenant_id`) using the identical `adk-memshield` library and schema.
- **AlloyDB Express to production upgrade path:** AlloyDB Express supports an in-place upgrade to production AlloyDB (HA, read pools, DR) with no schema or RLS policy changes.

## Not tested

- **Multi-region deployments** and cross-region replication lag.
- **Single tenants above 1,000,000 rows** or list-partitioned `memories` tables at multi-million-row scale.
- **Horizontal sharding** across multiple independent PostgreSQL clusters.
- **Concurrent high-QPS production load** (the `adk-leak-arena` demo console itself is single-replica by design because run history lives in process memory; `adk-memshield` library instances are stateless apart from their connection pool).
