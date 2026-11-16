# `adk-memshield`

**Zero-trust multi-tenant semantic memory for AI agents, enforced in the database by PostgreSQL `pgvector` + Row-Level Security (RLS). A drop-in memory service for Google ADK (`google-adk`), a framework-neutral core, and an MCP server.**

[![PyPI](https://img.shields.io/pypi/v/adk-memshield)](https://pypi.org/project/adk-memshield/)
[![Python](https://img.shields.io/pypi/pyversions/adk-memshield)](https://pypi.org/project/adk-memshield/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/aalishan001/adk-memshield/blob/main/LICENSE)
[![CI](https://github.com/aalishan001/adk-memshield/actions/workflows/ci.yml/badge.svg)](https://github.com/aalishan001/adk-memshield/actions/workflows/ci.yml)
[![Google ADK](https://img.shields.io/badge/google--adk-%3E%3D2.12-4285F4.svg)](https://github.com/google/adk-python)

---

## What changed in 0.2.0

- **0.2.1 (docs):** if you add an HNSW index, enable pgvector's iterative scan as a connection option; a filtered HNSW search can otherwise return nothing for callers who see little of a large table. See [ANN indexes and RLS](#ann-indexes-hnsw-and-rls).
- **Recall no longer collapses when a prepared statement switches to a generic plan** (prepared statements + an HNSW index). Every RLS transaction pins `plan_cache_mode = force_custom_plan`. Reported and measured by [Sunnatulla](https://dev.to/sunnatulla_dev/comment/3l7np); see [ANN indexes and RLS](#ann-indexes-hnsw-and-rls).
- **Pooled connections are tested** after rollbacks, statement timeouts, killed backends, session-scoped `set_config`, `SET ROLE` and temporary tables, and memshield's pools reset session settings, role and temp tables on check-in. The table is always used under its schema-qualified name.
- **Refuses to run unprotected.** On first use memshield checks that the role is not a superuser, has no `BYPASSRLS` and does not own the table, that the table has forced RLS, and that every command has a policy whose expressions check the tenant.
- **Verified identity (optional).** Bind a signed token per request (`HmacIdentityVerifier`, or `JwtIdentityVerifier` for OIDC/JWKS) and tenant, clearance and compartments come from the token, so one service instance can serve every tenant.
- **Compartments** add horizontal access (`hr`, `finance`, ...) on top of clearance.
- **Framework-neutral core** (`MemShieldStore`), an **MCP server** (`memshield-mcp`), and a `pre_write` hook that can only tighten or block.
- Upgrading from 0.1.x: [apply the migration](#upgrading-from-01x). The public ADK API is unchanged.

---

## Why `adk-memshield`?

Multi-tenant and multi-agent deployments often keep long-term semantic memory in one shared vector table, with isolation enforced only by the `WHERE` clause the application remembers to write. That design leaks in two well-documented ways:

1. **Cross-user semantic leakage**: *MemLeak: Cross-User Semantic Leakage in Multi-Tenant AI Agent Memory* ([arXiv:2610.04195](https://arxiv.org/abs/2610.04195)) shows that similarity search over a pooled store surfaces other users' memories without any exploit, and that hard ownership gating is the mitigation that consistently restores the clean baseline.
2. **Lateral leakage inside agent swarms**: *AgentLeak* ([arXiv:2602.11510](https://arxiv.org/abs/2602.11510)) shows that internal channels between agents are a major leakage path. `adk-memshield` addresses the memory-retrieval slice of that problem: a low-clearance sub-agent must not retrieve shared tenant memories labelled above its clearance.

`adk-memshield` moves ownership gating out of application code and into PostgreSQL, using **`FORCE ROW LEVEL SECURITY`** and **transaction-local identity (`set_config(..., true)`)**. A retrieval query with a missing or wrong filter returns only rows the caller is entitled to (their own, plus tenant-shared rows at or below their clearance and within their compartments), never anyone else's.

![adk-leak-arena console: the same no-WHERE query leaks cross-tenant rows from an unprotected table, while adk-memshield returns only rows the caller is entitled to](https://raw.githubusercontent.com/aalishan001/adk-leak-arena/main/docs/assets/console-overview.png)

*Live side-by-side comparison in the companion red-team console, [adk-leak-arena](https://github.com/aalishan001/adk-leak-arena) (`pip install adk-leak-arena`).*

---

## Architecture

```mermaid
flowchart LR
    subgraph Callers["Callers"]
        Agent["Google ADK Runner<br/>MemShieldMemoryService"]
        MCP["MCP client<br/>memshield-mcp"]
        App["Any Python app<br/>MemShieldStore"]
    end

    Core["MemShieldStore (core)<br/>identity: trusted config or verified token<br/>pre_write hook, embedder"]

    subgraph PG["PostgreSQL + pgvector (role memshield_app, NOSUPERUSER NOBYPASSRLS)"]
        Posture["Posture check (once per pool)<br/>role, FORCE RLS, policies"]
        Ctx["One statement per transaction<br/>set_config('app.*', val, true)<br/>set_config('plan_cache_mode', 'force_custom_plan', true)"]
        RLS["RLS policies<br/>SELECT / INSERT / UPDATE / DELETE"]
        Vec[("memories<br/>vector(384), compartments text[]")]
    end

    Agent --> Core
    MCP --> Core
    App --> Core
    Core --> Posture --> Ctx --> RLS --> Vec
```

### Security properties

- **No superuser bypass, checked at runtime.** Superusers and `BYPASSRLS` roles ignore RLS even under `FORCE ROW LEVEL SECURITY`. [`sql/01_schema.sql`](https://github.com/aalishan001/adk-memshield/blob/main/sql/01_schema.sql) creates a least-privilege `memshield_app` role (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`). Before the first operation on a pool, memshield reads `pg_roles`, `pg_class` and `pg_policy` and raises `MemShieldConfigurationError` if the role can bypass RLS, owns the table (or is a member of its owner role, so it could disable RLS), the table lacks forced RLS, a command has no policy, or a permissive policy that applies to the role (directly, through PUBLIC or through role membership) has a `USING` or `WITH CHECK` expression that never references `app.current_tenant_id`. This is a configuration check, not a proof that every policy is correct. Call `verify_rls_posture()` at startup to fail fast.
- **Pool-safe identity.** Every operation runs in an explicit transaction and binds `app.current_app_name`, `app.current_tenant_id`, `app.current_user_id`, `app.agent_clearance`, `app.agent_compartments` and `plan_cache_mode` in one `set_config(..., true)` statement. PostgreSQL discards them at commit or rollback. memshield's own pools also run `RESET ALL; RESET ROLE; DISCARD TEMP` when a connection is returned (measured at 0.58 ms per checkout, two round trips on local Docker), so session-scoped settings, a `SET ROLE` or a temporary table created by custom SQL cannot reach the next borrower. Advisory locks, `LISTEN` and `WITH HOLD` cursors are not reset: don't create them on the yielded cursor. The table is resolved once to its schema-qualified name (a temporary table can never shadow it; memshield refuses to run if the name resolves to one). All values are bound parameters; the only interpolated identifier (`table_name`) is validated against `^[A-Za-z_][A-Za-z0-9_]*$`.
- **Fail-closed.** Without identity context a query sees 0 rows. Identity columns carry `CHECK (<col> <> '')` because a pooled connection reports `''` (not `NULL`) for a custom setting once it has been used, and the service rejects empty `app_name`/`user_id` before touching the database.
- **All four commands are gated.** `SELECT` allows own rows plus `tenant_shared` rows with `min_clearance <= app.agent_clearance` that carry no compartments or share one with the caller. `INSERT` and `UPDATE` (`USING` + `WITH CHECK`) and `DELETE` (`USING`) are restricted to the caller's own rows, so cross-user poisoning or re-owning a row raises `InsufficientPrivilege`.
- **No write-up, no write-across.** An agent cannot write a `tenant_shared` memory labelled above its own clearance, or tag any memory with a compartment it does not hold.
- **Verified identity (optional).** With an `identity_verifier`, every operation needs a token bound with `bind_identity(token)`; the framework's `user_id` must equal the token subject, so a prompt-injected or buggy `user_id` argument is refused instead of trusted.
- **Defense in depth.** The library's own query mirrors the SELECT policy, so neither layer is a single point of failure. Ownership columns always come from the resolved identity, never from caller-supplied metadata.
- **Idempotent session ingestion.** ADK may call `add_session_to_memory` repeatedly for one session; a unique index on `(owner, session_id, event_id)` stores each event once.
- **Non-blocking.** Embedding and database I/O run in a worker thread (`asyncio.to_thread`), which inherits the caller's bound identity.

---

## Benchmark: unprotected `pgvector` vs. `adk-memshield`

[`benchmarks/run_memleak_eval.py`](https://github.com/aalishan001/adk-memshield/blob/main/benchmarks/run_memleak_eval.py) seeds a synthetic enterprise corpus (**3 tenants, 6 users, 60 memories**: API credentials, compensation, medical/HR records, query-shaped lure memories, and L3/L4 executive memos) into an ordinary table and into the RLS table. Each scenario runs **the same buggy application-layer SQL** against both, inside the same transaction-local identity of the authenticated caller, so the only variable is whether the database enforces ownership. `top_k=3`, 75 queries, 5 repeats. Raw output: [`benchmarks/runs/2026-11-16/memleak-eval-pg16.txt`](https://github.com/aalishan001/adk-memshield/blob/main/benchmarks/runs/2026-11-16/memleak-eval-pg16.txt) (PostgreSQL 16.15, pgvector 0.8.7).

| Scenario | Application-layer mistake | Queries | Unprotected: queries leaking | Unprotected: leaked share of top-k rows | Unprotected: leak at rank 1 | `adk-memshield`: queries leaking | Unprotected clean recall | `adk-memshield` clean recall |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Scenario 1: Shared-Tenant Pool (Incidental Overlap) | Filters `tenant_id` only, omits `user_id`/`scope` | 12 | 100.0% | 44.4% | 8.3% | **0.0%** | 100.0% | **100.0%** |
| Scenario 2: Adversarial Top-K Planted Lure | Same tenant-only filter; co-tenant plants query-shaped lures | 12 | 100.0% | 58.3% | 58.3% | **0.0%** | 100.0% | **100.0%** |
| Scenario 3: Tool-Argument `user_id` Override | Correct filter, but `user_id` taken from attacker-controlled tool args | 9 | 100.0% | 81.5% | 100.0% | **0.0%** | n/a | **n/a** |
| Scenario 4: Low-Clearance Swarm Agent (AgentLeak-style) | Own + `tenant_shared` rows, omits `min_clearance` check | 9 | 100.0% | 44.4% | 66.7% | **0.0%** | 100.0% | **100.0%** |
| Scenario 5: Total Filter Omission | No `WHERE` clause at all (`simulate_missing_app_filter=True`) | 33 | 100.0% | 74.7% | 69.7% | **0.0%** | 72.7% | **100.0%** |
| **Mean of Scenarios 1-5** | | 75 | **100.0%** | **60.7%** | **60.6%** | **0.0%** | **93.2%** | **100.0%** |
| Control: Correct App Filter (no bug) | `MemShieldMemoryService` default filter (user/scope/clearance) | 33 | 0.0% | 0.0% | 0.0% | **0.0%** | 100.0% | **100.0%** |

Retrieval latency (database transaction including `set_config`, 60 rows, ms):

| Scenario | Unprotected p50 / p95 | `adk-memshield` p50 / p95 |
| :--- | :---: | :---: |
| Scenario 1: Shared-Tenant Pool (Incidental Overlap) | 1.48 / 2.04 | 1.57 / 2.89 |
| Scenario 2: Adversarial Top-K Planted Lure | 1.48 / 2.05 | 1.61 / 2.26 |
| Scenario 3: Tool-Argument `user_id` Override | 1.53 / 1.95 | 1.60 / 2.57 |
| Scenario 4: Low-Clearance Swarm Agent (AgentLeak-style) | 1.63 / 2.21 | 1.63 / 2.39 |
| Scenario 5: Total Filter Omission | 1.15 / 1.53 | 1.15 / 1.58 |
| Control: Correct App Filter (no bug) | 1.29 / 1.87 | 1.45 / 2.00 |

**How to read this**

- **Leak rate is saturated by design of fixed top-k.** With no similarity floor, `LIMIT 3` always fills its slots. When a caller has fewer than three relevant rows of their own, a buggy filter fills the remainder with other people's rows, so every buggy query leaked at least one row. The *leaked share* and *rank-1* columns show how much of the retrieved context was unauthorized.
- **RLS removed every unauthorized row in every scenario**, while the identical buggy SQL leaked on the plain table. The control row confirms the leak classifier reports 0% when the application filter is correct.
- **Planted lures hijack rank 1, not recall.** Each Scenario 2 lure restates the target question followed by a short malicious payload (a white-box, PoisonedRAG-style attacker who knows the query wording). On the plain table a lure took rank 1 in 58.3% of queries. With RLS the lures are never retrieved.
- **Recall gains are modest and specific.** The recall gain appears under total filter omission (72.7% to 100%), where cross-tenant near-duplicates and lures crowd out the caller's own memories.
- **Scenario 3 has no authorized answer.** The queries are pure exfiltration attempts, so recall is n/a. RLS turns the attack into an own-rows-only result; with a verified identity token the spoofed `user_id` is refused outright.
- **Latency.** At 60 rows the RLS overhead is within run-to-run noise.
- The corpus and queries are synthetic and hand-written. Treat the numbers as a reproducible illustration of failure modes, not as an estimate of real-world leak rates.

The companion [adk-leak-arena](https://github.com/aalishan001/adk-leak-arena) runs a larger attack suite against live ADK agents; its numbers live in its own [BENCHMARKS.md](https://github.com/aalishan001/adk-leak-arena/blob/main/BENCHMARKS.md).

---

## ANN indexes (HNSW) and RLS

The schema ships without a vector index. If you add one (HNSW or IVFFlat), read this.

**What goes wrong without plan pinning.** psycopg 3 prepares a statement after 5 executions on the same connection (asyncpg prepares everything). After 5 more executions PostgreSQL may switch the prepared statement to a cached *generic* plan, and the generic plan sticks to that connection. For `ORDER BY embedding <=> $1 LIMIT $2` the generic plan can be the HNSW index scan with the whole RLS policy applied afterwards as a filter. HNSW hands back only `hnsw.ef_search` (default 40) candidates, so a caller who can see only a few rows of a large table gets an **empty** result. Nothing leaks; recall fails silently, which looks like "no memories yet". This was reported and measured first by [Sunnatulla](https://dev.to/sunnatulla_dev/comment/3l7np) on PostgreSQL 17 (100k rows, asyncpg and psycopg 3).

**What 0.2.0 does.** `rls_transaction` binds `set_config('plan_cache_mode', 'force_custom_plan', true)` in the same statement as the identity. It covers every parameterised statement in the transaction, including custom SQL on the yielded cursor, and it is checked at each execution, so a generic plan already cached on the connection is skipped. In a generic plan the query vector and the `LIMIT` are unknown parameters, so the planner can pick the HNSW scan with the RLS policy as a post-filter; a custom plan sees the actual vector and `LIMIT` on every execution. In this measurement the light user's custom plan is an exact parallel sequential scan plus sort. The price is re-planning on every execution.

**Measured** with [`benchmarks/plan_cache_hnsw.py`](https://github.com/aalishan001/adk-memshield/blob/main/benchmarks/plan_cache_hnsw.py): 100,000 rows in 3 tenants, clustered 384-d embeddings, HNSW (`vector_cosine_ops`, default build parameters), top 10, all 20 searches per row on **one** pinned connection (5 queries x 4 repeats). The light user sees 30 rows in a 33k-row tenant; the heavy user owns 30k of them. "RLS only" is the search with no `WHERE` clause, which is also the shape of custom SQL run under `rls_transaction()`. Recall is against an exact search.

| Query shape | Plan cache | User | `hnsw.iterative_scan` | Empty results (pg16 / pg17) | Recall@10 (pg16) | Recall@10 (pg17) |
| :--- | :--- | :--- | :--- | ---: | ---: | ---: |
| RLS only | 0.1.x (`auto`) | light | off | **10 / 10 of 20** | **0.50** | **0.50** |
| RLS only | **0.2.0 (`force_custom_plan`)** | light | off | 0 / 0 of 20 | **1.00** | **1.00** |
| RLS only | 0.1.x (`auto`) | light | `relaxed_order` | 0 / 0 of 20 | 0.85 | 0.84 |
| RLS only | 0.2.0 | light | `relaxed_order` | 0 / 0 of 20 | 1.00 | 1.00 |
| memshield's default search | 0.1.x and 0.2.0 | light | off | 0 / 0 of 20 | 1.00 | 1.00 |
| RLS only / default search | 0.1.x and 0.2.0 | heavy | off | 0 / 0 of 20 | 0.84 | 0.80 |
| RLS only | 0.2.0 | heavy | `relaxed_order` | 0 / 0 of 20 | 0.84 | 0.84 |

Raw output, plans and per-search row counts: [`plan-cache-hnsw-pg16-100k.txt`](https://github.com/aalishan001/adk-memshield/blob/main/benchmarks/runs/2026-11-16/plan-cache-hnsw-pg16-100k.txt) (PostgreSQL 16.15) and [`plan-cache-hnsw-pg17-100k.txt`](https://github.com/aalishan001/adk-memshield/blob/main/benchmarks/runs/2026-11-16/plan-cache-hnsw-pg17-100k.txt) (PostgreSQL 17.12), both pgvector 0.8.7. On one connection the light user's 0.1.x RLS-only searches return 10 rows for searches 1 to 10 and 0 rows from the 11th on.

**A second empty-results case: HNSW post-filtering under a custom plan.** Found while testing 0.2.0 with [adk-leak-arena](https://github.com/aalishan001/adk-leak-arena)'s prepared-connection mode (`leak-arena prepared`): 100,000 rows per table, a light caller who can read about 1.5% of them, a query whose nearest neighbours belong to other users, top 10, 20 executions on one pinned connection, recall against the exact answer. With an HNSW index the planner chose the index scan **under a custom plan, from the first execution**; the scan returned its 40 candidates (`hnsw.ef_search`) and the filter removed all 40. Plan pinning cannot help here. It happened with the RLS policy as the only filter and equally with an application `WHERE` clause on a table without RLS, so it is a property of filtered HNSW search, not of RLS. pgvector's iterative index scan fixed it:

| Table / query shape | Index | `hnsw.iterative_scan` | Empty results | Recall@10 | Plan (rows removed by filter) | p50 |
| :--- | :--- | :--- | ---: | ---: | :--- | ---: |
| memshield, RLS only | none | off | 0 of 20 | 1.00 | Bitmap Heap Scan (16,193) | 63.2 ms |
| memshield, RLS only | HNSW | off | **20 of 20** | **0.00** | HNSW Index Scan (40) | 1.7 ms |
| memshield, RLS only | HNSW | `relaxed_order` | 0 of 20 | 1.00 | HNSW Index Scan (412) | 5.3 ms |
| memshield, default search | HNSW | off | 0 of 20 | 1.00 | Bitmap Heap Scan (16,193) | 63.2 ms |
| plain pgvector table, app `WHERE` only | HNSW | off | **20 of 20** | **0.00** | HNSW Index Scan (40) | 1.4 ms |
| plain pgvector table, app `WHERE` only | HNSW | `relaxed_order` | 0 of 20 | 1.00 | HNSW Index Scan (427) | 5.6 ms |

PostgreSQL 16.15, pgvector 0.8.7, adk-memshield 0.2.0 from PyPI. Raw outputs: [`prepared-100k-exact`, `prepared-100k-hnsw` and `prepared-100k-hnsw-iterative`](https://github.com/aalishan001/adk-leak-arena/tree/main/benchmarks/runs/2026-11-16) (`.json`, `.log`, and the command in `.cmd`). memshield's default search got an exact bitmap plan here; that is the planner's choice for this data, not a guarantee.

**Recommendation: whenever you add an HNSW index, turn on pgvector's iterative scan** (pgvector 0.8+) for the role memshield connects as, so a filtered scan keeps fetching candidates until `LIMIT` rows pass the filter (or `hnsw.max_scan_tuples` is reached). Set it where the pool's `RESET ALL` on check-in keeps it: as a **connection startup option** in the DSN, or as a role default.

```text
postgresql://memshield_app:...@host:5432/db?options=-c%20hnsw.iterative_scan%3Drelaxed_order
```

```sql
ALTER ROLE memshield_app IN DATABASE mydb SET hnsw.iterative_scan = 'relaxed_order';
```

A plain `SET` in your own code does not survive check-in (`tests/test_pool_hygiene.py::test_startup_options_survive_the_checkin_reset` covers both). `relaxed_order` can return rows slightly out of exact distance order; use `strict_order` if you need exact order, or sort the hits by `similarity`. 0.2.1 does not set this for you: it changes query results and ordering on every connection of the pool, needs pgvector 0.8, and is better chosen per deployment. Measure recall at your own scale either way.

**Remaining guidance.**

- The pin stops the switch to a generic plan; it does not stop HNSW post-filtering (see the second case above). A custom plan can still be an HNSW scan with the policy applied afterwards: on PostgreSQL 17 the heavy user still got 9 rows instead of 10 on 8 of 20 searches with the pin, and callers with mid-range visibility (not measured here) can get fewer than `top_k` rows. For the light user the pin restores recall because the planner chooses an exact scan, whose cost grows with the table (RLS-only light p50 42.4 ms pinned vs 21.0 ms unpinned on pg16).

- memshield's own search was **not** affected in this measurement: its application filter (`user_id = $3 ...`) keeps the generic plan off the HNSW index. Custom SQL under `rls_transaction()` and the `simulate_missing_app_filter` path were affected. 0.2.0 pins the plan for all of them.
- The heavy user's recall below 1.0 is HNSW's approximation plus the RLS/application filter applied after the index returns `hnsw.ef_search` candidates. Iterative scans (above) and a larger `hnsw.ef_search` help here too; in the plan-cache benchmark `relaxed_order` kept the heavy user at 0.84.
- For very large tenants, consider list-partitioning `memories` by tenant so each tenant's index holds only its own rows.
- Benchmark recall at your own scale before relying on an ANN index.

---

## Threat model & limitations

- **What RLS protects against:** bugs and omissions in application retrieval SQL, prompt-injected tool arguments, and cross-user writes, all *while the service binds the correct identity*. With an identity verifier, a wrong or spoofed `user_id` from the application or a tool argument is refused before it reaches the database.
- **What it does not protect against:** a compromised application process. `memshield_app` can call `set_config` itself, so code holding the database credentials can claim any identity; code holding both the credentials and the token signing key can mint any identity. Keep identity binding inside this service and keep credentials and keys out of agent-reachable code paths.
- **Trusted caller mode (no verifier) takes tenant, clearance and compartments from the service config.** ADK's `search_memory` receives only `app_name`/`user_id`, so in that mode run one service instance per tenant/clearance tier (or per Runner). With a verifier they come from the token and one instance serves everyone.
- **Owners read their own rows at any label.** The SELECT policy lets a caller read every row it owns, whatever its clearance or compartments; a low-clearance agent acting for a user can read that user's high-clearance shared rows. It cannot relabel them: `UPDATE` only touches shared rows labelled within the agent's own clearance and compartments. If agents of different clearance act for the same user, give them different user ids.
- **Labels can come from the model.** `scope`, `min_clearance` and `compartments` arrive in memory metadata, `session.state` or the MCP `remember(shared=...)` argument. A prompt injection can ask to publish a memory tenant-wide (always within the writer's own clearance and compartments). Use a `pre_write` hook to enforce your own labelling policy.
- **`tenant_shared` content is trusted by design.** A user may publish a `tenant_shared` memory at or below their own clearance and within their compartments, and every agent entitled to read it will retrieve it. RLS enforces *who may read*, not whether the content is benign. The `pre_write` hook is the seam for a content check (it may only tighten or block).
- **ANN indexes:** see [ANN indexes (HNSW) and RLS](#ann-indexes-hnsw-and-rls).
- **Your own pool:** if you pass `pool=`, create it with `reset=adk_memshield.reset_connection`, or session state left by custom SQL could reach the next raw borrower of that connection (memshield itself always rebinds every key and uses the schema-qualified table).
- **JWT issuers:** `JwtIdentityVerifier` requires `issuer=`. A JWKS shared by many issuers (multi-tenant Entra ID, the Firebase key set) would otherwise accept tokens minted for another tenant or project. Prefer an `audience` your identity provider owns over the ADK app name.
- **MCP transport** is fixed when the server is built: the HTTP transport takes identity only from the `Authorization` header and refuses a call without one; stdio ignores headers.
- `sql/02_benchmark_baseline.sql` creates an intentionally unprotected table for tests and benchmarks. **Do not apply it in production.** memshield refuses to use it unless `allow_insecure_role=True`, which logs a warning on every use.

---

## Installation

```bash
pip install adk-memshield
```

Optional extras: `adk-memshield[jwt]` (OIDC / JWT identity tokens via PyJWT) and `adk-memshield[mcp]` (the MCP server).

From source, for development:

```bash
pip install -e ".[dev]"
```

---

## Quickstart

### 1. Apply the schema

Apply [`sql/01_schema.sql`](https://github.com/aalishan001/adk-memshield/blob/main/sql/01_schema.sql) as a superuser/owner, then rotate the `memshield_app` password. The file also ships inside the wheel:

```python
from importlib.resources import files

schema_sql = (files("adk_memshield") / "sql" / "01_schema.sql").read_text()
```

For local development, start the bundled Postgres on port `54329`:

```bash
docker compose -p adk-memshield up -d db
```

### 2. Wire it into an ADK `Runner`

```python
from google.adk.agents.llm_agent import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.load_memory_tool import load_memory_tool
from google.adk.tools.preload_memory_tool import preload_memory_tool

from adk_memshield import MemShieldConfig, MemShieldMemoryService

memory_service = MemShieldMemoryService(
    MemShieldConfig(
        dsn="postgresql://memshield_app:memshield_pass@localhost:54329/memshield",
        tenant_id="tenant_alpha",
        agent_clearance=2,
        compartments=["finance"],
    )
)
memory_service.verify_rls_posture()  # optional: fail fast at startup

runner = Runner(
    app_name="finance_copilot",
    agent=LlmAgent(
        name="assistant",
        model="gemini-3.8-flash",
        tools=[preload_memory_tool, load_memory_tool],
    ),
    session_service=InMemorySessionService(),
    memory_service=memory_service,
)
# ADK's memory tools call memory_service.search_memory(app_name=..., user_id=...) with the
# Runner's own identity; persist a finished session with:
#   await memory_service.add_session_to_memory(session)
```

### 3. Verified identity: one service for every tenant

```python
from adk_memshield import HmacIdentityVerifier, MemShieldMemoryService, bind_identity

verifier = HmacIdentityVerifier({"2026-11": KEY_BYTES})  # keep old keys during rotation
memory_service = MemShieldMemoryService(dsn=APP_DSN, identity_verifier=verifier)

# In your auth layer, once per request (the token is minted by your login service):
token = verifier.issue(kid="2026-11", user_id="alice", tenant_id="tenant_alpha",
                       audience="finance_copilot", clearance=2, compartments=["finance"])

with bind_identity(token):
    async for event in runner.run_async(user_id="alice", session_id=sid, new_message=msg):
        ...
```

With `JwtIdentityVerifier(jwks_url=..., issuer=...)` (`adk-memshield[jwt]`), the token can come from Firebase Auth, Google Cloud Identity Platform or any OIDC provider; tenant, clearance and compartments are read from the `tenant`, `clearance` and `compartments` claims (configurable). No token, an invalid or expired token, a token for another `app_name`, or an ADK `user_id` that differs from the token subject raises `MemShieldIdentityError`. Tokens are never logged.

### 4. Write and search memories directly

```python
from google.adk.memory.memory_entry import MemoryEntry
from google.genai import types

await memory_service.add_memory(
    app_name="finance_copilot",
    user_id="alice",
    memories=[
        MemoryEntry(
            content=types.Content(parts=[types.Part(text="Wire routing code is SWIFT-ALPHA-99.")]),
            custom_metadata={"scope": "private"},
        ),
        # Readable by tenant agents with clearance >= 2 that hold the finance compartment.
        MemoryEntry(
            content=types.Content(parts=[types.Part(text="Treasury approval threshold is $250k.")]),
            custom_metadata={"scope": "tenant_shared", "min_clearance": 2, "compartments": ["finance"]},
        ),
    ],
)

response = await memory_service.search_memory(
    app_name="finance_copilot", user_id="alice", query="What is my wire routing code?"
)
print(memory_service.last_query_telemetry.to_dict())  # SQL, bound context, latency, rows
```

Compartment names match `^[a-z0-9_-]{1,64}$`. A `tenant_shared` row with no compartments is readable by every entitled agent in the tenant; with compartments, by agents that hold at least one of them. Owners always read their own rows.

### 5. Run custom SQL under the caller's RLS identity

```python
with memory_service.rls_transaction(app_name="finance_copilot", user_id="alice") as cur:
    cur.execute("SELECT content FROM memories ORDER BY created_at DESC LIMIT 10")
    rows = cur.fetchall()  # only rows alice may read, even though the SQL has no WHERE clause
```

### 6. Without ADK: the core store

```python
from adk_memshield import MemoryRecord, MemShieldConfig, MemShieldStore

store = MemShieldStore(MemShieldConfig(dsn=APP_DSN, tenant_id="tenant_alpha"))
store.add(app_name="notes", user_id="alice", records=[MemoryRecord(text="Parking bay 4")])
hits = store.search(app_name="notes", user_id="alice", query="where do I park?")
```

### 7. MCP server

```bash
pip install "adk-memshield[mcp]"
# stdio, one trusted local user:
memshield-mcp --transport stdio --app notes --user alice --tenant tenant_alpha
# streamable HTTP: needs a verifier; clients send Authorization: Bearer <identity token>
MEMSHIELD_HMAC_KEYS='{"2026-11": "<32+ byte secret>"}' memshield-mcp --transport http --app notes
```

Tools: `remember`, `recall`, `forget`. The HTTP transport refuses to start without a verifier and refuses any request without a valid token. In code: `adk_memshield.adapters.mcp.create_mcp_server(store, app_name=...)`.

### 8. `pre_write` hook

```python
from adk_memshield import Allow, Block, Downlabel

def guard(identity, pending):
    if "ignore previous instructions" in pending.text.lower():
        return Block("prompt-injection pattern")
    if "salary" in pending.text.lower() and pending.scope == "tenant_shared":
        return Downlabel(scope="private")
    return Allow()

memory_service = MemShieldMemoryService(dsn=APP_DSN, tenant_id="t", pre_write=guard)
```

A hook may only tighten (`tenant_shared` to `private`, a higher `min_clearance`, a narrower compartment set) or block; a widening decision raises `ValueError`, and a hook that raises is treated as a block.

### 9. `memshield://` URI for the ADK service registry

```python
from adk_memshield import register_adk_uri
from google.adk.cli.service_registry import get_service_registry

register_adk_uri("memshield")
memory_service = get_service_registry().create_memory_service(
    "memshield://memshield_app:memshield_pass@localhost:54329/memshield"
    "?tenant_id=tenant_alpha&agent_clearance=2&compartments=finance,legal"
)
```

---

## Upgrading from 0.1.x

1. Apply [`sql/migrations/0.1_to_0.2.sql`](https://github.com/aalishan001/adk-memshield/blob/main/sql/migrations/0.1_to_0.2.sql) as the table owner, in one transaction: `psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 --single-transaction -f sql/migrations/0.1_to_0.2.sql`. It is idempotent. It adds `compartments` (existing rows get `{}` and keep exactly their 0.1.x visibility), a GIN index, and recreates the four policies.
   **Locking:** `ALTER TABLE` takes an `ACCESS EXCLUSIVE` lock, and in one transaction it is held while the `CHECK` constraint scans the table and the GIN index is built, so reads and writes on `memories` wait for the whole migration (the file sets `lock_timeout = '10s'` so it fails instead of queueing). On a large table, run it in a quiet window, or first add the constraint `NOT VALID` and `VALIDATE` it separately and create the index `CONCURRENTLY` outside a transaction; the migration then skips both.
2. Upgrade the package. The ADK API is unchanged. New: the service refuses an RLS-bypassing role, a role that owns the table, an unprotected table, or a permissive policy that never checks the tenant (`MemShieldConfigurationError`). Policies granted to a group role the app role belongs to now count. Benchmarks against an intentionally unprotected table need `allow_insecure_role=True`.
3. If you pass your own `pool=`, add `reset=adk_memshield.reset_connection`. It also clears session `SET`s made in a pool `configure=` callback after the first check-in; put those in the DSN `options` or `ALTER ROLE ... SET`.
4. Cost: every operation re-plans its statements (`force_custom_plan`), and memshield's pools run three reset statements and a commit on check-in.
5. `JwtIdentityVerifier` (new) requires `issuer=`; `rls_transaction` always resolves (and verifies) the identity.

---

## Reproducing tests & benchmarks

All containers use compose project `adk-memshield`; Postgres 16 is on host port `54329`, the optional Postgres 17 on `54331`.

```bash
docker compose -p adk-memshield up -d --wait db
docker compose -p adk-memshield run --rm test pytest -v              # 122 tests
docker compose -p adk-memshield run --rm test pytest -v -m slow      # 50k-row HNSW plan-cache test
docker compose -p adk-memshield run --rm test python benchmarks/run_memleak_eval.py
docker compose -p adk-memshield run --rm test python benchmarks/plan_cache_hnsw.py --rows 100000 --repeats 4
docker compose -p adk-memshield run --rm test python benchmarks/pool_reset_cost.py
# PostgreSQL 17:
docker compose -p adk-memshield --profile pg17 up -d --wait db17
docker compose -p adk-memshield run --rm \
  -e MEMSHIELD_DB_DSN=postgresql://memshield_app:memshield_pass@db17:5432/memshield \
  -e MEMSHIELD_ADMIN_DSN=postgresql://postgres:postgres_admin_pass@db17:5432/memshield \
  test pytest -v
```

Raw outputs of every number in this README are under [`benchmarks/runs/`](https://github.com/aalishan001/adk-memshield/tree/main/benchmarks/runs).

---

## Credits

- The prepared-statement + HNSW recall collapse was reported and measured by [Sunnatulla](https://dev.to/sunnatulla_dev/comment/3l7np), who also suggested pinning the plan in one helper rather than per query.
- The pooled-connection hygiene tests were prompted by a reader question.

## License

Apache License 2.0. See [`LICENSE`](https://github.com/aalishan001/adk-memshield/blob/main/LICENSE).
