# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Agent Skill (`skills/memshield-rbac-onboarding/`):** `agentskills.io`-format onboarding skill + deterministic `scripts/map_rbac.py` (no model) mapping roles YAML/JSON, IdP group claims (Okta, Entra ID, Google Groups), roles CSVs, and Casbin policy CSVs onto real `adk-memshield` identity fields (`tenant_id`, `user_id`, `clearance` 1–5, `compartments`), emitting a `JwtIdentityVerifier` snippet, flagging unmappable rules (conditions, deny rules, time restrictions, per-record ACLs) for human review, and generating pairwise isolation test cases. Tested on two fixtures (`benchmarks/runs/2026-11-20/rbac-{lending-startup,idp-groups}/`) and verified in Antigravity: 5 of 5 trigger tests correct (`benchmarks/runs/2026-11-20/rbac-skill-trigger-tests.md`).
- **Agent Skill (`skills/memshield-tenant-isolation/`):** `agentskills.io`-format skill (`SKILL.md`, `references/{setup,identity,anti-patterns}.md`, `scripts/posture_check.py`) that instructs coding agents to wire `adk-memshield` safely (non-bypass role, token-bound identity, owner-applied migrations, iterative scan + scope B-tree, never echoing DSNs). Verified in Antigravity: 10 of 10 trigger tests correct (`benchmarks/runs/2026-11-19/skill-trigger-tests.md`).
- **Scaling guide (`docs/SCALING.md`):** separates measured numbers (RLS overhead, HNSW plan-cache/iterative-scan/one-row-tenant results, AlloyDB Express ScaNN vs HNSW), what the design supports (transaction-mode pooling, read replicas, dedicated enterprise instances), and what is not yet tested.
- **AlloyDB Express (PostgreSQL 18.4) verification & ScaNN benchmark:**
  - `benchmarks/scann_vs_hnsw_rls.py` and raw output `benchmarks/runs/2026-11-19/scann-vs-hnsw-alloydb-50k.txt` (50,000 rows, 0 leaks across all 20 configs; ScaNN beat HNSW for heavy users at 0.890 recall / 0.53 ms and built 2.3x faster, while default ScaNN under RLS dropped to 0.090 recall / 2 of 10 empty for a 30-row light user despite inline filtering).
  - Test-suite verification on AlloyDB Express PostgreSQL 18.4 (`benchmarks/runs/2026-11-19/pytest-alloydb-express.txt`): 113 passed, 1 skipped, 9 failed (all 9 are admin-fixture assertions that expect `rolsuper=true`, whereas AlloyDB `postgres` has `rolsuper=false, rolbypassrls=false`; 0 product bugs).

## [0.2.2] - 2026-11-17

### Documentation
- **Iterative scans have a budget; tiny tenants need the scope B-tree.** pgvector's iterative index scan stops after `hnsw.max_scan_tuples` (20,000 by default) and at its memory limit (`hnsw.scan_mem_multiplier` × `work_mem`), so a tenant that owns one row in a large table can stay empty even with `hnsw.iterative_scan = relaxed_order`. The README's "ANN indexes (HNSW) and RLS" section now says so, points out that memshield's schema already ships the fix (`idx_memories_scope_lookup` on `app_name, tenant_id, user_id`, which lets the planner skip HNSW for tiny tenants), and recommends the same B-tree for application-filtered tables. Measured with the new `benchmarks/tiny_tenant_hnsw.py` at 200,000 rows on PostgreSQL 16.15 and 17.12: with the shipped B-tree 20 of 20 one-row tenants found (index scan, about 1.5 ms); with HNSW forced and no B-tree, 0 of 20 with the iterative scan at the default cap and still 0 with the cap raised above the table size. Reported and measured by Sunnatulla (https://dev.to/sunnatulla_dev).

### Added
- `benchmarks/tiny_tenant_hnsw.py` and its raw outputs (`benchmarks/runs/2026-11-17/tiny-tenant-hnsw-pg{16,17}-200k.txt`).

## [0.2.1] - 2026-11-17

### Documentation
- **A second empty-results case with HNSW, and its fix.** With an HNSW index at 100,000 rows, a light caller's filtered search can come back empty from the first execution under a custom plan: the index returns `hnsw.ef_search` (40) candidates and the filter removes them all. Plan pinning cannot prevent it, and it affects application-filtered tables without RLS the same way. The README's "ANN indexes (HNSW) and RLS" section now recommends pgvector's `hnsw.iterative_scan` (`relaxed_order`, or `strict_order` for exact ordering) whenever an HNSW index is used, set as a connection startup option or role default so the pool's `RESET ALL` keeps it, with the measured rows (recall@10 0.00 → 1.00, adk-leak-arena `prepared-100k-*` raw outputs). Nothing leaked in any configuration.
- Not made a default: it changes results and ordering for every query on the pool's connections and needs pgvector 0.8, so it is left to each deployment.

### Added
- Test that settings passed as connection startup options survive the check-in reset while a session `SET` does not (`test_startup_options_survive_the_checkin_reset`).

### Changed
- PyPI keywords: `model-context-protocol`, `access-control`.

## [0.2.0] - 2026-11-16

### Fixed
- **Recall no longer collapses when a prepared statement switches to a generic plan.** psycopg 3 prepares a statement after 5 executions on one connection, and PostgreSQL may then cache a generic plan; with the query vector and `LIMIT` unknown, that plan can be the HNSW scan with the RLS policy applied as a post-filter, so a caller with few visible rows gets empty results (nothing leaks). Every RLS transaction now binds `plan_cache_mode = force_custom_plan` in the same statement as the identity, covering custom SQL on `rls_transaction()` too. Measured at 100,000 rows on PostgreSQL 16.15 and 17.12, for custom SQL on `rls_transaction()` (the RLS-only query shape): the light user's recall@10 on a pinned connection went from 0.50 (empty from the 11th search on) to 1.00. memshield's own search was not affected in this measurement. The pin does not stop HNSW post-filtering under a custom plan (see the README). Reported and measured by Sunnatulla (https://dev.to/sunnatulla_dev/comment/3l7np).
- README: "a query with no WHERE clause returns only the caller's rows" was wrong; it returns the rows the caller is entitled to (own rows plus tenant-shared rows at or below their clearance, and now within their compartments).

### Security
- The table is resolved once to its schema-qualified name, so a temporary table of the same name (created through custom SQL on a pooled connection) can no longer capture reads or writes; memshield refuses to run if the name resolves to a temporary table.
- memshield's pools run `RESET ALL; RESET ROLE; DISCARD TEMP` when a connection is returned.
- The UPDATE policy only lets an agent modify a `tenant_shared` row labelled within its own clearance and compartments, so a low-clearance agent acting for the row's owner cannot declassify it.

### Added
- `verify_rls_posture()` and `MemShieldConfigurationError`: before the first operation on a pool, memshield refuses a superuser or `BYPASSRLS` role, a role that owns the table (or is a member of its owner role), a table without forced RLS, a command without a policy, and a permissive policy (granted to PUBLIC, the role, or a role it belongs to) with a `USING` or `WITH CHECK` expression that never references `app.current_tenant_id`. Construction runs no posture queries.
- Verified identity: `IdentityVerifier`, `bind_identity()`, `HmacIdentityVerifier` (standard library, key rotation by `kid`, finite expiry and a maximum lifetime), `JwtIdentityVerifier` (`adk-memshield[jwt]`, PyJWT + JWKS, `issuer` required), `MemShieldIdentity`, `MemShieldIdentityError`. With a verifier, tenant, clearance and compartments come from the token and the framework's `user_id` must match its subject. `rls_transaction()` always resolves and verifies the identity.
- Compartments: `compartments TEXT[]` with SELECT, INSERT and UPDATE policy rules (read: untagged or overlapping; write: no write-across), `MemShieldConfig.compartments`, and the `compartments` label in memory metadata.
- `MemShieldStore`: a framework-neutral core (`add`, `search`, `delete`, `rls_transaction`). `MemShieldMemoryService` is now a thin ADK layer over it; its public API is unchanged.
- MCP server (`adk-memshield[mcp]`, `memshield-mcp`): `remember`, `recall`, `forget` over stdio or streamable HTTP. The transport is fixed when the server is built; HTTP requires an identity verifier and a bearer token on every request and never reads identity from the environment.
- `pre_write` hook (`Allow`, `Downlabel`, `Block`): inspect each memory before it is stored; it may only tighten labels or block. A hook that raises blocks that memory; a decision that would widen access raises `ValueError` and aborts the `add` call.
- `reset_connection`: the pool reset callback above (0.58 ms per checkout measured on a one-connection pool over local Docker; two round trips).
- Tests: pooled-connection hygiene after rollback, statement timeout, a killed backend, session-scoped `set_config` (with a negative control), `SET ROLE`, temporary tables and concurrent tenants, prompted by a reader question; plan-cache tests that count generic vs custom plans of a prepared statement (with a negative control), plus a slow 50,000-row HNSW test with a negative control; posture, identity, compartment, migration and hook tests; a conformance suite run over the ADK service, the core store and the MCP tools. 121 tests plus 1 slow test, on PostgreSQL 16 and 17.
- Benchmarks: `benchmarks/plan_cache_hnsw.py`, `benchmarks/pool_reset_cost.py`, and raw outputs under `benchmarks/runs/2026-11-16/`.

### Changed
- PyPI keywords now describe the project (`adk`, `ai-agents`, `agent-memory`, `data-isolation`, `rls`, `vector-database`, `mcp`, ...); `agents` and `memleak` are dropped. Added the `Programming Language :: SQL` and `Topic :: Software Development :: Libraries :: Python Modules` classifiers.
- `QueryTelemetry.session_context` also reports `app.agent_compartments` and `plan_cache_mode`; `QueryTelemetry.blocked_writes` counts writes the `pre_write` hook blocked. Telemetry SQL shows the schema-qualified table.

### Upgrade notes
- Apply `sql/migrations/0.1_to_0.2.sql` as the table owner (idempotent; existing rows get `compartments = '{}'` and keep their 0.1.x visibility). It takes an `ACCESS EXCLUSIVE` lock on `memories` for its duration (constraint scan and GIN build); see the README for a lower-lock path on large tables.
- The service now refuses an RLS-bypassing role, a role that owns the table, or an unprotected table. Benchmarks against an intentionally unprotected table need `allow_insecure_role=True` (logs a warning on every use).
- If you pass your own `pool=`, create it with `reset=adk_memshield.reset_connection`; move session `SET`s from a `configure=` callback into the DSN `options` or `ALTER ROLE ... SET`.
- Every operation re-plans its statements (`force_custom_plan`).

## [0.1.1] - 2026-10-25

### Fixed
- `requires-python` is now `>=3.11`. The 0.1.0 metadata declared `>=3.10`, but its `google-adk>=2.12` dependency requires Python 3.11+, so installs on Python 3.10 fail to resolve.

### Changed
- README links are absolute so they work on PyPI; the README adds PyPI/CI badges and a screenshot of the companion adk-leak-arena console.

## [0.1.0] - 2026-10-22

### Added
- `MemShieldMemoryService`, a Google ADK `BaseMemoryService` backed by PostgreSQL `pgvector` with forced Row-Level Security and transaction-local identity (`set_config(..., true)`).
- RLS policies for `SELECT`, `INSERT`, `UPDATE` and `DELETE`, non-empty identity checks, a no-write-up clearance rule, and idempotent session ingestion.
- `rls_transaction()` for running custom SQL under the caller's RLS identity.
- `memshield://` URI registration for the ADK service registry.
- Integration tests, including a real ADK `Runner` with `preload_memory` and `load_memory`.
- MemLeak / AgentLeak-style benchmark with five application-layer failure scenarios and a control row.
