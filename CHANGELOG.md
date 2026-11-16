# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Recall no longer collapses with prepared statements and an HNSW index.** psycopg 3 prepares a statement after 5 executions on one connection, and PostgreSQL may then cache a generic plan in which the HNSW scan applies the RLS policy as a post-filter, so a caller with few visible rows gets empty results (nothing leaks). Every RLS transaction now binds `plan_cache_mode = force_custom_plan` in the same statement as the identity, covering custom SQL on `rls_transaction()` too. Measured at 100,000 rows on PostgreSQL 16.15 and 17.12: recall@10 for a light user on a pinned connection went from 0.50 (empty from the 11th search on) to 1.00. Reported and measured by Sunnatulla (https://dev.to/sunnatulla_dev/comment/3l7np).
- README: "a query with no WHERE clause returns only the caller's rows" was wrong; it returns the rows the caller is entitled to (own rows plus tenant-shared rows at or below their clearance, and now within their compartments).

### Added
- `verify_rls_posture()` and `MemShieldConfigurationError`: before the first operation on a pool, memshield refuses a superuser or `BYPASSRLS` role, a table without forced RLS, a command without a policy, and a permissive policy that does not check the tenant. Construction still does no I/O.
- Verified identity: `IdentityVerifier`, `bind_identity()`, `HmacIdentityVerifier` (standard library, key rotation by `kid`), `JwtIdentityVerifier` (`adk-memshield[jwt]`, PyJWT + JWKS), `MemShieldIdentity`, `MemShieldIdentityError`. With a verifier, tenant, clearance and compartments come from the token and the framework's `user_id` must match its subject.
- Compartments: `compartments TEXT[]` with SELECT, INSERT and UPDATE policy rules (read: untagged or overlapping; write: no write-across), `MemShieldConfig.compartments`, and the `compartments` label in memory metadata.
- `MemShieldStore`: a framework-neutral core (`add`, `search`, `delete`, `rls_transaction`). `MemShieldMemoryService` is now a thin ADK layer over it; its public API is unchanged.
- MCP server (`adk-memshield[mcp]`, `memshield-mcp`): `remember`, `recall`, `forget` over stdio or streamable HTTP. HTTP requires an identity verifier and a bearer token.
- `pre_write` hook (`Allow`, `Downlabel`, `Block`): inspect each memory before it is stored; it may only tighten labels or block, and a hook that raises blocks the write.
- `reset_connection`: memshield's pools run `RESET ALL` when a connection is returned (about 0.48 ms per checkout, measured).
- Tests: pooled-connection hygiene after rollback, statement timeout, a killed backend, session-scoped `set_config` (with a negative control) and concurrent tenants, prompted by a reader question; plan-cache tests including a slow 50,000-row HNSW test with a negative control; posture, identity, compartment, migration and hook tests; a conformance suite run over the ADK service, the core store and the MCP tools. 104 tests plus 1 slow test, on PostgreSQL 16 and 17.
- Benchmarks: `benchmarks/plan_cache_hnsw.py`, `benchmarks/pool_reset_cost.py`, and raw outputs under `benchmarks/runs/2026-11-16/`.

### Changed
- PyPI keywords now describe the project (`adk`, `ai-agents`, `agent-memory`, `data-isolation`, `rls`, `vector-database`, ...); `agents` and `memleak` are dropped. Added the `Programming Language :: SQL` and `Topic :: Software Development :: Libraries :: Python Modules` classifiers.
- `QueryTelemetry.session_context` also reports `app.agent_compartments` and `plan_cache_mode`; `QueryTelemetry.blocked_writes` counts writes the `pre_write` hook blocked.

### Upgrade notes
- Apply `sql/migrations/0.1_to_0.2.sql` as the table owner (idempotent; existing rows get `compartments = '{}'` and keep their 0.1.x visibility).
- The service now refuses an RLS-bypassing role or an unprotected table. Benchmarks against an intentionally unprotected table need `allow_insecure_role=True` (logs a warning on every use).
- If you pass your own `pool=`, create it with `reset=adk_memshield.reset_connection`.

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
