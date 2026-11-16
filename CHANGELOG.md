# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
