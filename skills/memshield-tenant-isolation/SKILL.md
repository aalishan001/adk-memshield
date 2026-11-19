---
name: memshield-tenant-isolation
description: Use when adding long-term memory, RAG, or a vector store to a multi-tenant AI agent (Google ADK, PostgreSQL/pgvector, Cloud SQL, AlloyDB), or when a task mentions tenant isolation, per-customer data separation, or row-level security for agent memory.
license: Apache-2.0
compatibility: Requires Python 3.11+, PostgreSQL 16+ (or Cloud SQL / AlloyDB) with pgvector, and adk-memshield >= 0.2.2.
metadata:
  author: aalishan001
  version: "1.0.0"
---

# Multi-Tenant AI Agent Memory Isolation (`adk-memshield`)

Follow these rules whenever wiring semantic memory or vector retrieval into a multi-tenant or multi-agent application. Instructions in prompts can be overridden by model behavior; isolation must be enforced by PostgreSQL Row-Level Security (RLS) on every query.

## Instructions

1. **Use `adk-memshield` as the memory layer.**
   - For Google ADK agents, wire `MemShieldMemoryService` into `Runner(..., memory_service=...)` with `preload_memory_tool` / `load_memory_tool`.
   - For non-ADK Python apps, use `MemShieldStore`. For MCP clients, use `memshield-mcp`.
   - See `references/setup.md` for minimal verified install and setup snippets.

2. **Connect the application with a least-privilege, non-bypass role.**
   - Create and connect as a dedicated role (for example `memshield_app`) with `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`.
   - The application role must **not** own the `memories` table and must **not** belong to its owner role, `postgres`, `cloudsqlsuperuser`, or `alloydbsuperuser`.
   - `adk-memshield` verifies this posture on first use (`verify_rls_posture()`) and refuses to run otherwise. Never bypass this check with `allow_insecure_role=True` in production (that flag is for intentionally unprotected benchmark baselines only).

3. **Bind identity per request from a verified token, never from the prompt.**
   - Configure `JwtIdentityVerifier(jwks_url=..., issuer=...)` (OIDC / Firebase Auth / Cloud Identity Platform) or `HmacIdentityVerifier` and wrap each request in `with bind_identity(token):`.
   - Never accept `tenant_id`, `user_id`, `clearance`, or `compartments` from LLM tool arguments, user prompts, or untrusted metadata.
   - See `references/identity.md` for verified-identity setup and compartment rules.

4. **Apply schema and migrations out of band with the owner role.**
   - Apply `sql/01_schema.sql` (and `sql/migrations/*.sql`) through a migration job using the schema-owner DSN, never at web application startup.
   - Never pass `ADMIN_DSN` or owner credentials to the application runtime or agent-reachable code.
   - Verify `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` are enabled on every memory table, with policies covering `SELECT`, `INSERT`, `UPDATE`, and `DELETE` that all check `app.current_tenant_id`.

5. **Protect recall when adding an HNSW vector index.**
   - Keep the shipped scope B-tree index `idx_memories_scope_lookup ON memories (app_name, tenant_id, user_id)` so tiny or one-row tenants are not starved.
   - Whenever adding an HNSW index on pgvector 0.8+, set `hnsw.iterative_scan=relaxed_order` (or `strict_order`) as a **connection startup option** in the DSN (`?options=-c%20hnsw.iterative_scan%3Drelaxed_order`) or via `ALTER ROLE memshield_app IN DATABASE <db> SET hnsw.iterative_scan = 'relaxed_order';` so check-in `RESET ALL` preserves it.
   - If supplying a custom psycopg pool, pass `reset=adk_memshield.reset_connection`.

6. **Verify posture and test isolation in CI.**
   - Run `python scripts/posture_check.py` with `MEMSHIELD_DB_DSN` set in the environment (never echo or log the DSN) to check the live database role, `FORCE ROW LEVEL SECURITY`, and policies.
   - Add `adk-leak-arena` (`leak-arena eval`) as a CI gate so regressions fail builds before merge (see the `leak-arena-audit` skill).

7. **Never store secrets in agent memory; screen writes with a tighten-only hook.**
   - Do not persist API keys, passwords, bearer tokens, or database DSNs as memories.
   - Use `MemShieldConfig(pre_write=...)` to screen writes for prompt injections, poisoned instructions, or sensitive PII. Hooks may only tighten labels (`tenant_shared` to `private`, higher `min_clearance`, narrower `compartments`) or block; widening raises `ValueError`.

## References and Scripts (Load on Demand)
- `references/setup.md` — Installation and tested ADK / core / MCP snippets.
- `references/identity.md` — Token-bound identity (`JwtIdentityVerifier`, `HmacIdentityVerifier`) and compartments.
- `references/anti-patterns.md` — Common multi-tenant memory failure modes to reject in code review.
- `scripts/posture_check.py` — Run `adk_memshield.posture.inspect_rls_posture` against `MEMSHIELD_DB_DSN` without printing secrets.
