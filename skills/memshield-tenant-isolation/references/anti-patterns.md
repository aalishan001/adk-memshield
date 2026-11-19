# Multi-Tenant Agent Memory Anti-Patterns

Reject these patterns during design and code review:

1. **Application-side `WHERE tenant_id = ...` as the sole isolation control.**
   - One omitted clause, ORM bug, or wrong filter parameter leaks every other tenant's memories. Always enforce `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` in PostgreSQL alongside application filters.

2. **Connecting with a superuser, `BYPASSRLS`, table-owner, or cloud-superuser role.**
   - PostgreSQL superusers and `BYPASSRLS` roles ignore RLS even under `FORCE ROW LEVEL SECURITY`. Table owners can run `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` or drop policies at runtime.
   - On Google Cloud, avoid `gcloud sql users create` or `gcloud alloydb users create --superuser=true` for the application role because they grant `cloudsqlsuperuser` / `alloydbsuperuser`. Create `memshield_app` via SQL with `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`.
   - Real-world example of this failure class: in 2025 researchers demonstrated a Supabase MCP agent reading a private table because its database key bypassed RLS.

3. **Taking `user_id`, `tenant_id`, or `clearance` from the prompt or LLM tool arguments.**
   - Prompt injections can override tool arguments (Scenario 3 / Scenario 8 in `adk-leak-arena`). Always bind caller identity from a verified login token (`JwtIdentityVerifier` or `HmacIdentityVerifier`).

4. **Using session-level `SET` instead of transaction-local `set_config(..., true)` on a connection pool.**
   - Session-level settings outlive a request and bleed into the next tenant's pooled checkout (Scenario 9 in `adk-leak-arena`). Always bind per transaction and configure `reset=adk_memshield.reset_connection` on custom pools.

5. **Adding an HNSW vector index without iterative scan or dropping `idx_memories_scope_lookup`.**
   - Post-filtered HNSW scans can return 0 rows for light callers (`hnsw.ef_search` candidates all filtered out), and iterative scans hit their tuple/memory ceiling on tiny tenants without the B-tree scope lookup index. Keep `idx_memories_scope_lookup` and set `hnsw.iterative_scan=relaxed_order` as a connection startup option or role default.

6. **Treating prompt rules or Agent Skills as the security boundary.**
   - Prompts and skills are advice that a model can ignore or be talked out of. Keep the deterministic security boundary in PostgreSQL RLS, and treat a `pre_write` guard as tighten-only defense in depth.

7. **Passing `ADMIN_DSN` or `allow_insecure_role=True` to a public or agent-facing service.**
   - Keep schema migrations and seeding in a separate out-of-band job that alone holds the owner DSN.
