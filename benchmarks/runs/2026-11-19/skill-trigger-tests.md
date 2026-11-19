# Agent Skills Trigger and Compliance Tests (2026-11-19)

Tested in Antigravity with both skills installed in `.agents/skills/` (copies of `adk-memshield/skills/memshield-tenant-isolation` and `adk-leak-arena/skills/leak-arena-audit`).

## Format validation (`agentskills.io`)

- `memshield-tenant-isolation`: **VALID** (`SKILL.md` = 54 lines < 500; description = 250 chars < 1024; all `references/` and `scripts/` paths verified; `scripts/posture_check.py` ran cleanly against local PostgreSQL 16 and exited `0` without printing DSN).
- `leak-arena-audit`: **VALID** (`SKILL.md` = 55 lines < 500; description = 189 chars < 1024; all `references/` paths verified).

## Trigger test matrix (10 of 10 correct)

Each prompt was executed in a fresh read-only Antigravity subagent session discovering workspace skills from `.agents/skills/`.

| # | Skill under test | Expected | Prompt | Triggered | Rule compliance check | Verdict |
| :---: | :--- | :---: | :--- | :--- | :--- | :---: |
| 1 | `memshield-tenant-isolation` | Trigger | "Add long-term memory to this ADK agent; it serves many companies." | `memshield-tenant-isolation`, `leak-arena-audit` | Non-owner `NOSUPERUSER NOBYPASSRLS` role, `JwtIdentityVerifier` (`issuer=`), `bind_identity`, `hnsw.iterative_scan=relaxed_order`, `posture_check.py`, `leak-arena eval` CI gate. | **PASS** |
| 2 | `memshield-tenant-isolation` | Trigger | "Make sure customer A's memories can never reach customer B." | `memshield-tenant-isolation`, `leak-arena-audit` | `ENABLE`/`FORCE ROW LEVEL SECURITY`, non-bypass app role (not `alloydbsuperuser`/`cloudsqlsuperuser`), verified token identity, `reset_connection`, tighten-only `pre_write`, CI gate. | **PASS** |
| 3 | `memshield-tenant-isolation` | Trigger | "Wire pgvector RAG memory on AlloyDB with row-level security for our multi-tenant agent." | `memshield-tenant-isolation` | AlloyDB non-bypass SQL role (avoiding `--superuser=true` / `alloydbsuperuser`), `verify_rls_posture()`, `JwtIdentityVerifier`, `idx_memories_scope_lookup` + `hnsw.iterative_scan=relaxed_order`. | **PASS** |
| 4 | `memshield-tenant-isolation` | No trigger | "Write a SQL query for monthly revenue." | `NONE` | Standard SQL query only; no false trigger. | **PASS** |
| 5 | `memshield-tenant-isolation` | No trigger | "Fix this CSS bug: the submit button overflows its container on mobile." | `NONE` | Standard CSS guidance only; no false trigger. | **PASS** |
| 6 | `leak-arena-audit` | Trigger | "Add a CI check that our agent memory doesn't leak." | `leak-arena-audit` | Synthetic data only, env-only `ARENA_DB_DSN`/`ARENA_ADMIN_DSN`, `leak-arena eval --min-recall 1.0`, strict `0`/`1`/`2` exit-code handling, scenario-to-fix mapping. | **PASS** |
| 7 | `leak-arena-audit` | Trigger | "Audit our multi-tenant agent's memory store and prove it cannot leak data across tenants or clearance levels." | `leak-arena-audit`, `memshield-tenant-isolation` | Explicit authorization + synthetic canary data, `leak-arena eval --scenarios all --targets unprotected,memshield,qdrant,mem0`, exit codes `0`/`1`/`2`, `S1`–`S9` remediation map. | **PASS** |
| 8 | `leak-arena-audit` | Trigger | "Test whether our pgvector and Qdrant memory backends leak cross-user memories when a filter is missing." | `leak-arena-audit`, `memshield-tenant-isolation` | `S1`/`S2`/`S5`/`CONTROL` across `unprotected,memshield,qdrant`, neutral Qdrant framing, `FORCE ROW LEVEL SECURITY` + token identity remediation. | **PASS** |
| 9 | `leak-arena-audit` | No trigger | "Write a Python function to parse ISO-8601 dates into quarters." | `NONE` | Standard Python `datetime` snippet only; no false trigger. | **PASS** |
| 10 | `leak-arena-audit` | No trigger | "Refactor our button hover animation in Tailwind CSS." | `NONE` | Standard CSS guidance only; no false trigger. | **PASS** |

## Summary
- **Result:** **10 of 10** trigger tests correct (6/6 positive triggers with full rule adherence; 4/4 negative non-triggers).
- **Gemini CLI:** not installed on this workstation (tested in Antigravity only).
