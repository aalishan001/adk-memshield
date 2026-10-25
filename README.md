# `adk-memshield`

**Zero-trust multi-tenant semantic memory for Google ADK (`google-adk`), enforced in the database by PostgreSQL `pgvector` + Row-Level Security (RLS).**

[![PyPI](https://img.shields.io/pypi/v/adk-memshield)](https://pypi.org/project/adk-memshield/)
[![Python](https://img.shields.io/pypi/pyversions/adk-memshield)](https://pypi.org/project/adk-memshield/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![CI](https://github.com/aalishan001/adk-memshield/actions/workflows/ci.yml/badge.svg)](https://github.com/aalishan001/adk-memshield/actions/workflows/ci.yml)
[![Google ADK](https://img.shields.io/badge/google--adk-%3E%3D2.12-4285F4.svg)](https://github.com/google/adk-python)

---

## Why `adk-memshield`?

Multi-tenant and multi-agent `google-adk` deployments often keep long-term semantic memory in one shared vector table, with isolation enforced only by the `WHERE` clause the application remembers to write. That design leaks in two well-documented ways:

1. **Cross-user semantic leakage** — *MemLeak: Cross-User Semantic Leakage in Multi-Tenant AI Agent Memory* ([arXiv:2610.04195](https://arxiv.org/abs/2610.04195)) shows that similarity search over a pooled store surfaces other users' memories without any exploit, and that hard ownership gating is the mitigation that consistently restores the clean baseline.
2. **Lateral leakage inside agent swarms** — *AgentLeak* ([arXiv:2602.11510](https://arxiv.org/abs/2602.11510)) shows that internal channels between agents are a major leakage path. `adk-memshield` addresses the memory-retrieval slice of that problem: a low-clearance sub-agent must not retrieve shared tenant memories labelled above its clearance.

`adk-memshield` is a drop-in `BaseMemoryService` that moves ownership gating out of application code and into PostgreSQL itself, using **`FORCE ROW LEVEL SECURITY`** and **transaction-local identity (`set_config(..., true)`)**. A retrieval query with a missing or wrong filter returns fewer rows, not someone else's rows.

![adk-leak-arena console: the same no-WHERE query leaks cross-tenant rows from an unprotected table and returns only the caller's rows from adk-memshield](https://raw.githubusercontent.com/aalishan001/adk-leak-arena/main/docs/assets/console-overview.png)

*Live side-by-side comparison in the companion red-team console, [adk-leak-arena](https://github.com/aalishan001/adk-leak-arena) (`pip install adk-leak-arena`).*

---

## Architecture

```mermaid
flowchart LR
    subgraph ADK["Google ADK Runtime"]
        Agent["ADK Agent / Sub-Agent<br/>(app_name, user_id from Runner)"]
        Service["MemShieldMemoryService<br/>(BaseMemoryService)<br/>tenant_id + clearance from config"]
        Embedder["MemShieldEmbedder<br/>(FastEmbed bge-small-en-v1.5, 384d)"]
    end

    subgraph PG["PostgreSQL 16 + pgvector (role memshield_app, NOBYPASSRLS)"]
        Tx["Explicit transaction"]
        Ctx["Transaction-local identity<br/>set_config('app.*', val, true)"]
        RLS["RLS policies<br/>SELECT / INSERT / UPDATE / DELETE"]
        Vec[("memories<br/>vector(384)")]
    end

    Agent --> Service
    Service --> Embedder
    Service --> Tx
    Tx --> Ctx
    Ctx --> RLS
    RLS --> Vec
```

### Security properties

- **No superuser bypass.** Superusers and `BYPASSRLS` roles ignore RLS even under `FORCE ROW LEVEL SECURITY`. [`sql/01_schema.sql`](./sql/01_schema.sql) creates a least-privilege `memshield_app` role (`NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`); connect with it.
- **Pool-safe identity.** Every operation runs in an explicit transaction and binds `app.current_app_name`, `app.current_tenant_id`, `app.current_user_id` and `app.agent_clearance` with `set_config(..., true)`. The settings vanish at commit/rollback, so identity never bleeds into the next pooled checkout. All values are bound parameters; the only interpolated identifier (`table_name`) is validated against `^[A-Za-z_][A-Za-z0-9_]*$`.
- **Fail-closed.** Without identity context a query sees 0 rows. Identity columns carry `CHECK (<col> <> '')` because a pooled connection reports `''` (not `NULL`) for a custom setting once it has been used, and the service rejects empty `app_name`/`user_id` before touching the database.
- **All four commands are gated.** `SELECT` allows own rows plus `tenant_shared` rows with `min_clearance <= app.agent_clearance`. `INSERT` and `UPDATE` (`USING` + `WITH CHECK`) and `DELETE` (`USING`) are restricted to the caller's own rows, so cross-user poisoning or re-owning a row raises `InsufficientPrivilege`.
- **No write-up.** An agent cannot write a `tenant_shared` memory labelled above its own clearance, so a Tier-1 agent cannot plant "executive" context that higher-clearance agents would trust.
- **Defense in depth.** The library's own query also filters by user/scope/clearance, mirroring the policy, so neither layer is a single point of failure. Ownership columns always come from call arguments and config, never from caller-supplied metadata.
- **Idempotent session ingestion.** ADK may call `add_session_to_memory` repeatedly for one session; a unique index on `(owner, session_id, event_id)` stores each event once.
- **Non-blocking.** Embedding and database I/O run in a worker thread (`asyncio.to_thread`), so memory calls do not stall the ADK event loop.

---

## Benchmark: unprotected `pgvector` vs. `adk-memshield`

[`benchmarks/run_memleak_eval.py`](./benchmarks/run_memleak_eval.py) seeds a synthetic enterprise corpus (**3 tenants, 6 users, 60 memories**: API credentials, compensation, medical/HR records, query-shaped lure memories, and L3/L4 executive memos) into an ordinary table and into the RLS table. Each scenario runs **the same buggy application-layer SQL** against both, inside the same transaction-local identity of the authenticated caller, so the only variable is whether the database enforces ownership. `top_k=3`, 75 queries, 5 repeats.

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
| Scenario 1: Shared-Tenant Pool (Incidental Overlap) | 0.74 / 1.19 | 0.78 / 1.38 |
| Scenario 2: Adversarial Top-K Planted Lure | 0.79 / 1.27 | 0.72 / 1.45 |
| Scenario 3: Tool-Argument `user_id` Override | 0.83 / 1.35 | 0.84 / 1.42 |
| Scenario 4: Low-Clearance Swarm Agent (AgentLeak-style) | 0.80 / 1.24 | 0.91 / 1.60 |
| Scenario 5: Total Filter Omission | 0.72 / 1.22 | 0.73 / 1.22 |
| Control: Correct App Filter (no bug) | 0.76 / 1.53 | 0.78 / 1.39 |

**How to read this**

- **Leak rate is saturated by design of fixed top-k.** With no similarity floor, `LIMIT 3` always fills its slots. When a caller has fewer than three relevant rows of their own, a buggy filter fills the remainder with other people's rows, so every buggy query leaked at least one row. The *leaked share* and *rank-1* columns show how much of the retrieved context was unauthorized.
- **RLS removed every unauthorized row in every scenario**, while the identical buggy SQL leaked on the plain table. The control row confirms the leak classifier reports 0% when the application filter is correct.
- **Planted lures hijack rank 1, not recall.** Each Scenario 2 lure restates the target question followed by a short malicious payload (a white-box, PoisonedRAG-style attacker who knows the query wording). On the plain table a lure took rank 1 in 58.3% of queries: every roadmap/SLA query, but only 1 of 3 vendor queries and none of the API/KMS queries, where the victim's own note already restates the question almost verbatim. With RLS the lures are never retrieved.
- **Recall gains are modest and specific.** In Scenarios 1, 2 and 4 the caller's own answer still made the top 3 on the plain table, so RLS changed *what else* was in context (and what ranked first) rather than recall. The recall gain appears under total filter omission (72.7% → 100%), where cross-tenant near-duplicates and lures crowd out the caller's own memories.
- **Scenario 3 has no authorized answer.** The queries are pure exfiltration attempts, so recall is n/a. RLS turns the attack into an empty or own-rows-only result; it cannot repair the application's wrong `user_id` argument.
- **Latency.** At 60 rows the RLS overhead is within run-to-run noise. This benchmark does not measure ANN index behaviour at scale (see Limitations).
- The corpus and queries are synthetic and hand-written. Treat the numbers as a reproducible illustration of failure modes, not as an estimate of real-world leak rates.

---

## Threat model & limitations

- **What RLS protects against:** bugs and omissions in application retrieval SQL, prompt-injected tool arguments, and cross-user writes, all *while the service binds the correct identity*.
- **What it does not protect against:** a compromised application process. `memshield_app` can call `set_config` itself, so code holding the database credentials can claim any identity. Keep identity binding inside this service and keep credentials out of agent-reachable code paths.
- **Tenant and clearance come from service config, not from the ADK session.** `search_memory` receives only `app_name`/`user_id` from ADK, so run one service instance per tenant/clearance tier (or per Runner).
- **`tenant_shared` content is trusted by design.** A user may publish a `tenant_shared` memory at or below their own clearance, and every agent in the tenant with sufficient clearance can retrieve it. RLS enforces *who may read*, not whether the content is benign.
- **ANN indexes and RLS.** The schema ships without a vector index. If you add HNSW/IVFFlat, RLS filters rows *after* the index scan and can return fewer than `top_k` rows. Use pgvector ≥ 0.8 iterative index scans (`SET hnsw.iterative_scan = relaxed_order`) and benchmark recall at your scale.
- `sql/02_benchmark_baseline.sql` creates an intentionally unprotected table for tests and benchmarks. **Do not apply it in production.**

---

## Installation

```bash
pip install adk-memshield
```

From source, for development:

```bash
pip install -e ".[dev]"
```

---

## Quickstart

### 1. Apply the schema

Apply [`sql/01_schema.sql`](./sql/01_schema.sql) as a superuser/owner, then rotate the `memshield_app` password. The file also ships inside the wheel:

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
    )
)

runner = Runner(
    app_name="finance_copilot",
    agent=LlmAgent(
        name="assistant",
        model="gemini-2.5-flash",
        tools=[preload_memory_tool, load_memory_tool],
    ),
    session_service=InMemorySessionService(),
    memory_service=memory_service,
)
# ADK's memory tools call memory_service.search_memory(app_name=..., user_id=...) with the
# Runner's authenticated identity; persist a finished session with:
#   await memory_service.add_session_to_memory(session)
```

### 3. Write and search memories directly

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
        # Visible to tenant agents with clearance >= 2 (the writer's clearance must be >= 2).
        MemoryEntry(
            content=types.Content(parts=[types.Part(text="Treasury approval threshold is $250k.")]),
            custom_metadata={"scope": "tenant_shared", "min_clearance": 2},
        ),
    ],
)

response = await memory_service.search_memory(
    app_name="finance_copilot", user_id="alice", query="What is my wire routing code?"
)
for entry in response.memories:
    print(entry.content.parts[0].text, entry.custom_metadata["similarity"])

print(memory_service.last_query_telemetry.to_dict())  # SQL, identity context, latency, rows
```

### 4. Run custom SQL under the caller's RLS identity

```python
with memory_service.rls_transaction(app_name="finance_copilot", user_id="alice") as cur:
    cur.execute("SELECT content FROM memories ORDER BY created_at DESC LIMIT 10")
    rows = cur.fetchall()  # only rows alice may read, even though the SQL has no WHERE clause
```

### 5. `memshield://` URI for the ADK service registry

```python
from adk_memshield import register_adk_uri
from google.adk.cli.service_registry import get_service_registry

register_adk_uri("memshield")
memory_service = get_service_registry().create_memory_service(
    "memshield://memshield_app:memshield_pass@localhost:54329/memshield?tenant_id=tenant_alpha&agent_clearance=2"
)
```

---

## Reproducing tests & benchmarks

All containers use compose project `adk-memshield` and host port `54329`:

```bash
# 1. Start pgvector:pg16 (applies sql/01_schema.sql and sql/02_benchmark_baseline.sql on first start)
docker compose -p adk-memshield up -d db

# 2. Run the 8 integration tests, including a real ADK Runner + preload_memory/load_memory test
docker compose -p adk-memshield run --rm test pytest -v

# 3. Run the benchmark
docker compose -p adk-memshield run --rm test python benchmarks/run_memleak_eval.py
```

---

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
