# Setup Reference (`adk-memshield`)

Verified snippets matching the tested examples in `adk-memshield/README.md`.

## Install

```bash
pip install adk-memshield
# Optional extras:
pip install "adk-memshield[jwt]"   # OIDC / JWKS identity tokens (PyJWT)
pip install "adk-memshield[mcp]"   # MCP server (memshield-mcp)
```

## 1. Apply the schema (owner role, out of band)

Apply `sql/01_schema.sql` as the schema owner, then ensure `memshield_app` has a strong password and is `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` (and not a member of `alloydbsuperuser` or `cloudsqlsuperuser`):

```python
from importlib.resources import files

schema_sql = (files("adk_memshield") / "sql" / "01_schema.sql").read_text()
```

On Cloud SQL / AlloyDB, create `memshield_app` with SQL first so the development default password is never used:

```sql
CREATE ROLE memshield_app LOGIN PASSWORD '<strong-password>'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
```

## 2. Wire into a Google ADK `Runner`

```python
import os
from google.adk.agents.llm_agent import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.load_memory_tool import load_memory_tool
from google.adk.tools.preload_memory_tool import preload_memory_tool

from adk_memshield import MemShieldConfig, MemShieldMemoryService

memory_service = MemShieldMemoryService(
    MemShieldConfig(
        dsn=os.environ["MEMSHIELD_DB_DSN"],
        tenant_id="tenant_alpha",
        agent_clearance=2,
        compartments=["finance"],
    )
)
memory_service.verify_rls_posture()  # fail fast at startup

runner = Runner(
    app_name="finance_copilot",
    agent=LlmAgent(
        name="assistant",
        model="gemini-3.1-flash-lite",
        tools=[preload_memory_tool, load_memory_tool],
    ),
    session_service=InMemorySessionService(),
    memory_service=memory_service,
)
```

## 3. Core store (without ADK)

```python
import os
from adk_memshield import MemoryRecord, MemShieldConfig, MemShieldStore

store = MemShieldStore(
    MemShieldConfig(dsn=os.environ["MEMSHIELD_DB_DSN"], tenant_id="tenant_alpha")
)
store.add(app_name="notes", user_id="alice", records=[MemoryRecord(text="Parking bay 4")])
hits = store.search(app_name="notes", user_id="alice", query="where do I park?")
```

## 4. Tighten-only `pre_write` hook

```python
from adk_memshield import Allow, Block, Downlabel, MemShieldMemoryService

def guard(identity, pending):
    if "ignore previous instructions" in pending.text.lower():
        return Block("prompt-injection pattern")
    if "salary" in pending.text.lower() and pending.scope == "tenant_shared":
        return Downlabel(scope="private")
    return Allow()

memory_service = MemShieldMemoryService(
    dsn=os.environ["MEMSHIELD_DB_DSN"], tenant_id="tenant_alpha", pre_write=guard
)
```
