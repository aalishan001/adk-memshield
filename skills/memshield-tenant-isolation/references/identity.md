# Identity Binding Reference (`adk-memshield`)

## Verified identity: one service instance for every tenant

In multi-tenant deployments, bind caller identity from a verified token on every request instead of passing tenant or user IDs from application prompts or tool parameters.

### OIDC / JWT (`JwtIdentityVerifier`, requires `adk-memshield[jwt]`)

Works with Google Cloud Identity Platform, Firebase Auth, or any standard OIDC provider:

```python
import os
from adk_memshield import JwtIdentityVerifier, MemShieldMemoryService, bind_identity

verifier = JwtIdentityVerifier(
    jwks_url="https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
    issuer="https://securetoken.google.com/YOUR_PROJECT_ID",
)
memory_service = MemShieldMemoryService(
    dsn=os.environ["MEMSHIELD_DB_DSN"],
    identity_verifier=verifier,
)

# Per HTTP/RPC request, pass the bearer token verified from the Authorization header:
with bind_identity(request_bearer_token):
    async for event in runner.run_async(user_id=token_sub, session_id=sid, new_message=msg):
        ...
```

Rules enforced by `JwtIdentityVerifier`:
- `issuer=` is mandatory so a shared multi-tenant JWKS cannot accept tokens minted for another tenant or project.
- Missing, invalid, or expired tokens, wrong `audience`/`app_name`, or a mismatched ADK `user_id` vs token subject raise `MemShieldIdentityError` before any SQL runs.
- Tokens are never logged.

### HMAC (`HmacIdentityVerifier`, built in)

```python
import os
from adk_memshield import HmacIdentityVerifier, MemShieldMemoryService, bind_identity

verifier = HmacIdentityVerifier({"2026-11": KEY_BYTES})
memory_service = MemShieldMemoryService(
    dsn=os.environ["MEMSHIELD_DB_DSN"],
    identity_verifier=verifier,
)

token = verifier.issue(
    kid="2026-11",
    user_id="alice",
    tenant_id="tenant_alpha",
    audience="finance_copilot",
    clearance=2,
    compartments=["finance"],
)
with bind_identity(token):
    ...
```

## Access rules enforced in PostgreSQL RLS
- A caller reads their own rows (any scope/clearance/compartments) plus `tenant_shared` rows at or below their `agent_clearance` that either carry no compartments (`{}`) or share at least one compartment with the caller.
- `INSERT`, `UPDATE`, and `DELETE` are restricted to the caller's own rows; an agent cannot write a `tenant_shared` memory above its own clearance or tag compartments it does not hold.
- Every identity setting is bound with `set_config('app.*', val, true)` (transaction-local `SET LOCAL`) inside an explicit transaction and cleared automatically at commit or rollback.
