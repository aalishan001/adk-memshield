"""Generated adk-memshield JwtIdentityVerifier configuration (review before applying)."""

from adk_memshield import JwtIdentityVerifier, MemShieldConfig, MemShieldMemoryService

verifier = JwtIdentityVerifier(
    jwks_url='https://auth.acmelending.example/.well-known/jwks.json',
    issuer='https://auth.acmelending.example/',  # required: prevents cross-issuer token confusion on shared JWKS
    audience='lending-copilot',
    algorithms=("RS256",),
    tenant_claim='org_id',
    clearance_claim='clearance_tier',
    compartments_claim='dept_compartments',
)

memory_service = MemShieldMemoryService(
    MemShieldConfig(
        dsn="postgresql://memshield_app:<from-secret-manager>@<host>:5432/memshield",
        identity_verifier=verifier,
    )
)
memory_service.verify_rls_posture()
