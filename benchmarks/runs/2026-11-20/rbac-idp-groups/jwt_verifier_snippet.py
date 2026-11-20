"""Generated adk-memshield JwtIdentityVerifier configuration (review before applying)."""

from adk_memshield import JwtIdentityVerifier, MemShieldConfig, MemShieldMemoryService

verifier = JwtIdentityVerifier(
    jwks_url='https://acme.okta.com/oauth2/default/v1/keys',
    issuer='https://acme.okta.com/oauth2/default',  # required: prevents cross-issuer token confusion on shared JWKS
    audience='enterprise-agent',
    algorithms=("RS256",),
    tenant_claim='tenant',
    clearance_claim='clearance',
    compartments_claim='groups',
)

memory_service = MemShieldMemoryService(
    MemShieldConfig(
        dsn="postgresql://memshield_app:<from-secret-manager>@<host>:5432/memshield",
        identity_verifier=verifier,
    )
)
memory_service.verify_rls_posture()
