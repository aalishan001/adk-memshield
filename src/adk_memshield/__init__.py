"""adk-memshield: zero-trust multi-tenant semantic memory for AI agents (Google ADK first).

Isolation between tenants, users, clearance levels and compartments is enforced by
PostgreSQL forced Row-Level Security, not by application ``WHERE`` clauses.
"""

from .config import MemShieldConfig
from .core import MemoryHit, MemoryRecord, MemShieldStore, QueryTelemetry, reset_connection
from .embedder import EmbedFn, MemShieldEmbedder
from .errors import MemShieldConfigurationError, MemShieldError, MemShieldIdentityError
from .hooks import Allow, Block, Decision, Downlabel, PendingMemory, PreWriteHook
from .identity import (
    HmacIdentityVerifier,
    IdentityVerifier,
    JwtIdentityVerifier,
    MemShieldIdentity,
    bind_identity,
    current_identity_token,
    issue_hmac_token,
)
from .posture import PostureReport
from .service import MemShieldMemoryService, register_adk_uri

__version__ = "0.2.2"

__all__ = [
    "Allow",
    "Block",
    "Decision",
    "Downlabel",
    "EmbedFn",
    "HmacIdentityVerifier",
    "IdentityVerifier",
    "JwtIdentityVerifier",
    "MemShieldConfig",
    "MemShieldConfigurationError",
    "MemShieldEmbedder",
    "MemShieldError",
    "MemShieldIdentity",
    "MemShieldIdentityError",
    "MemShieldMemoryService",
    "MemShieldStore",
    "MemoryHit",
    "MemoryRecord",
    "PendingMemory",
    "PostureReport",
    "PreWriteHook",
    "QueryTelemetry",
    "bind_identity",
    "current_identity_token",
    "issue_hmac_token",
    "register_adk_uri",
    "reset_connection",
]
