"""Configuration models for adk-memshield."""

from __future__ import annotations

import os
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .identity import validate_compartments

_SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class MemShieldConfig(BaseModel):
    """Configuration for :class:`MemShieldMemoryService` and :class:`MemShieldStore`.

    Attributes:
        dsn: PostgreSQL connection URI using a non-superuser, NOBYPASSRLS role (e.g.
            ``memshield_app``) so Row-Level Security (RLS) policies are enforced. memshield
            checks this on first use and refuses to run otherwise.
        tenant_id: Tenant bound to ``app.current_tenant_id`` in trusted caller mode (no
            identity verifier). With a verifier, the tenant comes from the token.
        agent_clearance: Clearance (1..5) bound to ``app.agent_clearance`` in trusted
            caller mode. With a verifier, it comes from the token.
        compartments: Compartments bound to ``app.agent_compartments`` in trusted caller
            mode. A caller reads ``tenant_shared`` rows that carry no compartments, or at
            least one of its own. With a verifier, they come from the token.
        default_scope: Default visibility scope for new memories (``'private'`` or
            ``'tenant_shared'``).
        default_min_clearance: Default minimum clearance (1..5) required to read
            ``'tenant_shared'`` memories.
        top_k: Maximum number of memories returned by a search.
        min_similarity: Optional minimum cosine similarity for retrieval.
        embedding_model: FastEmbed ONNX model identifier.
        embedding_dim: Expected embedding dimensionality.
        table_name: Target table (``'memories'`` by default). Validated as an identifier.
        simulate_missing_app_filter: Chaos/testing flag. When True, searches run with no
            application-layer ``WHERE`` clause, to show that RLS alone still isolates.
        allow_insecure_role: Benchmarks and tests only. Run even if the connection role
            bypasses RLS or the table is unprotected, logging a warning on every check.
        identity_verifier: Optional :class:`~adk_memshield.identity.IdentityVerifier`.
            When set, every operation needs a token bound with ``bind_identity``.
        pre_write: Optional hook called before each memory is stored; see
            :mod:`adk_memshield.hooks`. It may only tighten labels or block.
    """

    model_config = ConfigDict(validate_assignment=True, extra="forbid", arbitrary_types_allowed=True)

    dsn: str = Field(
        default_factory=lambda: os.environ.get(
            "MEMSHIELD_DB_DSN",
            "postgresql://memshield_app:memshield_pass@localhost:54329/memshield",
        )
    )
    tenant_id: str = Field(default="default", min_length=1)
    agent_clearance: int = Field(default=1, ge=1, le=5)
    compartments: tuple[str, ...] = Field(default=())
    default_scope: Literal["private", "tenant_shared"] = Field(default="private")
    default_min_clearance: int = Field(default=1, ge=1, le=5)
    top_k: int = Field(default=5, ge=1, le=100)
    min_similarity: float | None = Field(default=None, ge=-1.0, le=1.0)
    embedding_model: str = Field(default="BAAI/bge-small-en-v1.5")
    embedding_dim: int = Field(default=384, ge=1)
    table_name: str = Field(default="memories")
    simulate_missing_app_filter: bool = Field(default=False)
    allow_insecure_role: bool = Field(default=False)
    identity_verifier: Any | None = Field(default=None)
    pre_write: Any | None = Field(default=None)

    @field_validator("table_name")
    @classmethod
    def _validate_table_name(cls, value: str) -> str:
        if not _SAFE_IDENTIFIER_RE.match(value):
            raise ValueError(f"Unsafe SQL table identifier: {value!r}")
        return value

    @field_validator("compartments", mode="before")
    @classmethod
    def _validate_compartments(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()
        return validate_compartments(value)

    @field_validator("identity_verifier")
    @classmethod
    def _validate_verifier(cls, value: Any) -> Any:
        if value is not None and not callable(getattr(value, "verify", None)):
            raise ValueError("identity_verifier must have a verify(token, *, audience) method")
        return value

    @field_validator("pre_write")
    @classmethod
    def _validate_pre_write(cls, value: Any) -> Any:
        if value is not None and not callable(value):
            raise ValueError("pre_write must be callable")
        return value
