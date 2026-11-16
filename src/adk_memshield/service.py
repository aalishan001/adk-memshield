"""Google ADK BaseMemoryService backed by PostgreSQL pgvector + Row-Level Security."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import psycopg
from google.adk.events.event import Event
from google.adk.memory.base_memory_service import BaseMemoryService, SearchMemoryResponse
from google.adk.memory.memory_entry import MemoryEntry
from google.adk.sessions.session import Session
from google.genai import types
from psycopg_pool import ConnectionPool

from .config import MemShieldConfig
from .core import (
    MemoryRecord,
    MemShieldStore,
    QueryTelemetry,
    _format_vector,  # noqa: F401  (re-exported for 0.1.x callers)
    _get_shared_pool,  # noqa: F401  (re-exported for 0.1.x callers)
)
from .embedder import EmbedFn
from .identity import IdentityVerifier, MemShieldIdentity
from .posture import PostureReport

__all__ = ["MemShieldMemoryService", "QueryTelemetry", "register_adk_uri"]

_LABEL_KEYS = ("scope", "min_clearance", "compartments", "session_id")


def _extract_text_from_content(content: types.Content | None) -> str:
    """Extract concatenated non-empty text parts from a google.genai Content object."""
    if content is None or not content.parts:
        return ""
    texts: list[str] = []
    for part in content.parts:
        if getattr(part, "text", None):
            stripped = part.text.strip()
            if stripped:
                texts.append(stripped)
    return "\n".join(texts)


def _parse_memshield_uri(uri: str) -> tuple[str, dict[str, Any]]:
    """Parse a memshield:// or postgresql:// URI into (postgres_dsn, config_overrides)."""
    parsed = urlparse(uri)
    query_params = parse_qs(parsed.query)
    overrides: dict[str, Any] = {}

    if "tenant_id" in query_params:
        overrides["tenant_id"] = query_params.pop("tenant_id")[0]
    if "agent_clearance" in query_params:
        overrides["agent_clearance"] = int(query_params.pop("agent_clearance")[0])
    if "compartments" in query_params:
        raw = query_params.pop("compartments")[0]
        overrides["compartments"] = [c for c in raw.split(",") if c]
    if "default_scope" in query_params:
        overrides["default_scope"] = query_params.pop("default_scope")[0]
    if "default_min_clearance" in query_params:
        overrides["default_min_clearance"] = int(query_params.pop("default_min_clearance")[0])
    if "top_k" in query_params:
        overrides["top_k"] = int(query_params.pop("top_k")[0])
    if "table_name" in query_params:
        overrides["table_name"] = query_params.pop("table_name")[0]
    if "simulate_missing_app_filter" in query_params:
        val = query_params.pop("simulate_missing_app_filter")[0].lower()
        overrides["simulate_missing_app_filter"] = val in ("1", "true", "yes")

    remaining_query = urlencode(query_params, doseq=True)
    dsn = urlunparse(
        ("postgresql", parsed.netloc, parsed.path, parsed.params, remaining_query, parsed.fragment)
    )
    return dsn, overrides


class MemShieldMemoryService(BaseMemoryService):
    """Zero-trust multi-tenant semantic memory service for Google ADK.

    Enforces tenant, user, clearance and compartment boundaries in PostgreSQL with forced
    Row-Level Security and transaction-local identity. A thin layer over
    :class:`~adk_memshield.core.MemShieldStore`.

    Blocking work (ONNX embedding and psycopg I/O) runs in a worker thread via
    ``asyncio.to_thread``, so memory calls never stall the ADK event loop. The worker
    inherits the caller's context, so an identity bound with ``bind_identity`` applies.
    """

    def __init__(
        self,
        config: MemShieldConfig | None = None,
        *,
        dsn: str | None = None,
        uri: str | None = None,
        tenant_id: str | None = None,
        agent_clearance: int | None = None,
        compartments: Sequence[str] | None = None,
        default_scope: Literal["private", "tenant_shared"] | None = None,
        default_min_clearance: int | None = None,
        top_k: int | None = None,
        min_similarity: float | None = None,
        embedding_model: str | None = None,
        embedding_dim: int | None = None,
        table_name: str | None = None,
        simulate_missing_app_filter: bool | None = None,
        allow_insecure_role: bool | None = None,
        identity_verifier: IdentityVerifier | None = None,
        pre_write: Any | None = None,
        embed_fn: EmbedFn | None = None,
        pool: ConnectionPool | None = None,
    ) -> None:
        cfg_data: dict[str, Any] = dict(config) if config is not None else {}

        if uri is not None:
            parsed_dsn, uri_overrides = _parse_memshield_uri(uri)
            cfg_data["dsn"] = parsed_dsn
            cfg_data.update(uri_overrides)

        explicit_overrides = {
            "dsn": dsn,
            "tenant_id": tenant_id,
            "agent_clearance": agent_clearance,
            "compartments": compartments,
            "default_scope": default_scope,
            "default_min_clearance": default_min_clearance,
            "top_k": top_k,
            "min_similarity": min_similarity,
            "embedding_model": embedding_model,
            "embedding_dim": embedding_dim,
            "table_name": table_name,
            "simulate_missing_app_filter": simulate_missing_app_filter,
            "allow_insecure_role": allow_insecure_role,
            "identity_verifier": identity_verifier,
            "pre_write": pre_write,
        }
        for key, value in explicit_overrides.items():
            if value is not None:
                cfg_data[key] = value

        self.config = MemShieldConfig(**cfg_data)
        self.store = self._make_store(embed_fn=embed_fn, pool=pool)
        self.embedder = self.store.embedder
        self._pool = self.store.pool

    def _make_store(self, *, embed_fn: EmbedFn | None, pool: ConnectionPool | None) -> MemShieldStore:
        return MemShieldStore(self.config, embed_fn=embed_fn, pool=pool)

    @property
    def last_query_telemetry(self) -> QueryTelemetry | None:
        return self.store.last_query_telemetry

    @last_query_telemetry.setter
    def last_query_telemetry(self, value: QueryTelemetry | None) -> None:
        self.store.last_query_telemetry = value

    def resolve_identity(self, *, app_name: str, user_id: str) -> MemShieldIdentity:
        """Return the identity an operation would run under (see ``MemShieldStore``)."""
        return self.store.resolve_identity(app_name=app_name, user_id=user_id)

    def verify_rls_posture(self) -> PostureReport:
        """Fail fast if the role can bypass RLS or the table is unprotected."""
        return self.store.verify_rls_posture()

    @contextmanager
    def rls_transaction(self, *, app_name: str, user_id: str) -> Iterator[psycopg.Cursor[Any]]:
        """Yield a cursor inside an explicit transaction bound to the caller's RLS identity.

        Identity is bound with ``set_config(..., is_local => true)``, so it is discarded when
        the transaction commits or rolls back. Custom SQL on the yielded cursor is subject
        to the RLS policies even if it omits its own ownership filters.
        """
        with self.store.rls_transaction(app_name=app_name, user_id=user_id) as cur:
            yield cur

    async def add_session_to_memory(self, session: Session) -> None:
        """Extract non-empty text parts from ``session.events``, embed, and insert with RLS.

        Idempotent per event: ADK may add the same session several times during its
        lifetime, and previously stored ``(session_id, event_id)`` pairs are skipped.
        """
        session_meta: dict[str, Any] = {}
        if session.state:
            for key in ("scope", "min_clearance", "compartments"):
                if key in session.state:
                    session_meta[key] = session.state[key]

        await self.add_events_to_memory(
            app_name=session.app_name,
            user_id=session.user_id,
            events=session.events,
            session_id=session.id,
            custom_metadata=session_meta or None,
        )

    async def add_events_to_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        events: Sequence[Event],
        session_id: str | None = None,
        custom_metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Append incremental ADK events into RLS-protected semantic memory."""
        base_meta = dict(custom_metadata) if custom_metadata else {}
        entries: list[MemoryEntry] = []

        for event in events:
            text = _extract_text_from_content(event.content)
            if not text:
                continue
            author = event.author or (
                event.content.role if event.content and event.content.role else "user"
            )
            ev_meta = dict(base_meta)
            if session_id is not None:
                ev_meta.setdefault("session_id", session_id)
            if event.id:
                ev_meta.setdefault("event_id", event.id)
            entries.append(
                MemoryEntry(
                    content=types.Content(parts=[types.Part(text=text)], role=author),
                    author=author,
                    custom_metadata=ev_meta,
                )
            )

        if not entries:
            return
        await self.add_memory(
            app_name=app_name, user_id=user_id, memories=entries, custom_metadata=base_meta
        )

    async def add_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        memories: Sequence[MemoryEntry],
        custom_metadata: Mapping[str, object] | None = None,
    ) -> None:
        """Directly ingest ``MemoryEntry`` items into RLS-protected PostgreSQL storage.

        Labels are read from each entry's ``custom_metadata`` (``scope``,
        ``min_clearance``, ``compartments``, ``session_id``); ownership always comes from
        the caller's identity.
        """
        self.store.resolve_identity(app_name=app_name, user_id=user_id)  # fail fast
        await asyncio.to_thread(
            self._add_memory_sync,
            app_name=app_name,
            user_id=user_id,
            memories=memories,
            custom_metadata=custom_metadata,
        )

    def _add_memory_sync(
        self,
        *,
        app_name: str,
        user_id: str,
        memories: Sequence[MemoryEntry],
        custom_metadata: Mapping[str, object] | None,
    ) -> None:
        base_meta = dict(custom_metadata) if custom_metadata else {}
        records: list[MemoryRecord] = []
        for entry in memories:
            merged = {**base_meta, **(entry.custom_metadata or {})}
            labels = {key: merged.pop(key, None) for key in _LABEL_KEYS}
            author = entry.author or (
                entry.content.role if entry.content and entry.content.role else "user"
            )
            min_clearance = labels["min_clearance"]
            records.append(
                MemoryRecord(
                    text=_extract_text_from_content(entry.content),
                    author=author,
                    scope=labels["scope"],
                    min_clearance=int(min_clearance) if min_clearance is not None else None,
                    compartments=labels["compartments"],
                    session_id=labels["session_id"],
                    metadata=merged,
                )
            )
        ids = self.store.add(app_name=app_name, user_id=user_id, records=records)
        for entry, new_id in zip(memories, ids, strict=True):
            if new_id is not None and entry.id is None:
                entry.id = new_id

    async def search_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        query: str,
    ) -> SearchMemoryResponse:
        """Search semantic memories with transaction-local PostgreSQL RLS enforcement."""
        self.store.resolve_identity(app_name=app_name, user_id=user_id)  # fail fast
        return await asyncio.to_thread(
            self._search_memory_sync, app_name=app_name, user_id=user_id, query=query
        )

    def _search_memory_sync(self, *, app_name: str, user_id: str, query: str) -> SearchMemoryResponse:
        hits = self.store.search(app_name=app_name, user_id=user_id, query=query)
        results: list[MemoryEntry] = []
        for hit in hits:
            meta = dict(hit.metadata)
            meta.update(
                {
                    "app_name": hit.app_name,
                    "tenant_id": hit.tenant_id,
                    "user_id": hit.user_id,
                    "session_id": hit.session_id,
                    "scope": hit.scope,
                    "min_clearance": hit.min_clearance,
                    "compartments": list(hit.compartments),
                    "similarity": hit.similarity,
                }
            )
            results.append(
                MemoryEntry(
                    id=hit.id,
                    content=types.Content(parts=[types.Part(text=hit.content)], role=hit.author),
                    author=hit.author,
                    timestamp=hit.created_at.isoformat() if hit.created_at else None,
                    custom_metadata=meta,
                )
            )
        return SearchMemoryResponse(memories=results)

    async def delete_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        memory_id: str | None = None,
    ) -> None:
        """Delete a specific memory id (or all caller-owned memories) under RLS."""
        self.store.resolve_identity(app_name=app_name, user_id=user_id)  # fail fast
        await asyncio.to_thread(
            self.store.delete, app_name=app_name, user_id=user_id, memory_id=memory_id
        )


def register_adk_uri(scheme: str = "memshield") -> None:
    """Register the ``memshield://`` URI scheme with Google ADK's ServiceRegistry."""
    from google.adk.cli.service_registry import get_service_registry

    def _factory(uri: str, **kwargs: Any) -> BaseMemoryService:
        kwargs_copy = dict(kwargs)
        kwargs_copy.pop("agents_dir", None)
        return MemShieldMemoryService(uri=uri, **kwargs_copy)

    get_service_registry().register_memory_service(scheme, _factory)
