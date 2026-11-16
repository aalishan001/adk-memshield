"""Framework-neutral core: RLS-bound add / search / delete over PostgreSQL + pgvector.

Nothing here imports an agent framework. :class:`~adk_memshield.service.MemShieldMemoryService`
(Google ADK) and the adapters in :mod:`adk_memshield.adapters` are thin layers on
:class:`MemShieldStore`.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import weakref
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, ClassVar

import psycopg
from psycopg_pool import ConnectionPool

from .config import MemShieldConfig
from .embedder import EmbedFn, MemShieldEmbedder
from .errors import MemShieldIdentityError
from .hooks import Allow, Block, Downlabel, PendingMemory, apply_downlabel
from .identity import MemShieldIdentity, current_identity_token, validate_compartments
from .posture import PostureReport, enforce_rls_posture

logger = logging.getLogger("adk_memshield")

_SHARED_POOLS: dict[str, ConnectionPool] = {}
_SHARED_POOLS_LOCK = threading.Lock()

# Pools whose role/table posture has been verified, keyed weakly so a closed pool's entry
# disappears with it. Value: the set of table names verified on that pool.
_POSTURE_VERIFIED: weakref.WeakKeyDictionary[ConnectionPool, set[str]] = weakref.WeakKeyDictionary()
_POSTURE_LOCK = threading.Lock()


def reset_connection(conn: psycopg.Connection[Any]) -> None:
    """Pool ``reset`` callback: drop session-level settings when a connection is returned.

    memshield binds identity with transaction-local ``set_config(..., true)``, which
    PostgreSQL discards at commit or rollback. Custom SQL on the cursor yielded by
    ``rls_transaction`` could still set an ``app.*`` value at *session* level; ``RESET ALL``
    removes it before the connection is lent to anyone else. memshield's own pools use this
    callback. If you pass your own ``pool=``, create it with ``reset=reset_connection``.
    """
    conn.execute("RESET ALL")
    conn.commit()


def _get_shared_pool(dsn: str) -> ConnectionPool:
    """Return a process-shared ConnectionPool keyed by PostgreSQL DSN."""
    with _SHARED_POOLS_LOCK:
        pool = _SHARED_POOLS.get(dsn)
        if pool is None or pool.closed:
            pool = ConnectionPool(
                conninfo=dsn, min_size=1, max_size=8, open=True, reset=reset_connection
            )
            _SHARED_POOLS[dsn] = pool
        return pool


def _format_vector(vec: Sequence[float]) -> str:
    """Serialize a float sequence as a pgvector literal string."""
    return "[" + ",".join(f"{float(x):.8f}" for x in vec) + "]"


def _require_names(app_name: str, user_id: str) -> None:
    """Reject empty identities before they reach the database (fail closed)."""
    if not app_name or not str(app_name).strip():
        raise ValueError("app_name must be a non-empty string")
    if not user_id or not str(user_id).strip():
        raise ValueError("user_id must be a non-empty string")


@dataclass
class QueryTelemetry(Mapping[str, Any]):
    """Telemetry snapshot of the last operation (``last_query_telemetry``).

    Supports both attribute access (``telemetry.latency_ms``) and dictionary access
    (``telemetry["latency_ms"]``).
    """

    operation: str
    sql: str
    session_context: dict[str, str]
    latency_ms: float
    row_count: int
    simulate_missing_app_filter: bool
    table_name: str
    blocked_writes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return asdict(self)[key]

    def __iter__(self) -> Iterator[str]:
        return iter(asdict(self))

    def __len__(self) -> int:
        return len(asdict(self))


@dataclass
class MemoryRecord:
    """A memory to store. ``None`` labels fall back to the configured defaults."""

    text: str
    author: str = "user"
    scope: str | None = None
    min_clearance: int | None = None
    compartments: Sequence[str] | None = None
    session_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MemoryHit:
    """A memory returned by :meth:`MemShieldStore.search`."""

    id: str
    app_name: str
    tenant_id: str
    user_id: str
    session_id: str | None
    author: str
    scope: str
    min_clearance: int
    compartments: tuple[str, ...]
    content: str
    metadata: dict[str, Any]
    created_at: datetime | None
    similarity: float


_SELECT_COLUMNS = """
    id, app_name, tenant_id, user_id, session_id, author,
    scope, min_clearance, compartments, content, custom_metadata, created_at,
    1 - (embedding <=> %s::vector) AS similarity
"""


class MemShieldStore:
    """RLS-enforced semantic memory store, independent of any agent framework.

    Every operation runs in one explicit transaction that binds the caller's identity with
    ``set_config(..., true)`` (transaction-local), and pins ``plan_cache_mode`` to
    ``force_custom_plan`` in the same statement so a cached generic plan can never turn an
    HNSW scan into a silent post-filter (see the README section on ANN indexes).
    """

    #: Plan cache mode bound in every transaction. Override to ``"auto"`` only to
    #: reproduce the 0.1.x behaviour in a benchmark.
    plan_cache_mode: ClassVar[str] = "force_custom_plan"

    def __init__(
        self,
        config: MemShieldConfig,
        *,
        embed_fn: EmbedFn | None = None,
        pool: ConnectionPool | None = None,
    ) -> None:
        self.config = config
        self.embedder = MemShieldEmbedder(
            model_name=config.embedding_model,
            expected_dim=config.embedding_dim,
            embed_fn=embed_fn,
        )
        self._pool = pool if pool is not None else _get_shared_pool(config.dsn)
        self.last_query_telemetry: QueryTelemetry | None = None

    @property
    def pool(self) -> ConnectionPool:
        return self._pool

    # ------------------------------------------------------------------ identity
    def resolve_identity(self, *, app_name: str, user_id: str) -> MemShieldIdentity:
        """Return the identity an operation for ``(app_name, user_id)`` runs under.

        Without a verifier this is trusted caller mode: ``user_id`` as given, tenant,
        clearance and compartments from the config. With a verifier, the bound token must
        verify for audience ``app_name`` and its subject must equal ``user_id``.
        """
        _require_names(app_name, user_id)
        verifier = self.config.identity_verifier
        if verifier is None:
            return MemShieldIdentity(
                tenant_id=self.config.tenant_id,
                user_id=str(user_id),
                clearance=self.config.agent_clearance,
                compartments=self.config.compartments,
            )
        token = current_identity_token()
        if not token:
            raise MemShieldIdentityError(
                "an identity verifier is configured but no identity token is bound "
                "(wrap the request in adk_memshield.bind_identity(token))"
            )
        try:
            identity = verifier.verify(token, audience=str(app_name))
        except MemShieldIdentityError:
            raise
        except Exception as exc:  # never echo the token
            raise MemShieldIdentityError(
                f"identity verification failed ({type(exc).__name__})"
            ) from None
        if not isinstance(identity, MemShieldIdentity):
            raise MemShieldIdentityError("identity verifier did not return a MemShieldIdentity")
        if identity.user_id != str(user_id):
            raise MemShieldIdentityError(
                "the requested user_id does not match the verified identity token"
            )
        return identity

    def _context(self, app_name: str, identity: MemShieldIdentity) -> dict[str, str]:
        return {
            "app.current_app_name": str(app_name),
            "app.current_tenant_id": identity.tenant_id,
            "app.current_user_id": identity.user_id,
            "app.agent_clearance": str(identity.clearance),
            "app.agent_compartments": ",".join(identity.compartments),
            "plan_cache_mode": self.plan_cache_mode,
        }

    # ------------------------------------------------------------------ posture
    def _check_posture(self, cur: psycopg.Cursor[Any]) -> None:
        table = self.config.table_name
        if self.config.allow_insecure_role:
            # Inspect once per pool and table like the secure path, but warn on every use.
            key = f"insecure:{table}"
            with _POSTURE_LOCK:
                known = _POSTURE_VERIFIED.get(self._pool)
                cached = known is not None and key in known
            if cached:
                logger.warning(
                    "adk-memshield running WITHOUT row-level security protection on %r "
                    "(allow_insecure_role=True)",
                    table,
                )
                return
            report = enforce_rls_posture(cur, table, allow_insecure_role=True)
            with _POSTURE_LOCK:
                _POSTURE_VERIFIED.setdefault(self._pool, set()).add(
                    table if report.ok else key
                )
            return
        with _POSTURE_LOCK:
            verified = _POSTURE_VERIFIED.get(self._pool)
            if verified is not None and table in verified:
                return
        enforce_rls_posture(cur, table)
        with _POSTURE_LOCK:
            _POSTURE_VERIFIED.setdefault(self._pool, set()).add(table)

    def verify_rls_posture(self) -> PostureReport:
        """Check now that the role cannot bypass RLS and the table is protected.

        Runs automatically (once per pool and table) before the first operation; call it at
        startup to fail fast. Raises :class:`MemShieldConfigurationError` on any problem
        (or only warns with ``allow_insecure_role=True``).
        """
        with self._pool.connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    report = enforce_rls_posture(
                        cur,
                        self.config.table_name,
                        allow_insecure_role=self.config.allow_insecure_role,
                    )
        if report.ok:
            with _POSTURE_LOCK:
                _POSTURE_VERIFIED.setdefault(self._pool, set()).add(self.config.table_name)
        return report

    # ------------------------------------------------------------------ transaction
    @contextmanager
    def rls_transaction(
        self,
        *,
        app_name: str,
        user_id: str,
        identity: MemShieldIdentity | None = None,
    ) -> Iterator[psycopg.Cursor[Any]]:
        """Yield a cursor in an explicit transaction bound to the caller's RLS identity.

        Identity, compartments and ``plan_cache_mode`` are bound with one
        ``set_config(..., true)`` statement, so they are discarded at commit or rollback.
        Any custom SQL on the yielded cursor is subject to the RLS policies even if it omits
        its own ownership filters.
        """
        if identity is None:
            identity = self.resolve_identity(app_name=app_name, user_id=user_id)
        context = self._context(app_name, identity)
        with self._pool.connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    self._check_posture(cur)
                    cur.execute(
                        """
                        SELECT
                            set_config('app.current_app_name', %s, true),
                            set_config('app.current_tenant_id', %s, true),
                            set_config('app.current_user_id', %s, true),
                            set_config('app.agent_clearance', %s, true),
                            set_config('app.agent_compartments', %s, true),
                            set_config('plan_cache_mode', %s, true);
                        """,
                        (
                            context["app.current_app_name"],
                            context["app.current_tenant_id"],
                            context["app.current_user_id"],
                            context["app.agent_clearance"],
                            context["app.agent_compartments"],
                            context["plan_cache_mode"],
                        ),
                    )
                    yield cur

    # ------------------------------------------------------------------ write
    def _pending(self, record: MemoryRecord) -> PendingMemory:
        scope = record.scope if record.scope is not None else self.config.default_scope
        if scope not in ("private", "tenant_shared"):
            raise ValueError(f"invalid scope: {scope!r}")
        min_clearance = (
            record.min_clearance
            if record.min_clearance is not None
            else self.config.default_min_clearance
        )
        if isinstance(min_clearance, bool) or not isinstance(min_clearance, int):
            min_clearance = int(min_clearance)
        return PendingMemory(
            text=record.text,
            author=record.author or "user",
            scope=scope,  # type: ignore[arg-type]
            min_clearance=min_clearance,
            compartments=validate_compartments(record.compartments),
            session_id=record.session_id,
            metadata=dict(record.metadata),
        )

    def _run_hook(self, identity: MemShieldIdentity, pending: PendingMemory) -> PendingMemory | None:
        hook = self.config.pre_write
        if hook is None:
            return pending
        try:
            decision = hook(identity, pending)
        except Exception as exc:
            logger.warning("pre_write hook raised %s; memory not stored", type(exc).__name__)
            return None
        if isinstance(decision, Allow):
            return pending
        if isinstance(decision, Block):
            logger.info("pre_write hook blocked a memory: %s", decision.reason)
            return None
        if isinstance(decision, Downlabel):
            return apply_downlabel(pending, decision)
        raise TypeError(f"pre_write hook returned {type(decision).__name__}, not Allow/Downlabel/Block")

    def add(
        self, *, app_name: str, user_id: str, records: Sequence[MemoryRecord]
    ) -> list[str | None]:
        """Store ``records`` for the caller. Returns one id per record.

        The id is ``None`` for an empty text, a duplicate ``(session_id, event_id)`` or a
        memory the ``pre_write`` hook blocked. Ownership columns always come from the
        resolved identity, never from record metadata.
        """
        identity = self.resolve_identity(app_name=app_name, user_id=user_id)
        ids: list[str | None] = [None] * len(records)
        to_store: list[tuple[int, PendingMemory]] = []
        blocked = 0
        for idx, record in enumerate(records):
            if not record.text or not record.text.strip():
                continue
            pending = self._run_hook(identity, self._pending(record))
            if pending is None:
                blocked += 1
                continue
            to_store.append((idx, pending))

        table = self.config.table_name
        insert_sql = f"""
            INSERT INTO {table} (
                app_name, tenant_id, user_id, session_id, author,
                scope, min_clearance, compartments, content, custom_metadata, embedding
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s::text[], %s, %s::jsonb, %s::vector)
            ON CONFLICT (app_name, tenant_id, user_id, session_id, (custom_metadata->>'event_id'))
                WHERE custom_metadata ? 'event_id'
                DO NOTHING
            RETURNING id
        """
        context = self._context(app_name, identity)
        if not to_store:
            self.last_query_telemetry = QueryTelemetry(
                operation="add_memory",
                sql=insert_sql.strip(),
                session_context=context,
                latency_ms=0.0,
                row_count=0,
                simulate_missing_app_filter=self.config.simulate_missing_app_filter,
                table_name=table,
                blocked_writes=blocked,
            )
            return ids

        embeddings = self.embedder.embed_documents([p.text for _, p in to_store])
        t0 = time.perf_counter()
        inserted = 0
        with self.rls_transaction(app_name=app_name, user_id=user_id, identity=identity) as cur:
            for (idx, pending), vec in zip(to_store, embeddings, strict=True):
                cur.execute(
                    insert_sql,
                    (
                        app_name,
                        identity.tenant_id,
                        identity.user_id,
                        pending.session_id,
                        pending.author,
                        pending.scope,
                        pending.min_clearance,
                        list(pending.compartments),
                        pending.text,
                        json.dumps(dict(pending.metadata)),
                        _format_vector(vec),
                    ),
                )
                row = cur.fetchone()
                if row is None:
                    continue  # duplicate (session_id, event_id) already stored
                ids[idx] = str(row[0])
                inserted += 1
        self.last_query_telemetry = QueryTelemetry(
            operation="add_memory",
            sql=insert_sql.strip(),
            session_context=context,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            row_count=inserted,
            simulate_missing_app_filter=self.config.simulate_missing_app_filter,
            table_name=table,
            blocked_writes=blocked,
        )
        return ids

    # ------------------------------------------------------------------ read
    def search(
        self,
        *,
        app_name: str,
        user_id: str,
        query: str,
        top_k: int | None = None,
    ) -> list[MemoryHit]:
        """Semantic search under the caller's RLS identity."""
        identity = self.resolve_identity(app_name=app_name, user_id=user_id)
        limit = self.config.top_k if top_k is None else int(top_k)
        if limit < 1:
            raise ValueError("top_k must be at least 1")
        vec_literal = _format_vector(self.embedder.embed_query(query))
        table = self.config.table_name

        if self.config.simulate_missing_app_filter:
            sql = f"""
                SELECT {_SELECT_COLUMNS}
                FROM {table}
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """
            params: tuple[Any, ...] = (vec_literal, vec_literal, limit)
        else:
            # Defense in depth: the application filter mirrors the RLS SELECT policy, so
            # neither layer alone is a single point of failure.
            sql = f"""
                SELECT {_SELECT_COLUMNS}
                FROM {table}
                WHERE app_name = %s AND tenant_id = %s
                  AND (
                    user_id = %s
                    OR (
                      scope = 'tenant_shared' AND min_clearance <= %s
                      AND (cardinality(compartments) = 0 OR compartments && %s::text[])
                    )
                  )
                ORDER BY embedding <=> %s::vector
                LIMIT %s
            """
            params = (
                vec_literal,
                app_name,
                identity.tenant_id,
                identity.user_id,
                identity.clearance,
                list(identity.compartments),
                vec_literal,
                limit,
            )

        t0 = time.perf_counter()
        with self.rls_transaction(app_name=app_name, user_id=user_id, identity=identity) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
        latency_ms = (time.perf_counter() - t0) * 1000.0

        hits: list[MemoryHit] = []
        for (
            row_id,
            row_app,
            row_tenant,
            row_user,
            row_session,
            row_author,
            row_scope,
            row_min_clearance,
            row_compartments,
            row_content,
            row_meta,
            row_created,
            row_similarity,
        ) in rows:
            similarity = float(row_similarity)
            if self.config.min_similarity is not None and similarity < self.config.min_similarity:
                continue
            hits.append(
                MemoryHit(
                    id=str(row_id),
                    app_name=row_app,
                    tenant_id=row_tenant,
                    user_id=row_user,
                    session_id=row_session,
                    author=row_author or "user",
                    scope=row_scope,
                    min_clearance=int(row_min_clearance),
                    compartments=tuple(row_compartments or ()),
                    content=str(row_content),
                    metadata=dict(row_meta) if isinstance(row_meta, Mapping) else {},
                    created_at=row_created,
                    similarity=similarity,
                )
            )

        self.last_query_telemetry = QueryTelemetry(
            operation="search_memory",
            sql=sql.strip(),
            session_context=self._context(app_name, identity),
            latency_ms=latency_ms,
            row_count=len(hits),
            simulate_missing_app_filter=self.config.simulate_missing_app_filter,
            table_name=table,
        )
        return hits

    # ------------------------------------------------------------------ delete
    def delete(self, *, app_name: str, user_id: str, memory_id: str | None = None) -> int:
        """Delete one memory id, or every memory the caller owns. Returns rows deleted."""
        identity = self.resolve_identity(app_name=app_name, user_id=user_id)
        table = self.config.table_name
        owner_filter = "app_name = %s AND tenant_id = %s AND user_id = %s"
        owner_params: tuple[Any, ...] = (app_name, identity.tenant_id, identity.user_id)
        if memory_id is not None:
            sql = f"DELETE FROM {table} WHERE id = %s::uuid AND {owner_filter}"
            params: tuple[Any, ...] = (memory_id, *owner_params)
        else:
            sql = f"DELETE FROM {table} WHERE {owner_filter}"
            params = owner_params

        t0 = time.perf_counter()
        with self.rls_transaction(app_name=app_name, user_id=user_id, identity=identity) as cur:
            cur.execute(sql, params)
            deleted = cur.rowcount if cur.rowcount is not None else 0
        self.last_query_telemetry = QueryTelemetry(
            operation="delete_memory",
            sql=sql,
            session_context=self._context(app_name, identity),
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            row_count=deleted,
            simulate_missing_app_filter=self.config.simulate_missing_app_filter,
            table_name=table,
        )
        return deleted
