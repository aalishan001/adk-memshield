"""Model Context Protocol server over :class:`~adk_memshield.core.MemShieldStore`.

Install with ``pip install 'adk-memshield[mcp]'``. Three tools: ``remember``, ``recall`` and
``forget``. Isolation is the same database-enforced RLS as the ADK service.

Identity
--------
* **Streamable HTTP** needs an identity verifier. Each request carries a signed identity
  token in ``Authorization: Bearer <token>``; tenant, user, clearance and compartments come
  from the verified token. Without a verifier the HTTP server refuses to start, and a
  request without a valid token is refused. (The header is only a carrier: the token is
  verified cryptographically, never trusted as sent.)
* **stdio** serves one local user. With a verifier, the token is read from the
  ``MEMSHIELD_IDENTITY_TOKEN`` environment variable and verified on every call. Without
  one, the server runs in trusted mode for the ``user_id`` given at start-up, with tenant,
  clearance and compartments from the config.

Run it::

    memshield-mcp --transport stdio --app my_agent --user alice
    MEMSHIELD_HMAC_KEYS='{"k1": "<32+ byte secret>"}' memshield-mcp --transport http --app my_agent
"""


import argparse
import asyncio
import json
import os
from collections.abc import Mapping
from typing import Any

from ..config import MemShieldConfig
from ..core import MemoryRecord, MemShieldStore
from ..errors import MemShieldConfigurationError, MemShieldIdentityError
from ..identity import HmacIdentityVerifier, MemShieldIdentity, bind_identity

TOKEN_ENV = "MEMSHIELD_IDENTITY_TOKEN"


def _request_headers(ctx: Any) -> Mapping[str, str] | None:
    """HTTP headers of the current MCP request, or ``None`` when there is no request context.

    On the HTTP transport ``None`` makes the call fail closed; on stdio headers are ignored.
    """
    try:
        return ctx.headers
    except (AttributeError, LookupError, RuntimeError, ValueError):  # no active request context
        return None


def _bearer(headers: Mapping[str, str] | None) -> str | None:
    if not headers:
        return None
    for key, value in headers.items():
        if key.lower() == "authorization":
            scheme, _, token = value.partition(" ")
            if scheme.lower() == "bearer" and token.strip():
                return token.strip()
            return None
    return None


class MemShieldMcpTools:
    """The tool logic, independent of the MCP SDK (and directly testable).

    ``transport`` is fixed at construction. ``"http"`` requires an identity verifier and
    takes the token only from the request's ``Authorization`` header (never from the
    environment); a call without request headers is refused. ``"stdio"`` ignores headers
    and uses ``MEMSHIELD_IDENTITY_TOKEN`` (with a verifier) or the trusted ``user_id``.
    """

    def __init__(
        self,
        store: MemShieldStore,
        *,
        app_name: str,
        user_id: str | None = None,
        transport: str = "stdio",
        environ: Mapping[str, str] | None = None,
    ) -> None:
        if not app_name or not app_name.strip():
            raise ValueError("app_name must be a non-empty string")
        if transport not in ("stdio", "http"):
            raise ValueError("transport must be 'stdio' or 'http'")
        if transport == "http" and store.config.identity_verifier is None:
            raise MemShieldConfigurationError("the HTTP transport needs an identity verifier")
        if store.config.identity_verifier is None and not user_id:
            raise MemShieldConfigurationError(
                "without an identity verifier the MCP server serves one trusted local user: "
                "pass user_id"
            )
        self.store = store
        self.app_name = app_name
        self.user_id = user_id
        self.transport = transport
        self._environ = os.environ if environ is None else environ

    def _token_for(self, headers: Mapping[str, str] | None) -> str | None:
        if self.transport == "http":
            if headers is None:
                raise MemShieldIdentityError("no HTTP request context: refusing the call")
            return _bearer(headers)
        return self._environ.get(TOKEN_ENV) or None

    def _identity(self, headers: Mapping[str, str] | None) -> tuple[MemShieldIdentity, str | None]:
        verifier = self.store.config.identity_verifier
        token = self._token_for(headers)
        if verifier is None:
            assert self.user_id is not None
            return self.store.resolve_identity(app_name=self.app_name, user_id=self.user_id), None
        if not token:
            raise MemShieldIdentityError("no identity token (send Authorization: Bearer <token>)")
        try:
            identity = verifier.verify(token, audience=self.app_name)
        except MemShieldIdentityError:
            raise
        except Exception as exc:
            raise MemShieldIdentityError(f"identity verification failed ({type(exc).__name__})") from None
        if self.user_id is not None and identity.user_id != self.user_id:
            raise MemShieldIdentityError("the identity token is for a different user than this server")
        return identity, token

    async def _run(self, headers: Mapping[str, str] | None, fn: Any) -> Any:
        identity, token = self._identity(headers)

        def call() -> Any:
            if token is None:
                return fn(identity)
            with bind_identity(token):
                return fn(identity)

        return await asyncio.to_thread(call)

    async def remember(
        self,
        text: str,
        *,
        shared: bool = False,
        min_clearance: int | None = None,
        compartments: list[str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        if not text or not text.strip():
            raise ValueError("text must not be empty")

        def op(identity: MemShieldIdentity) -> dict[str, Any]:
            record = MemoryRecord(
                text=text,
                author="user",
                scope="tenant_shared" if shared else "private",
                min_clearance=min_clearance,
                compartments=compartments,
            )
            ids = self.store.add(app_name=self.app_name, user_id=identity.user_id, records=[record])
            return {"id": ids[0], "stored": ids[0] is not None}

        return await self._run(headers, op)

    async def recall(
        self, query: str, *, top_k: int | None = None, headers: Mapping[str, str] | None = None
    ) -> list[dict[str, Any]]:
        def op(identity: MemShieldIdentity) -> list[dict[str, Any]]:
            hits = self.store.search(
                app_name=self.app_name, user_id=identity.user_id, query=query, top_k=top_k
            )
            return [
                {
                    "id": h.id,
                    "text": h.content,
                    "owner": h.user_id,
                    "tenant": h.tenant_id,
                    "scope": h.scope,
                    "min_clearance": h.min_clearance,
                    "compartments": list(h.compartments),
                    "similarity": round(h.similarity, 6),
                    "created_at": h.created_at.isoformat() if h.created_at else None,
                }
                for h in hits
            ]

        return await self._run(headers, op)

    async def forget(self, memory_id: str, *, headers: Mapping[str, str] | None = None) -> dict[str, Any]:
        def op(identity: MemShieldIdentity) -> dict[str, Any]:
            deleted = self.store.delete(
                app_name=self.app_name, user_id=identity.user_id, memory_id=memory_id
            )
            return {"deleted": deleted}

        return await self._run(headers, op)


def create_mcp_server(
    store: MemShieldStore,
    *,
    app_name: str,
    user_id: str | None = None,
    name: str = "adk-memshield",
    transport: str = "stdio",
) -> Any:
    """Build an ``mcp.server.mcpserver.MCPServer`` exposing remember / recall / forget.

    ``transport`` must match how you run the server: ``"http"`` for streamable HTTP
    (requires an identity verifier), ``"stdio"`` otherwise.
    """
    try:
        from mcp.server.mcpserver import Context, MCPServer
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError("the MCP adapter needs the MCP SDK: pip install 'adk-memshield[mcp]'") from exc

    tools = MemShieldMcpTools(store, app_name=app_name, user_id=user_id, transport=transport)
    server = MCPServer(
        name=name,
        instructions=(
            "Long-term memory isolated per tenant, user, clearance and compartment by "
            "PostgreSQL row-level security. recall only ever returns memories the caller "
            "is entitled to read."
        ),
    )

    @server.tool(description="Store a memory for the calling user. shared=True makes it readable "
                 "by others in the tenant at or above min_clearance and in one of its compartments.")
    async def remember(
        text: str,
        ctx: Context,
        shared: bool = False,
        min_clearance: int | None = None,
        compartments: list[str] | None = None,
    ) -> dict[str, Any]:
        return await tools.remember(
            text, shared=shared, min_clearance=min_clearance, compartments=compartments,
            headers=_request_headers(ctx),
        )

    @server.tool(description="Semantic search over the memories the calling user may read.")
    async def recall(query: str, ctx: Context, top_k: int | None = None) -> list[dict[str, Any]]:
        return await tools.recall(query, top_k=top_k, headers=_request_headers(ctx))

    @server.tool(description="Delete one of the calling user's own memories by id.")
    async def forget(memory_id: str, ctx: Context) -> dict[str, Any]:
        return await tools.forget(memory_id, headers=_request_headers(ctx))

    server.memshield_tools = tools  # type: ignore[attr-defined]
    return server


def _verifier_from_env() -> HmacIdentityVerifier | None:
    raw = os.environ.get("MEMSHIELD_HMAC_KEYS")
    if not raw:
        return None
    keys = json.loads(raw)
    if not isinstance(keys, dict) or not keys:
        raise MemShieldConfigurationError("MEMSHIELD_HMAC_KEYS must be a JSON object {kid: secret}")
    return HmacIdentityVerifier(keys)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="memshield-mcp", description="adk-memshield MCP server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--app", required=True, help="application name bound to app.current_app_name")
    parser.add_argument("--user", help="stdio without a verifier: the one trusted local user")
    parser.add_argument("--dsn", default=None, help="defaults to $MEMSHIELD_DB_DSN")
    parser.add_argument("--tenant", default="default", help="trusted mode tenant")
    parser.add_argument("--clearance", type=int, default=1, help="trusted mode clearance")
    parser.add_argument("--compartments", default="", help="trusted mode, comma-separated")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    verifier = _verifier_from_env()
    if args.transport == "http" and verifier is None:
        raise MemShieldConfigurationError(
            "the HTTP transport needs an identity verifier: set MEMSHIELD_HMAC_KEYS"
        )
    config_kwargs: dict[str, Any] = {
        "tenant_id": args.tenant,
        "agent_clearance": args.clearance,
        "compartments": [c for c in args.compartments.split(",") if c],
        "identity_verifier": verifier,
    }
    if args.dsn:
        config_kwargs["dsn"] = args.dsn
    store = MemShieldStore(MemShieldConfig(**config_kwargs))
    store.verify_rls_posture()
    server = create_mcp_server(store, app_name=args.app, user_id=args.user, transport=args.transport)
    if args.transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
