"""M6: the MCP server end to end (in-process stdio-style calls and streamable HTTP)."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from conftest import APP_DSN, fake_embed
from psycopg_pool import ConnectionPool

from adk_memshield import (
    HmacIdentityVerifier,
    MemShieldConfig,
    MemShieldConfigurationError,
    MemShieldIdentityError,
    MemShieldStore,
    issue_hmac_token,
)

mcp = pytest.importorskip("mcp")

from adk_memshield.adapters.mcp import MemShieldMcpTools, create_mcp_server, main  # noqa: E402

APP = "mcp_app"
KEY = b"m" * 32


def _store(pool: ConnectionPool, *, verified: bool, **kw) -> MemShieldStore:
    cfg = MemShieldConfig(
        dsn=APP_DSN, tenant_id="tenant_a",
        identity_verifier=HmacIdentityVerifier({"k": KEY}) if verified else None, **kw,
    )
    return MemShieldStore(cfg, embed_fn=fake_embed, pool=pool)


def _token(user: str, tenant: str = "tenant_a") -> str:
    return issue_hmac_token(KEY, kid="k", user_id=user, tenant_id=tenant, audience=APP)


def _payload(result) -> object:
    assert not result.is_error, result
    if result.structured_content is not None:
        content = result.structured_content
        return content.get("result", content) if isinstance(content, dict) else content
    return json.loads(result.content[0].text)


async def test_stdio_trusted_mode_roundtrip(make_pool: Callable[..., ConnectionPool]) -> None:
    server = create_mcp_server(_store(make_pool(), verified=False), app_name=APP, user_id="alice")
    names = {t.name for t in await server.list_tools()}
    assert names == {"remember", "recall", "forget"}

    stored = _payload(await server.call_tool("remember", {"text": "alice parks in bay 4"}))
    hits = _payload(await server.call_tool("recall", {"query": "parking"}))
    assert [h["text"] for h in hits] == ["alice parks in bay 4"]
    assert hits[0]["owner"] == "alice" and hits[0]["tenant"] == "tenant_a"
    gone = _payload(await server.call_tool("forget", {"memory_id": stored["id"]}))
    assert gone == {"deleted": 1}


def test_trusted_mode_needs_a_user(make_pool: Callable[..., ConnectionPool]) -> None:
    with pytest.raises(MemShieldConfigurationError, match="user_id"):
        MemShieldMcpTools(_store(make_pool(), verified=False), app_name=APP)


async def test_stdio_verified_mode_reads_token_from_env(make_pool: Callable[..., ConnectionPool]) -> None:
    store = _store(make_pool(), verified=True)
    tools = MemShieldMcpTools(store, app_name=APP, environ={"MEMSHIELD_IDENTITY_TOKEN": _token("bob")})
    await tools.remember("bob note")
    assert [h["owner"] for h in await tools.recall("note")] == ["bob"]
    no_token = MemShieldMcpTools(store, app_name=APP, environ={})
    with pytest.raises(MemShieldIdentityError, match="no identity token"):
        await no_token.recall("note")
    pinned = MemShieldMcpTools(store, app_name=APP, user_id="alice",
                               environ={"MEMSHIELD_IDENTITY_TOKEN": _token("bob")})
    with pytest.raises(MemShieldIdentityError, match="different user"):
        await pinned.recall("note")


async def test_http_headers_without_verifier_are_refused(make_pool: Callable[..., ConnectionPool]) -> None:
    tools = MemShieldMcpTools(_store(make_pool(), verified=False), app_name=APP, user_id="alice")
    with pytest.raises(MemShieldIdentityError, match="identity verifier"):
        await tools.recall("x", headers={"Authorization": f"Bearer {_token('alice')}"})


def test_cli_refuses_http_without_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEMSHIELD_HMAC_KEYS", raising=False)
    with pytest.raises(MemShieldConfigurationError, match="identity verifier"):
        main(["--transport", "http", "--app", APP])


def _rpc(client, method: str, params: dict, headers: dict[str, str], rid: int = 1):
    body = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
    return client.post(
        "/mcp", json=body,
        headers={"Accept": "application/json, text/event-stream", **headers},
    )


def test_streamable_http_end_to_end(make_pool: Callable[..., ConnectionPool]) -> None:
    from starlette.testclient import TestClient

    server = create_mcp_server(_store(make_pool(max_size=2), verified=True), app_name=APP)
    app = server.streamable_http_app(stateless_http=True, json_response=True)
    alice = {"Authorization": f"Bearer {_token('alice')}"}
    bob = {"Authorization": f"Bearer {_token('bob')}"}
    init = {"protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "conformance", "version": "0"}}

    # One client: the session manager's lifespan may run only once per app.
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:

        def call(headers: dict[str, str], name: str, args: dict, rid: int):
            _rpc(client, "initialize", init, headers)
            resp = _rpc(client, "tools/call", {"name": name, "arguments": args}, headers, rid)
            assert resp.status_code == 200, resp.text
            return resp.json()

        stored = call(alice, "remember", {"text": "alice locker 12"}, 2)
        assert not stored["result"].get("isError"), stored
        call(bob, "remember", {"text": "bob locker 44"}, 3)

        found = call(alice, "recall", {"query": "locker"}, 4)["result"]
        texts = json.dumps(found)
        assert "alice locker 12" in texts and "bob locker 44" not in texts

        for headers in ({}, {"Authorization": "Bearer forged.token"}):
            refused = call(headers, "recall", {"query": "locker"}, 5)["result"]
            assert refused.get("isError") is True
            assert "locker 12" not in json.dumps(refused.get("content", []))
