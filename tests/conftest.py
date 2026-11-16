"""Shared fixtures. Tests need the project's Postgres (see README, "Reproducing tests")."""

from __future__ import annotations

import hashlib
import math
import os
import uuid
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from psycopg_pool import ConnectionPool

from adk_memshield import reset_connection

APP_DSN = os.environ.get(
    "MEMSHIELD_DB_DSN",
    "postgresql://memshield_app:memshield_pass@localhost:54329/memshield",
)
ADMIN_DSN = os.environ.get(
    "MEMSHIELD_ADMIN_DSN",
    "postgresql://postgres:postgres_admin_pass@localhost:54329/memshield",
)
ROOT = Path(__file__).resolve().parents[1]
DIM = 384


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: needs a large data set (run with -m slow)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("-m") and "slow" in config.getoption("-m"):
        return
    if os.environ.get("MEMSHIELD_RUN_SLOW") == "1":
        return
    skip = pytest.mark.skip(reason="slow test: run with -m slow or MEMSHIELD_RUN_SLOW=1")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


def with_db(dsn: str, db: str) -> str:
    return urlunparse(urlparse(dsn)._replace(path="/" + db))


def fake_vector(text: str) -> list[float]:
    """Deterministic unit vector for ``text`` (no model download, no semantics)."""
    out: list[float] = []
    counter = 0
    while len(out) < DIM:
        digest = hashlib.sha256(f"{text}|{counter}".encode()).digest()
        out.extend((b - 127.5) / 127.5 for b in digest)
        counter += 1
    vec = out[:DIM]
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def fake_embed(texts: Sequence[str]) -> list[list[float]]:
    return [fake_vector(t) for t in texts]


@pytest.fixture(autouse=True)
def clean_tables() -> None:
    """Truncate the shared test tables before each test."""
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        conn.execute("TRUNCATE TABLE memories, memories_unprotected")


@pytest.fixture
def make_pool() -> Iterator[Callable[..., ConnectionPool]]:
    """Factory for pools closed at teardown. Default: one connection, memshield's reset."""
    pools: list[ConnectionPool] = []

    def factory(dsn: str = APP_DSN, *, max_size: int = 1, reset: bool = True) -> ConnectionPool:
        pool = ConnectionPool(
            dsn,
            min_size=1,
            max_size=max_size,
            open=True,
            reset=reset_connection if reset else None,
        )
        pool.wait()
        pools.append(pool)
        return pool

    yield factory
    for pool in pools:
        pool.close()


@pytest.fixture
def temp_database() -> Iterator[Callable[[], str]]:
    """Factory for throwaway databases on the test server, dropped at teardown.

    Returns the database name; build DSNs with :func:`with_db`.
    """
    created: list[str] = []

    def factory() -> str:
        name = f"memshield_test_{uuid.uuid4().hex[:10]}"
        with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
            conn.execute(f'CREATE DATABASE "{name}"')
        created.append(name)
        return name

    yield factory
    with psycopg.connect(ADMIN_DSN, autocommit=True) as conn:
        for name in created:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def apply_sql(dsn: str, path: Path) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(path.read_text(encoding="utf-8"))


def backend_pid(pool: ConnectionPool) -> int:
    with pool.connection() as conn:
        return conn.execute("SELECT pg_backend_pid()").fetchone()[0]
