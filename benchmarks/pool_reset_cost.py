"""Per-checkout cost of the pool ``reset`` callback (``RESET ALL`` on return).

memshield's own pools run :func:`adk_memshield.reset_connection` when a connection is
returned, so session-scoped ``app.*`` settings written by custom SQL can never reach the
next borrower. This measures what that costs: N checkouts of ``SELECT 1`` on a one-
connection pool, with and without the callback, interleaved in rounds.

    python benchmarks/pool_reset_cost.py --checkouts 2000
"""

from __future__ import annotations

import argparse
import os
import statistics
import time

from psycopg_pool import ConnectionPool

from adk_memshield import reset_connection


def timed(pool: ConnectionPool, n: int) -> list[float]:
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        with pool.connection() as conn:
            conn.execute("SELECT 1").fetchone()
        out.append((time.perf_counter() - t0) * 1000.0)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkouts", type=int, default=2000)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    dsn = os.environ.get(
        "MEMSHIELD_DB_DSN", "postgresql://memshield_app:memshield_pass@localhost:54329/memshield"
    )
    with_reset = ConnectionPool(dsn, min_size=1, max_size=1, reset=reset_connection, open=True)
    without = ConnectionPool(dsn, min_size=1, max_size=1, open=True)
    try:
        timed(with_reset, 200)
        timed(without, 200)  # warm up
        a: list[float] = []
        b: list[float] = []
        per_round = args.checkouts // args.rounds
        for _ in range(args.rounds):
            a += timed(with_reset, per_round)
            b += timed(without, per_round)
    finally:
        with_reset.close()
        without.close()
    a.sort()
    b.sort()

    def row(name: str, xs: list[float]) -> str:
        return (f"| {name} | {len(xs)} | {statistics.mean(xs):.3f} | {statistics.median(xs):.3f} "
                f"| {xs[int(0.95 * (len(xs) - 1))]:.3f} |")

    print("| Pool | Checkouts | mean ms | p50 ms | p95 ms |")
    print("| :--- | ---: | ---: | ---: | ---: |")
    print(row("reset=reset_connection (RESET ALL; RESET ROLE; DISCARD TEMP)", a))
    print(row("no reset callback", b))
    print()
    print(f"Mean added per checkout: {statistics.mean(a) - statistics.mean(b):.3f} ms "
          "(the reset runs after the connection is returned; this includes the time the next "
          "checkout waits for it on a one-connection pool)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
