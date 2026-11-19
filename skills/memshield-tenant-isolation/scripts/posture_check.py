#!/usr/bin/env python3
"""Verify PostgreSQL Row-Level Security posture for adk-memshield without printing the DSN.

Usage:
    MEMSHIELD_DB_DSN="postgresql://..." python scripts/posture_check.py [--table memories]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import psycopg
from adk_memshield.posture import inspect_rls_posture


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect adk-memshield PostgreSQL RLS posture.")
    parser.add_argument(
        "--env",
        default="MEMSHIELD_DB_DSN",
        help="Environment variable holding the application DSN (default: MEMSHIELD_DB_DSN).",
    )
    parser.add_argument(
        "--table",
        default="memories",
        help="Target memory table name (default: memories).",
    )
    args = parser.parse_args(argv)

    dsn = os.environ.get(args.env, "").strip()
    if not dsn:
        print(f"ERROR: environment variable {args.env} is not set.", file=sys.stderr)
        return 2

    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                report = inspect_rls_posture(cur, args.table)
    except Exception as exc:
        # Report only exception type; never risk printing a DSN or password.
        print(f"ERROR: posture check failed ({type(exc).__name__})", file=sys.stderr)
        return 2

    payload = {
        "ok": report.ok,
        "role": report.role,
        "table": report.table,
        "rolsuper": report.rolsuper,
        "rolbypassrls": report.rolbypassrls,
        "row_security": report.row_security,
        "force_row_security": report.force_row_security,
        "policies": report.policies,
        "problems": report.problems,
    }
    print(json.dumps(payload, indent=2))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
