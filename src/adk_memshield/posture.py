"""Refuse to run on a connection that cannot enforce Row-Level Security."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import psycopg

from .errors import MemShieldConfigurationError

logger = logging.getLogger("adk_memshield")

_REQUIRED_COMMANDS = ("SELECT", "INSERT", "UPDATE", "DELETE")
_TENANT_SETTING = "app.current_tenant_id"


@dataclass(frozen=True)
class PostureReport:
    """What the posture check found for one role and table."""

    role: str
    table: str
    rolsuper: bool
    rolbypassrls: bool
    row_security: bool
    force_row_security: bool
    policies: dict[str, list[str]] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def inspect_rls_posture(cur: psycopg.Cursor[Any], table: str) -> PostureReport:
    """Read the posture of ``current_user`` and ``table`` from the catalogs.

    ``table`` must already be a validated identifier; it is passed as a bound parameter to
    ``to_regclass`` and never interpolated.
    """
    cur.execute(
        "SELECT current_user, r.rolsuper, r.rolbypassrls"
        " FROM pg_roles r WHERE r.rolname = current_user"
    )
    role_row = cur.fetchone()
    if role_row is None:  # pragma: no cover - current_user always has a pg_roles row
        raise MemShieldConfigurationError("could not read the current role from pg_roles")
    role, rolsuper, rolbypassrls = role_row

    cur.execute(
        "SELECT c.relrowsecurity, c.relforcerowsecurity,"
        " pg_has_role(current_user, c.relowner, 'MEMBER')"
        " FROM pg_class c WHERE c.oid = to_regclass(%s)",
        (table,),
    )
    rel_row = cur.fetchone()

    policies: dict[str, list[str]] = {}
    problems: list[str] = []
    if rolsuper:
        problems.append(f"role {role!r} is a superuser, which bypasses row-level security")
    if rolbypassrls:
        problems.append(f"role {role!r} has BYPASSRLS, which bypasses row-level security")

    if rel_row is None:
        problems.append(f"table {table!r} does not exist or is not visible on the search_path")
        row_security = force_row_security = False
    else:
        row_security, force_row_security = bool(rel_row[0]), bool(rel_row[1])
        if not row_security:
            problems.append(f"table {table!r} does not have row-level security enabled")
        if not force_row_security:
            problems.append(
                f"table {table!r} does not FORCE row-level security (the table owner would bypass it)"
            )
        if rel_row[2]:
            problems.append(
                f"role {role!r} owns table {table!r} (or is a member of its owner role) and could "
                "disable row-level security or drop its policies at runtime"
            )
        # A policy applies to the role if it is granted to PUBLIC or to any role the
        # connecting role is a member of (directly or through inheritance).
        cur.execute(
            "SELECT p.polname,"
            " CASE p.polcmd WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE'"
            "   WHEN 'd' THEN 'DELETE' ELSE 'ALL' END,"
            " p.polpermissive,"
            " EXISTS (SELECT 1 FROM unnest(p.polroles) AS r"
            "         WHERE r = 0 OR pg_has_role(current_user, r, 'MEMBER')),"
            " coalesce(pg_get_expr(p.polqual, p.polrelid), ''),"
            " coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')"
            " FROM pg_policy p WHERE p.polrelid = to_regclass(%s)",
            (table,),
        )
        covered: set[str] = set()
        for name, cmd, permissive, applies, qual, check in cur.fetchall():
            if not applies:
                continue
            policies.setdefault(cmd, []).append(name)
            if permissive:
                # Each expression that decides visibility or writes must check the tenant.
                needed = {
                    "SELECT": [qual],
                    "DELETE": [qual],
                    "INSERT": [check],
                    "UPDATE": [qual, check or qual],
                    "ALL": [qual, check or qual],
                }[cmd]
                if any(_TENANT_SETTING not in expr for expr in needed):
                    problems.append(
                        f"policy {name!r} on {table!r} is permissive and an expression for "
                        f"{cmd} does not reference {_TENANT_SETTING}, so it can widen access"
                    )
            if cmd == "ALL":
                covered.update(_REQUIRED_COMMANDS)
            else:
                covered.add(cmd)
        missing = [c for c in _REQUIRED_COMMANDS if c not in covered]
        if missing:
            problems.append(
                f"table {table!r} has no row-level security policy for {', '.join(missing)}"
                f" that applies to role {role!r}"
            )

    return PostureReport(
        role=role,
        table=table,
        rolsuper=bool(rolsuper),
        rolbypassrls=bool(rolbypassrls),
        row_security=row_security,
        force_row_security=force_row_security,
        policies=policies,
        problems=problems,
    )


def enforce_rls_posture(
    cur: psycopg.Cursor[Any], table: str, *, allow_insecure_role: bool = False
) -> PostureReport:
    """Inspect posture and raise :class:`MemShieldConfigurationError` on any problem.

    With ``allow_insecure_role=True`` (benchmarks and tests against an intentionally
    unprotected table only) problems are logged as a warning instead of raising.
    """
    report = inspect_rls_posture(cur, table)
    if report.ok:
        return report
    summary = "; ".join(report.problems)
    if allow_insecure_role:
        logger.warning("adk-memshield running WITHOUT row-level security protection: %s", summary)
        return report
    raise MemShieldConfigurationError(
        f"refusing to run: {summary}. Connect as a NOSUPERUSER NOBYPASSRLS role "
        "(see sql/01_schema.sql) on a table with FORCE ROW LEVEL SECURITY."
    )
