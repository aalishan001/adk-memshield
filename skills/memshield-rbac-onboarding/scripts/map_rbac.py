#!/usr/bin/env python3
"""Deterministic RBAC / IdP-group / Casbin mapper for adk-memshield (no LLM calls).

Reads roles YAML/JSON, IdP group claims JSON, roles CSV, or Casbin policy CSV and emits:
  1. memshield-mapping.yaml          (role -> clearance 1..5, group -> compartment, unmappable rules)
  2. jwt_verifier_snippet.py         (matching real adk_memshield.JwtIdentityVerifier API)
  3. generated_leak_arena_cases.json (pairwise isolation test cases)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

COMPARTMENT_RE = re.compile(r"^[a-z0-9_-]{1,64}$")

_CLEARANCE_HINTS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("superadmin", "root", "ciso", "board", "owner"), 5),
    (("admin", "cfo", "exec", "executive", "director", "vp"), 4),
    (("compliance", "audit", "legal", "security", "dpo", "manager", "lead"), 3),
    (("collections", "analyst", "senior", "ops", "finance", "hr", "underwriter"), 2),
    (("support", "agent", "tier1", "readonly", "viewer", "intern", "contractor", "user"), 1),
)

_UNMAPPABLE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("deny", "explicit_deny_rule"),
    ("between", "time_based_rule"),
    ("hours", "time_based_rule"),
    ("schedule", "time_based_rule"),
    ("if ", "attribute_condition_rule"),
    ("when ", "attribute_condition_rule"),
    ("amount", "attribute_condition_rule"),
    ("record_id", "per_record_acl"),
    ("loan_id", "per_record_acl"),
    ("owner_only_exception", "per_record_acl"),
)


def normalize_compartment(raw: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_-]+", "_", raw.strip().lower()).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned)[:64]
    if not cleaned or not COMPARTMENT_RE.fullmatch(cleaned):
        return ""
    return cleaned


def infer_clearance(role_name: str, explicit_level: Any = None) -> int:
    if isinstance(explicit_level, int) and not isinstance(explicit_level, bool) and 1 <= explicit_level <= 5:
        return explicit_level
    low = role_name.strip().lower()
    for tokens, level in _CLEARANCE_HINTS:
        if any(tok in low for tok in tokens):
            return level
    return 1


def _detect_unmappable(text: str, source_ref: str) -> list[dict[str, str]]:
    low = text.lower()
    hits: list[dict[str, str]] = []
    seen_kinds: set[str] = set()
    for pat, kind in _UNMAPPABLE_PATTERNS:
        if pat in low and kind not in seen_kinds:
            seen_kinds.add(kind)
            hits.append(
                {
                    "source": source_ref,
                    "kind": kind,
                    "detail": text.strip(),
                    "action_required": "Human decision: enforce in app policy, pre_write hook, or custom RLS predicate.",
                }
            )
    return hits


def _load_structured(path: Path) -> Any:
    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(raw)
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]

            return yaml.safe_load(raw)
        except ImportError:
            return json.loads(raw)
    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as fh:
            rows = list(csv.reader(fh))
        return {"_csv_rows": rows}
    raise ValueError(f"Unsupported input format: {path.suffix}")


def map_input(data: Any, *, source_name: str) -> dict[str, Any]:
    roles: dict[str, dict[str, Any]] = {}
    group_to_compartment: dict[str, str] = {}
    unmappable: list[dict[str, str]] = []
    claim_mapping = {
        "user_id": "sub",
        "tenant_id": "tenant",
        "clearance": "clearance",
        "compartments": "compartments",
    }

    if isinstance(data, dict) and "_csv_rows" in data:
        rows = [r for r in data["_csv_rows"] if r and any(c.strip() for c in r)]
        if rows and rows[0][0].strip() in ("p", "g"):
            # Casbin policy CSV
            for idx, r in enumerate(rows, start=1):
                rtype = r[0].strip()
                if rtype == "p" and len(r) >= 4:
                    subj, obj, act = r[1].strip(), r[2].strip(), r[3].strip()
                    eff = r[4].strip().lower() if len(r) >= 5 else "allow"
                    if eff == "deny":
                        unmappable.append(
                            {
                                "source": f"{source_name}:line_{idx}",
                                "kind": "explicit_deny_rule",
                                "detail": ", ".join(r),
                                "action_required": "Human decision: adk-memshield policies are allow-list RLS; handle deny rules in app/hook.",
                            }
                        )
                        continue
                    comp = normalize_compartment(obj)
                    entry = roles.setdefault(
                        subj, {"clearance": infer_clearance(subj), "compartments": []}
                    )
                    if comp and comp not in entry["compartments"]:
                        entry["compartments"].append(comp)
                    unmappable.extend(_detect_unmappable(f"{obj} {act}", f"{source_name}:line_{idx}"))
        elif rows:
            headers = [h.strip().lower() for h in rows[0]]
            for idx, r in enumerate(rows[1:], start=2):
                rec = dict(zip(headers, r))
                rname = (rec.get("role") or rec.get("name") or f"role_{idx}").strip()
                dept = (rec.get("department") or rec.get("compartment") or "").strip()
                lvl = int(rec["clearance"]) if str(rec.get("clearance", "")).isdigit() else None
                comp = normalize_compartment(dept) if dept else ""
                roles[rname] = {
                    "clearance": infer_clearance(rname, lvl),
                    "compartments": [comp] if comp else [],
                }
                for col in ("conditions", "rules", "permissions", "notes"):
                    if rec.get(col):
                        unmappable.extend(_detect_unmappable(rec[col], f"{source_name}:row_{idx}:{col}"))
    elif isinstance(data, dict):
        if isinstance(data.get("claim_names"), dict):
            for k in ("tenant_id", "clearance", "compartments"):
                if data["claim_names"].get(k):
                    claim_mapping[k] = str(data["claim_names"][k])

        # Structured roles list
        for item in data.get("roles") or []:
            if not isinstance(item, dict):
                continue
            rname = str(item.get("name") or item.get("role") or "").strip()
            if not rname:
                continue
            comps: list[str] = []
            for raw_c in item.get("compartments") or item.get("departments") or ([item["department"]] if item.get("department") else []):
                nc = normalize_compartment(str(raw_c))
                if nc and nc not in comps:
                    comps.append(nc)
            roles[rname] = {
                "clearance": infer_clearance(rname, item.get("clearance")),
                "compartments": sorted(comps),
            }
            for rule_field in ("conditions", "deny_rules", "time_restrictions", "record_acls"):
                vals = item.get(rule_field)
                if isinstance(vals, list):
                    for v in vals:
                        unmappable.append(
                            {
                                "source": f"{source_name}:{rname}.{rule_field}",
                                "kind": rule_field,
                                "detail": str(v),
                                "action_required": "Human decision required; cannot be represented directly in tenant/clearance/compartment RLS.",
                            }
                        )
                elif isinstance(vals, str) and vals.strip():
                    unmappable.extend(_detect_unmappable(vals, f"{source_name}:{rname}.{rule_field}"))

        # IdP groups export (Okta / Entra / Google Groups)
        for grp in data.get("groups") or []:
            gname = grp.get("name") if isinstance(grp, dict) else str(grp)
            gname = str(gname or "").strip()
            if not gname:
                continue
            # Strip common IdP prefixes like "okta-", "dept:", "grp_", "ad-"
            core = re.sub(r"^(?:okta|entra|aad|google|grp|dept|role)[-_:/]+", "", gname.lower())
            comp = normalize_compartment(core)
            if comp:
                group_to_compartment[gname] = comp
            if isinstance(grp, dict) and grp.get("role"):
                rname = str(grp["role"]).strip()
                entry = roles.setdefault(rname, {"clearance": infer_clearance(rname, grp.get("clearance")), "compartments": []})
                if comp and comp not in entry["compartments"]:
                    entry["compartments"].append(comp)
                    entry["compartments"].sort()
            elif gname.lower().startswith(("role-", "role_", "role:")):
                rname = normalize_compartment(core)
                if rname:
                    roles.setdefault(rname, {"clearance": infer_clearance(rname), "compartments": []})
            if isinstance(grp, dict) and grp.get("condition"):
                unmappable.append(
                    {
                        "source": f"{source_name}:group:{gname}",
                        "kind": "attribute_condition_rule",
                        "detail": str(grp["condition"]),
                        "action_required": "Human decision required.",
                    }
                )

    # Generate pairwise leak-arena isolation test cases
    role_names = sorted(roles.keys())
    pair_cases: list[dict[str, Any]] = []
    for i, a in enumerate(role_names):
        for b in role_names[i + 1 :]:
            ra, rb = roles[a], roles[b]
            if ra["clearance"] != rb["clearance"]:
                low, high = (a, b) if ra["clearance"] < rb["clearance"] else (b, a)
                rlow, rhigh = roles[low], roles[high]
                pair_cases.append(
                    {
                        "case_id": f"RBAC_CLR_{low}_cannot_read_{high}",
                        "type": "clearance_isolation",
                        "caller_role": low,
                        "caller_clearance": rlow["clearance"],
                        "caller_compartments": rlow["compartments"],
                        "target_memory_min_clearance": rhigh["clearance"],
                        "target_memory_scope": "tenant_shared",
                        "expected_leaked_rows": 0,
                        "assertion": f"{low} (clearance {rlow['clearance']}) must read 0 tenant_shared rows labelled clearance {rhigh['clearance']} ({high}).",
                    }
                )
            ca, cb = set(ra["compartments"]), set(rb["compartments"])
            if ca and cb and ca.isdisjoint(cb):
                pair_cases.append(
                    {
                        "case_id": f"RBAC_COMP_{a}_cannot_read_{b}",
                        "type": "compartment_isolation",
                        "caller_role": a,
                        "caller_clearance": ra["clearance"],
                        "caller_compartments": sorted(ca),
                        "target_memory_compartments": sorted(cb),
                        "target_memory_scope": "tenant_shared",
                        "expected_leaked_rows": 0,
                        "assertion": f"{a} ({sorted(ca)}) must read 0 tenant_shared rows tagged {sorted(cb)} ({b}).",
                    }
                )

    return {
        "schema_version": "adk-memshield-rbac-mapping/v1",
        "source": source_name,
        "requires_human_approval": True,
        "identity_fields": claim_mapping,
        "roles": roles,
        "group_to_compartment": group_to_compartment,
        "unmappable_items": unmappable,
        "generated_test_cases": pair_cases,
    }


def _to_yaml(mapping: dict[str, Any]) -> str:
    """Render mapping as clean human-readable YAML without requiring PyYAML."""
    lines = [
        f"schema_version: {mapping['schema_version']}",
        f"source: {mapping['source']}",
        f"requires_human_approval: {str(mapping['requires_human_approval']).lower()}",
        "identity_fields:",
    ]
    for k, v in mapping["identity_fields"].items():
        lines.append(f"  {k}: {v}")
    lines.append("roles:")
    for rname, rdata in sorted(mapping["roles"].items()):
        comps = ", ".join(rdata["compartments"])
        lines.append(f"  {rname}:")
        lines.append(f"    clearance: {rdata['clearance']}")
        lines.append(f"    compartments: [{comps}]")
    lines.append("group_to_compartment:")
    if mapping["group_to_compartment"]:
        for g, c in sorted(mapping["group_to_compartment"].items()):
            lines.append(f'  "{g}": {c}')
    else:
        lines.append("  {}")
    lines.append("unmappable_items:")
    if mapping["unmappable_items"]:
        for item in mapping["unmappable_items"]:
            lines.append(f"  - source: {json.dumps(item['source'])}")
            lines.append(f"    kind: {item['kind']}")
            lines.append(f"    detail: {json.dumps(item['detail'])}")
            lines.append(f"    action_required: {json.dumps(item['action_required'])}")
    else:
        lines.append("  []")
    lines.append("")
    return "\n".join(lines)


def _render_jwt_snippet(mapping: dict[str, Any], *, issuer: str, jwks_url: str, audience: str) -> str:
    f = mapping["identity_fields"]
    return f'''"""Generated adk-memshield JwtIdentityVerifier configuration (review before applying)."""

from adk_memshield import JwtIdentityVerifier, MemShieldConfig, MemShieldMemoryService

verifier = JwtIdentityVerifier(
    jwks_url={jwks_url!r},
    issuer={issuer!r},  # required: prevents cross-issuer token confusion on shared JWKS
    audience={audience!r},
    algorithms=("RS256",),
    tenant_claim={f["tenant_id"]!r},
    clearance_claim={f["clearance"]!r},
    compartments_claim={f["compartments"]!r},
)

memory_service = MemShieldMemoryService(
    MemShieldConfig(
        dsn="postgresql://memshield_app:<from-secret-manager>@<host>:5432/memshield",
        identity_verifier=verifier,
    )
)
memory_service.verify_rls_posture()
'''


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic RBAC/IdP mapper for adk-memshield")
    parser.add_argument("--input", required=True, help="Path to roles JSON/YAML, IdP groups JSON, or CSV")
    parser.add_argument("--out-dir", required=True, help="Directory for generated mapping artifacts")
    parser.add_argument("--issuer", default="https://idp.example.com/", help="OIDC issuer URL")
    parser.add_argument("--jwks-url", default="https://idp.example.com/.well-known/jwks.json", help="OIDC JWKS URL")
    parser.add_argument("--audience", default="memshield-agent-app", help="Expected JWT aud claim")
    args = parser.parse_args(argv)

    in_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = _load_structured(in_path)
    mapping = map_input(data, source_name=in_path.name)

    (out_dir / "memshield-mapping.yaml").write_text(_to_yaml(mapping), encoding="utf-8")
    (out_dir / "jwt_verifier_snippet.py").write_text(
        _render_jwt_snippet(mapping, issuer=args.issuer, jwks_url=args.jwks_url, audience=args.audience),
        encoding="utf-8",
    )
    (out_dir / "generated_leak_arena_cases.json").write_text(
        json.dumps(mapping["generated_test_cases"], indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"Mapped {len(mapping['roles'])} roles, {len(mapping['group_to_compartment'])} groups, "
        f"{len(mapping['unmappable_items'])} unmappable items, "
        f"{len(mapping['generated_test_cases'])} generated test cases -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
