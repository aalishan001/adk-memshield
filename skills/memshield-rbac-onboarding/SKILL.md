---
name: memshield-rbac-onboarding
description: Use when onboarding an existing multi-tenant application's RBAC, roles table, Identity Provider groups (Okta, Entra ID, Google Groups), or Casbin/OPA policies onto adk-memshield's identity model (tenant_id, user_id, clearance 1-5, compartments) and JwtIdentityVerifier.
---

# Onboarding Existing RBAC to `adk-memshield`

Use this skill when a team already has application roles, a roles CSV/table, IdP group claims, or Casbin/OPA policy files and wants to map them safely onto `adk-memshield`'s PostgreSQL Row-Level Security identity model.

## Ground Rules

1. **Read-only inspection first.** Never modify the customer's existing IAM, IdP, or database roles. Only read exported role/group files.
2. **Map onto real `adk-memshield` fields only:**
   - `tenant_id` (non-empty string, JWT `tenant_claim`)
   - `user_id` (non-empty string, JWT `sub` claim)
   - `clearance` (integer `1` through `5`, JWT `clearance_claim`)
   - `compartments` (list of lowercase tokens matching `^[a-z0-9_-]{1,64}$`, JWT `compartments_claim`)
3. **Propose, never apply silently.** Present the generated `memshield-mapping.yaml`, the `JwtIdentityVerifier` snippet, and every flagged unmappable rule to a human engineer/security owner for explicit approval before wiring it into production.
4. **Be honest about unmappable rules.** `adk-memshield` enforces tenant, owner, vertical clearance (`1..5`), and horizontal compartments. Explicitly flag attribute/condition rules (e.g., `amount < 50000`), explicit `deny` rules, time-based rules (e.g., business hours), and per-record ACLs for application-layer or custom-policy review.
5. **Verify before cutover.** Run the generated pair tests (every lower clearance or non-matching compartment must see 0 restricted rows) and run `adk_memshield.verify_rls_posture()` / `leak-arena eval`.

## Procedure

1. Export the team's roles or IdP groups to JSON, YAML, or CSV (roles table or Casbin policy CSV).
2. Run the deterministic mapper (no LLM calls):
   ```bash
   python skills/memshield-rbac-onboarding/scripts/map_rbac.py \
     --input path/to/roles.json \
     --out-dir path/to/out \
     --issuer https://idp.example.com/ \
     --jwks-url https://idp.example.com/.well-known/jwks.json
   ```
3. Review the three generated artifacts with the human owner:
   - `memshield-mapping.yaml` (role -> clearance, group -> compartment, claim names, and `unmappable_items`)
   - `jwt_verifier_snippet.py` (`JwtIdentityVerifier` with mandatory `issuer=`)
   - `generated_leak_arena_cases.json` (pairwise lower-vs-higher clearance and cross-compartment isolation checks)
4. Resolve every entry in `unmappable_items` explicitly with the security owner.
5. After human approval, wire `JwtIdentityVerifier` + `bind_identity(token)` into the app, run `verify_rls_posture()`, and run `leak-arena eval --scenarios all --min-recall 1.0`.

## Reference Fixtures

- `references/fixtures/lending_startup_rbac.json`: fictional lending-startup RBAC (`support_agent`, `support_lead`, `collections`, `compliance`, `admin`, departments as compartments, plus unmappable condition/deny/time/per-record rules).
- `references/fixtures/idp_groups_export.json`: fictional Okta / Google / Entra IdP group claims export.
