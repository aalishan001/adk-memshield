# Agent Skill Trigger Tests — `memshield-rbac-onboarding` (2026-11-20)

Tested in Antigravity across 5 independent prompts (3 positive should-trigger, 2 negative should-not-trigger) after installing `skills/memshield-rbac-onboarding/` into `.agents/skills/`.

| ID | Prompt | Expected | Observed | Rule Adherence | Verdict |
| :--- | :--- | :--- | :--- | :--- | :---: |
| P1 | "We have an Okta groups JSON export and a Postgres roles table; help us map them to adk-memshield clearances and compartments and generate JWT config." | `memshield-rbac-onboarding` | `memshield-rbac-onboarding` | Read-only inspection; propose for human approval | **PASS** |
| P2 | "Onboard our lending startup's existing RBAC YAML (support_agent, collections, compliance, admin) into MemShield with Casbin rules." | `memshield-rbac-onboarding` | `memshield-rbac-onboarding` | Read-only; real fields only; human approval before cutover | **PASS** |
| P3 | "Map our Entra ID group claims to MemShield identity fields and generate isolation tests for each role pair." | `memshield-rbac-onboarding` | `memshield-rbac-onboarding` | Read-only; flag unmappable rules; human approval | **PASS** |
| N1 | "Center a div vertically using CSS flexbox." | `NONE` | `NONE` | n/a | **PASS** |
| N2 | "Write a Python function to parse ISO 8601 dates and calculate business days." | `NONE` | `NONE` | n/a | **PASS** |

**Result:** **5 of 5 correct** (3/3 positive triggers with rule compliance, 2/2 negative non-triggers). Combined across all three MemShield Agent Skills (`memshield-tenant-isolation`, `leak-arena-audit`, `memshield-rbac-onboarding`): **15 of 15 correct**.

## Deterministic Mapper Fixture Runs (`scripts/map_rbac.py`)
- `references/fixtures/lending_startup_rbac.json` -> `benchmarks/runs/2026-11-20/rbac-lending-startup/`: 5 roles, 4 unmappable items flagged (time restriction, waiver amount condition, per-loan_id ACL, explicit deny rule), 14 pairwise isolation test cases generated.
- `references/fixtures/idp_groups_export.json` -> `benchmarks/runs/2026-11-20/rbac-idp-groups/`: 5 roles, 5 IdP groups mapped to compartments, 1 unmappable item flagged (hardware_key MFA condition), 19 pairwise isolation test cases generated.
