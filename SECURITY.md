# Security Policy

## Scope

adk-memshield enforces tenant, user and clearance isolation for Google ADK memory with PostgreSQL Row-Level Security. Security-relevant reports include, for example:

- a way for one identity to read, write, update or delete another identity's rows through `MemShieldMemoryService` or the RLS policies in `sql/01_schema.sql`;
- identity context bleeding across pooled connections;
- SQL injection through any service parameter or configuration value.

Known, documented limits are not vulnerabilities: a compromised process holding the `memshield_app` credentials can call `set_config` itself, and `tenant_shared` content written at or below a writer's clearance is readable by design (see the README's threat model).

`sql/02_benchmark_baseline.sql` creates an intentionally unprotected table for benchmarks. Never apply it in production.

## Supported versions

| Version | Supported |
| :--- | :---: |
| 0.1.x | Yes |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories:

**https://github.com/aalishan001/adk-memshield/security/advisories/new**

Include the affected version, PostgreSQL/pgvector versions, and steps to reproduce. You should receive an acknowledgement within 7 days. Please do not disclose the issue publicly until a fix is released.
