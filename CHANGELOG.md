# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-22

### Added
- `MemShieldMemoryService`, a Google ADK `BaseMemoryService` backed by PostgreSQL `pgvector` with forced Row-Level Security and transaction-local identity (`set_config(..., true)`).
- RLS policies for `SELECT`, `INSERT`, `UPDATE` and `DELETE`, non-empty identity checks, a no-write-up clearance rule, and idempotent session ingestion.
- `rls_transaction()` for running custom SQL under the caller's RLS identity.
- `memshield://` URI registration for the ADK service registry.
- Integration tests, including a real ADK `Runner` with `preload_memory` and `load_memory`.
- MemLeak / AgentLeak-style benchmark with five application-layer failure scenarios and a control row.
