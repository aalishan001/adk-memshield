# Contributing to adk-memshield

Thanks for helping improve adk-memshield. Bug reports, policy hardening and new tests are all welcome.

## Development setup

You need Python 3.10+ and PostgreSQL 16 with `pgvector`. The tests and benchmark expect the database on `localhost:54329`.

```bash
git clone https://github.com/aalishan001/adk-memshield.git
cd adk-memshield
docker compose -p adk-memshield up -d db
pip install -e ".[dev]"
pytest -v
python benchmarks/run_memleak_eval.py
```

Or run inside the Compose runner image:

```bash
docker compose -p adk-memshield run --rm test pytest -v
```

`docker compose` applies `sql/01_schema.sql` (production) and `sql/02_benchmark_baseline.sql` (benchmark-only, no RLS) on first start. Schema changes require recreating this project's volume: `docker compose -p adk-memshield down -v`.

## Guidelines

- **RLS policy changes** in `sql/01_schema.sql` need a test in `tests/test_rls_isolation.py` that fails without the change. Cover `SELECT`, `INSERT`, `UPDATE` and `DELETE` where relevant.
- **Defense in depth:** keep the application-layer filter in `MemShieldMemoryService.search_memory` aligned with the RLS `SELECT` policy.
- **Identity** must only come from call arguments and `MemShieldConfig`, never from caller-supplied metadata.
- **Benchmark claims** in the README must come from `benchmarks/run_memleak_eval.py` output you can reproduce. Do not tune queries or lures to reach a target number.
- Keep the public API compatible with `google.adk.memory.base_memory_service.BaseMemoryService`.

## Pull requests

Run `pytest -v` and the benchmark before opening a PR, and describe the threat or behaviour the change addresses.

## Reporting security issues

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
