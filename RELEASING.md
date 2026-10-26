# Releasing

Releases are published by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a `vX.Y.Z` tag is pushed. It builds the sdist and wheel, publishes them to PyPI with trusted publishing (no API tokens), and creates the GitHub Release with that version's CHANGELOG section as the notes.

## Cutting a release

1. Bump `version` in `pyproject.toml` and `__version__` in `src/adk_memshield/__init__.py`.
2. Add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`. The heading must match the version exactly; the workflow fails without it.
3. Commit: `git commit -am "release: adk-memshield X.Y.Z"`
4. Tag the release commit: `git tag -a vX.Y.Z -m "adk-memshield X.Y.Z"`
5. Push the commit, then the tag: `git push origin main` and `git push origin vX.Y.Z`

The workflow refuses a tag that does not match the `pyproject.toml` version. If that version is already on PyPI, it skips publishing and only creates or updates the GitHub Release, attaching the files PyPI already serves (checked against PyPI's SHA-256). You can therefore rerun it safely from **Actions → Release → Run workflow** with the tag as input.

## One-time setup

1. **PyPI trusted publisher.** On pypi.org, open the project's **Manage → Publishing** page and add a GitHub publisher with owner `aalishan001`, repository `adk-memshield`, workflow `release.yml` and environment `pypi`.
2. **GitHub environment.** In the repository's **Settings → Environments**, create `pypi`. Optionally add yourself as a required reviewer so every upload needs approval.
