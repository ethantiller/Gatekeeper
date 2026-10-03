# Project Agent Instructions

- Run Python scripts and tests through `uv run` so the interpreter in `.python-version` is used.
- For the standard-library-only fixture server, use `uv run --no-sync python fixtures/fixture_server.py` to avoid syncing the full project dependency set.
- Run tests with `uv run --group dev python -m pytest` so workspace imports resolve consistently.