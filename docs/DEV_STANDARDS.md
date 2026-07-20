# DEV_STANDARDS

## Code style & formatting

ShadowSensor uses **Ruff** for both linting and formatting. The active configuration lives in `pyproject.toml`.

- Line length: 100 characters
- Target runtime: Python 3.11
- Formatter: Ruff formatter with double quotes and spaces for indentation
- Linting focus: correctness, import hygiene, basic style, and modern Python upgrades

## Typing convention

Full type hints are required on all public functions and methods across every module.

- Public APIs should include explicit parameter and return annotations.
- Internal helpers should also be typed when practical, but public surface area is mandatory.
- `mypy` is **recommended, not CI-blocking** in this phase; it will be used as a quality gate during later implementation work.

## Docstring convention

Use **Google-style docstrings** consistently.

- One-line summary first
- Blank line before any longer explanation
- Args/Returns/Raises sections when applicable
- Keep placeholder package docstrings short and purpose-driven

## Test convention

Tests use **pytest**.

- Test files live under `tests/unit/`
- Test file names mirror the source area they cover, such as `tests/unit/test_normalizer.py`
- Shared fixtures live under `tests/fixtures/`
- Sysmon samples, when present, belong under `tests/fixtures/sysmon_samples/`
- Test function names should describe observable behavior, not implementation detail

## Logging convention

Use the standard library `logging` module everywhere.

- One logger per module via `logging.getLogger(__name__)`
- Consistent format: timestamp, level, module, message
- Background components such as the collector, dashboard, and service should log clearly enough for unattended operation and post-run diagnosis

## Forward-looking reproducibility

For ML phases 5–7, any randomness must use fixed, documented seeds.

- Set and record seeds for train/test splits
- Set and record seeds for Isolation Forest and Random Forest training
- Keep reproducibility decisions visible in code and supporting docs when those phases arrive
