# DEPENDENCIES

Pinned in `requirements.txt` for Python 3.11 on Windows.

- `pywin32==312` — Windows API and Event Log access for the collector in Phase 1; also used again for the Windows service wrapper in Phase 9.
- `lxml==6.1.1` — XML parsing for Sysmon normalization in Phase 1.
- `PyYAML==6.0.3` — YAML rule loading for the rules engine in Phase 2.
- `SQLAlchemy==2.0.51` — ORM and schema layer over SQLite in Phase 3.
- `fastapi==0.138.0` — dashboard API backend in Phase 3.
- `uvicorn==0.49.0` — ASGI server for the dashboard in Phase 3 and later packaging/runtime work in Phase 9.
- `Jinja2==3.1.6` — server-rendered dashboard templates in Phase 3.
- `lark==1.3.1` — KQL-style query grammar/parser for the search console in Phase 3; chosen over `pyparsing` because the grammar reads more cleanly and will be easier to extend.
- `scikit-learn==1.9.0` — Isolation Forest and Random Forest modeling in Phases 6 and 7.
- `joblib==1.5.3` — trained model persistence in Phase 6.
- `numpy==2.5.0` — feature engineering and numeric array handling in Phase 5.
- `pandas==3.0.3` — tabular feature engineering and dataset wrangling in Phase 5.
- `pyinstaller==6.21.0` — single-executable packaging in Phase 9.
- `pytest==9.1.1` — test framework baseline for the project, used from Phase 0B onward.

Tray-icon support is intentionally deferred to Phase 9, so no tray-specific library is pinned yet.
