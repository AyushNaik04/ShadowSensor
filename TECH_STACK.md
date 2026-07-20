# ShadowSensor — Complete Tech Stack Reference

*Read this file before executing any phase task. It is the canonical reference for all technology choices, versions, architecture decisions, and constraints. Never contradict what is written here without an explicit instruction from the project owner.*

---

## Project Identity

**Tool name:** ShadowSensor
**What it is:** A standalone, consent-based Windows endpoint detection research tool that identifies fileless threats using behavioral telemetry — process lineage, command-line patterns, parent-child chains, and in-memory activity signals. Not file-hash matching.
**Two deliverables:** (1) A working detection tool users install themselves, consensually, on their own machine. (2) An academic research paper.
**Framing (non-negotiable):** Defensive security tooling, end to end. Never covert. Never centrally deployed. The end user runs the installer on their own machine and is fully aware of what it does.

---

## Runtime Environment

| Item | Value |
|---|---|
| Language | Python 3.13 (sandbox runtime: `python_runtime\python.exe`, currently 3.13.5) |
| Target OS | Windows 10 and Windows 11 (x64) |
| Repo root | `filelessmalware/` |
| Absolute paths | **Never.** No `C:\...` or drive letters anywhere in code or config. Use `pathlib.Path` and relative paths throughout. |

Note: `pyproject.toml`'s `target-version = "py311"` is a Ruff lint/format minimum-compatibility floor, not the execution runtime.

---

## Repository Structure

```
filelessmalware/
├── collector/          Phase 1  — polls Sysmon event log via win32evtlog
├── normalizer/         Phase 1  — typed dataclasses + XML→object parsing
├── rules/              Phase 2/4 — YAML rule definitions + rule engine
├── storage/            Phase 3  — SQLite schema + SQLAlchemy models
├── dashboard/          Phase 3  — FastAPI app, Jinja2 templates, HTMX frontend
├── alerting/           Phase 8  — alert correlation + severity engine
├── ml/                 Phase 5–7 — feature engineering, Isolation Forest, Random Forest
├── service/            Phase 9  — Windows Service wrapper
├── tray/               Phase 9  — tray companion app (created IN Phase 9, not before)
├── evaluation/         Phase 10 — evaluation scripts, metrics, figures
├── docs/
│   ├── DEV_STANDARDS.md
│   └── DEPENDENCIES.md
├── tests/
│   ├── unit/           mirrors source module structure
│   └── fixtures/
│       └── sysmon_samples/   5 Sysmon XML samples from Phase 0A
├── requirements.txt
├── .gitignore
├── README.md
├── TECH_STACK.md       ← this file
├── CURSOR_INSTRUCTIONS.md
└── TASK_PHASE_X.md     ← current active phase task file (only one active at a time)
```

Each Python package folder has an `__init__.py` with a one-line module docstring. The `tray/` folder does not exist until Phase 9A creates it.

---

## Dependency Manifest

*Actual pinned versions are in `requirements.txt` — that file is the source of truth for versions. This table documents purpose and introduction phase.*

| Package | Purpose | Introduced |
|---|---|---|
| pywin32 | Windows API: event log reads (Phase 1), Windows Service + tray app (Phase 9) | Phase 1 |
| lxml | XML parsing for Sysmon event normalization | Phase 1 |
| PyYAML | Rule definition loading from YAML files | Phase 2A |
| SQLAlchemy | ORM layer over SQLite | Phase 3 |
| FastAPI | Dashboard HTTP backend | Phase 3 |
| uvicorn | ASGI server to run FastAPI | Phase 3 |
| Jinja2 | Server-rendered HTML templates for dashboard | Phase 3 |
| lark | Grammar-based KQL-style query parser (chosen over pyparsing for cleaner grammar DSL) | Phase 3 |
| scikit-learn | Isolation Forest (unsupervised) + Random Forest (supervised) models | Phase 6/7 |
| joblib | Trained model persistence (.joblib files) | Phase 6B |
| numpy | Numerical operations for feature engineering | Phase 5 |
| pandas | Tabular data handling for feature extraction and dataset management | Phase 5 |
| pyinstaller | Single-executable packaging for distribution | Phase 9A |
| pytest | Test framework, all phases | Phase 0B |

**Tray icon library:** Decision deferred to Phase 9A. Options are pywin32 (already a dependency) or pystray. The Phase 9A builder makes the call and documents it in DEPENDENCIES.md at that time.

**Do not add any package not listed above without flagging it explicitly in your completion report.**

---

## Architecture — Five Core Components

```
[Sysmon Event Log: Microsoft-Windows-Sysmon/Operational]
        │
        ▼
┌─────────────────────┐
│  1. Event Collector │  win32evtlog EVT API, polling every 2s,
│     (collector/)    │  bookmark-tracked, filtered to 6 event IDs
└─────────┬───────────┘
          │ raw XML strings
          ▼
┌─────────────────────┐
│  2. Normalizer      │  lxml XML parsing → typed Python dataclasses
│     (normalizer/)   │  one dataclass per event type
└─────────┬───────────┘
          │ typed SysmonEvent objects
          ▼
┌─────────────────────┐
│  3. Rule Engine     │  YAML rules loaded at startup, ATT&CK-mapped,
│     (rules/)        │  evaluated against each normalized event
└──────┬──────────────┘
       │ rule_hit records
       ▼
┌─────────────────────┐     ┌─────────────────────┐
│  4. SQLite Storage  │◄────│  5. ML Layer         │
│     (storage/)      │     │     (ml/)            │
│  events table       │     │  Isolation Forest    │
│  rule_hits table    │     │  (unsupervised)      │
│  model_scores table │     │  Random Forest       │
│  alerts table       │     │  (supervised)        │
└──────┬──────────────┘     └──────────────────────┘
       │
       ▼
┌─────────────────────┐
│  6. Alert Engine    │  Fuses rule hits + ML scores → severity tiers
│     (alerting/)     │  suspected_families reference field (metadata only)
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│  7. Dashboard       │  FastAPI + Jinja2 + HTMX on localhost:8080
│     (dashboard/)    │  9 pages, KQL query bar, HTMX real-time polling
└──────┬──────────────┘
       │
       ▼
┌─────────────────────────────────────────────────┐
│  8. Service + Tray                               │
│     (service/)  Windows Service in Session 0    │
│     (tray/)     Tray companion app in user      │
│                 session, polls localhost:8080   │
└─────────────────────────────────────────────────┘
```

**Critical constraint:** The shippable agent has zero ELK dependency. Elasticsearch, Kibana, and Winlogbeat are the Validation Lab's confirmation bench only. They never enter this codebase.

---

## SQLite Schema — Four Tables (designed in Phase 3)

| Table | Primary key | Key columns | Purpose |
|---|---|---|---|
| `events` | `id` INTEGER | `event_id`, `utc_time`, `image`, `process_id`, `raw_json` TEXT | Every normalized Sysmon event |
| `rule_hits` | `id` INTEGER | `event_fk`, `rule_name`, `mitre_technique`, `fired_at` | Rule engine matches |
| `model_scores` | `id` INTEGER | `event_fk`, `isolation_score` REAL, `rf_score` REAL, `scored_at` | ML model outputs |
| `alerts` | `id` INTEGER | `severity` TEXT, `event_fk`, `rule_hit_fk`, `suspected_families` TEXT, `created_at` | Correlated, deduplicated alerts |

`suspected_families` is a JSON array stored as TEXT. It is reference-only metadata — never used as a detection signal, never an input to severity computation.

---

## Dashboard Architecture (Phase 3)

- **Backend:** FastAPI, port 8080 (localhost only)
- **ORM:** SQLAlchemy 2.x (Core + ORM)
- **Templates:** Jinja2 (server-rendered)
- **Frontend interactivity:** HTMX only — no JS framework, no bundler
- **Real-time refresh:** `hx-trigger="every 3s"` on Alert Feed and Query Console
- **Query language:** KQL-style via `lark` grammar → SQLAlchemy filter translation

**Nine dashboard pages:**

| Page | Route | Description |
|---|---|---|
| Home / Status | `/` | AV-style protection indicator, alert counts by severity, service health, last-activity timestamp |
| Alert Feed | `/alerts` | Real-time HTMX-polled list of alerts |
| Alert Details | `/alerts/{id}` | Per-alert drill-down |
| Event Explorer | `/events` | Searchable events with KQL bar |
| Process Tree | `/process-tree` | Parent-child chain visualization |
| Search / Query Console | `/search` | Dedicated KQL search, HTMX-polled results |
| ML Insights | `/ml` | Anomaly scores, model status (graceful placeholder pre-Phase 6B) |
| Rules Library | `/rules` | Loaded YAML rules, ATT&CK mappings, firing frequency |
| Settings | `/settings` | Service status, exclusions, basic config |

KQL grammar coverage: `field:value` exact/partial, `AND` / `OR` / `NOT`, parenthesized nested grouping with correct operator precedence, wildcards (`*`, `?`), numeric and time range queries, quoted phrase matching.

---

## Severity Tiers (Phase 8A)

| Tier | Trigger condition |
|---|---|
| Low | Single rule hit, low ML anomaly score |
| Medium | Multiple rule hits OR elevated ML score |
| High | High ML score combined with rule hits across multiple categories |
| Critical | All three signals agree: rule hit + Isolation Forest anomaly + Random Forest positive |

---

## Sysmon Event Types in Scope

| Event ID | Name | Status |
|---|---|---|
| 1 | ProcessCreate | ✅ Phase 0A confirmed, XML sample exists |
| 3 | NetworkConnect | ✅ Phase 0A confirmed, XML sample exists |
| 7 | ImageLoad | ✅ Phase 0A confirmed, XML sample exists |
| 8 | CreateRemoteThread | ⏸ Deferred to Phase 4B (requires controlled injection simulation) |
| 10 | OpenProcess | ✅ Phase 0A confirmed, XML sample exists |
| 22 | DnsQuery | ✅ Phase 0A confirmed, XML sample exists |

XML samples for all 5 confirmed types live in `tests/fixtures/sysmon_samples/`. Event ID 8 support must be coded (dataclass + parser) but cannot be validated against a real sample until Phase 4B.

---

## Code Standards — Locked in Phase 0B

| Standard | Decision |
|---|---|
| Formatter / linter | **ruff** — single tool covering format + lint. Config lives in `ruff.toml` or `[tool.ruff]` in pyproject.toml. |
| Type hints | **Required** on all public functions and methods in every module. |
| mypy | Recommended, not CI-blocking. Solo project; run it but don't fail builds on it. |
| Docstrings | **Google-style** on all public functions, methods, and classes. |
| Test framework | **pytest** |
| Test file location | `tests/unit/test_<module>.py` — mirrors source module name. |
| Shared test fixtures | `tests/fixtures/` |
| Test naming | Function names describe the behavior under test, not implementation details. |
| Logging | `logging.getLogger(__name__)` in every module. No `print()` statements in production code. |
| Log format | `%(asctime)s %(levelname)s %(name)s %(message)s` |
| ML reproducibility | Fixed random seeds set and documented in code for all Phase 5–7 randomness (splits, model init). |

---

## Framing Rules — Apply in All Code, Docstrings, Comments, and Docs

- Say **"fileless threats"** — not "malware" repeated densely.
- Say **"simulating suspicious behavior in an isolated sandbox"** — not "running an attack."
- Prefer **"technique"** over "exploit" where both fit.
- End-user installation is always **consensual and owner-initiated**.
- `suspected_families` is **reference-only metadata** — never a detection signal, never an attribution claim.

---

## Hard Constraints — Never Violate

1. No absolute paths (`C:\...`, drive letters) anywhere in code or config. `pathlib.Path` + relative paths only.
2. No new packages added without flagging in the completion report.
3. No ELK dependency (Elasticsearch, Kibana, Winlogbeat) anywhere in the shippable codebase.
4. `suspected_families` field: populated by static lookup only, never used in severity computation or detection logic.
5. All suspicious-behavior testing stays in the isolated VMware sandbox — never on the host machine.
6. No `print()` in production code — use `logging` exclusively.
7. No TODO comments left in function bodies — deferred work goes in module-level docstrings.
