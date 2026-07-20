# ShadowSensor

**Behavioral Detection EDR for Windows — Fileless Threat Analysis**

ShadowSensor is a standalone, consent-based Windows endpoint detection and response (EDR) tool that detects fileless threats through behavioral telemetry rather than file-hash signatures. Fileless malware executes entirely in memory and leaves no file on disk, making it invisible to traditional antivirus. ShadowSensor addresses this gap by observing OS-level behavioral patterns through Sysmon's kernel-mode ETW hooks and applying a three-layer detection architecture.

---

## Detection Architecture

| Layer | Method | Status |
|-------|--------|--------|
| 1 | Rule-based detection — 49 YAML-defined behavioral rules, MITRE ATT&CK mapped | ✅ Complete |
| 2 | Unsupervised ML — Isolation Forest anomaly scoring (0.0–1.0) | 🔜 Phase 6 |
| 3 | Supervised ML — Random Forest classification with precision/recall/F1/ROC-AUC | 🔜 Phase 7 |

---

## Current Status

**Phase 5 of 10 complete — Feature Engineering Pipeline**

| Metric | Value |
|--------|-------|
| Tests passing | 502 / 502 |
| Behavioral detection rules | 49 (across 5 YAML files) |
| MITRE ATT&CK tactics covered | 9 |
| Dashboard pages | 9 + Kill Chain visualisation |
| ML features defined | 30 (Process · Relationship · Network · API/Memory · Rule-Hit) |

See [`status.md`](status.md) for the full phase tracker and [`VM_RUN_GUIDE.md`](VM_RUN_GUIDE.md) for setup and validation instructions.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Platform | Windows 10/11 (isolated VMware sandbox for validation) |
| Language | Python 3.11 |
| Telemetry | Sysmon 15.x — Event IDs 1, 3, 7, 8, 10, 22 |
| Backend | FastAPI + SQLAlchemy 2.0 + SQLite |
| Frontend | Jinja2 + HTMX 1.9.12 + ApexCharts |
| Query Engine | KQL-style parser — lark LALR(1) grammar |
| ML | scikit-learn — Isolation Forest + Random Forest |
| Rule Format | YAML with MITRE ATT&CK metadata |

---

## Repository Structure

```
collector/          Sysmon event polling and bookmark management
normalizer/         XML → typed Python dataclass parsing
rules/              YAML rule definitions + evaluation engine
  definitions/      49 behavioral rules across 5 YAML files
storage/            SQLite persistence (SQLAlchemy 2.0)
alerting/           Alert management
dashboard/          FastAPI backend, KQL engine, Jinja2 templates, static assets
  kql/              KQL grammar + lark parser + SQLAlchemy transformer
  routers/          API endpoints + page routes + Kill Chain routes
  services/         Kill Chain tactic-aggregation service
  templates/        Jinja2 HTML templates (9 pages + partials)
  static/           CSS + JS (charts, theme, time range)
ml/features/        Feature engineering pipeline (30-feature specification)
service/            Windows Service wrapper (Phase 9 — stub)
evaluation/         Evaluation scripts (Phase 10 — stub)
tests/              25 test files, 502 tests passing
scripts/            Pipeline entry points and VM validation scripts
docs/               Technical reference and phase documentation
```

---

## Six Target Event Types (Sysmon)

| Event ID | Name | Fileless Relevance |
|----------|------|--------------------|
| 1 | ProcessCreate | PowerShell -EncodedCommand, LOLBin invocations, suspicious parent-child chains |
| 3 | NetworkConnect | C2 callbacks, download cradles, beaconing |
| 7 | ImageLoad | Reflective DLL injection, unsigned module loading |
| 8 | CreateRemoteThread | Process injection indicator |
| 10 | OpenProcess | Credential dumping (lsass access), process hollowing setup |
| 22 | DnsQuery | C2 domain detection, DNS tunneling |

---

## Quick Start

> ⚠️ All suspicious-behavior simulations must be performed inside an isolated VMware sandbox only. Never on a host machine.

See [`VM_RUN_GUIDE.md`](VM_RUN_GUIDE.md) for full setup, dependency installation, and validation steps.

**Start the detection pipeline (Administrator shell, repo root):**
```bat
python_runtime\python.exe scripts\run_pipeline.py
```

**Start the dashboard (separate shell):**
```bat
python_runtime\python.exe scripts\run_dashboard.py
```

Dashboard: `http://localhost:8080`

> Note: `python_runtime\` is excluded from this repository (948 MB bundled interpreter).
> Install Python 3.11 separately and install dependencies: `pip install -r requirements.txt`

---

## Research Context

ShadowSensor is the subject of an academic research paper on behavioral detection of fileless threats. The paper covers: telemetry design, rule-based detection with MITRE ATT&CK mapping, unsupervised vs. supervised ML layer comparison, tool design, and evaluation results.

---

*Defensive security research tool. Standalone, user-installed with explicit consent. Not for covert deployment.*
