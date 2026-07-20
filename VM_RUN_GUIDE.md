# ShadowSensor — VM Run Guide

Run ShadowSensor on the **Windows 10 Pro sandbox VM** using the VMware shared folder.

**Shared folder path:** `\\vmware-host\Shared Folders\filelessmalware`

Always run the pipeline from the **repo root** (the folder that contains `scripts\`, `rules\`, and `python_runtime\`).

---

## Before you start

1. Open **cmd** or **PowerShell** as **Administrator** (right-click → Run as administrator).
2. Confirm Sysmon is installed and logging (Event Viewer → Sysmon → Operational).
3. Use the shared folder path below — do **not** run commands from `C:\` unless you copied the repo there.

---

## Step 1 — Go to the repo root

### CMD (Administrator)

```bat
pushd "\\vmware-host\Shared Folders\filelessmalware"
```

`pushd` maps a temporary drive letter if needed and changes into the folder. You should see a prompt like `Z:\>` or similar.

Confirm you are in the right place:

```bat
dir scripts\run_pipeline.py
dir python_runtime\python.exe
```

Both files must exist. `python.exe` should be about **100 KB**, not **0 bytes**.

### PowerShell (Administrator)

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
```

Confirm:

```powershell
Test-Path scripts\run_pipeline.py
Test-Path python_runtime\python.exe
(Get-Item python_runtime\python.exe).Length
```

The length should be greater than 0 (typically ~104000).

### Optional — map a drive letter (if `pushd` / `cd` fails)

**CMD:**

```bat
net use Z: "\\vmware-host\Shared Folders\filelessmalware"
Z:
```

**PowerShell:**

```powershell
net use Z: "\\vmware-host\Shared Folders\filelessmalware"
cd Z:\
```

---

## Step 2 — Clean bookmark (fresh run)

Delete the bookmark so the collector only reads **new** events after startup.

### CMD

```bat
del logs\.shadowsensor_bookmark.xml 2>nul
```

### PowerShell

```powershell
Remove-Item logs\.shadowsensor_bookmark.xml -ErrorAction SilentlyContinue
```

---

## Step 3 — Verify Python

### CMD

```bat
python_runtime\python.exe --version
```

### PowerShell

```powershell
python_runtime\python.exe --version
```

Expected: `Python 3.13.x` with no error.

If you see **"This app can't run on your PC"**, `python.exe` is corrupted (0-byte file). Copy a valid `python.exe` from the host into `python_runtime\` or use a local repo copy on `C:\filelessmalware`.

---

## Step 4 — Start the pipeline

Keep this window open. The pipeline polls Sysmon every 2 seconds and prints `RULE_HIT` lines when rules fire.

### CMD (Administrator, repo root)

```bat
pushd "\\vmware-host\Shared Folders\filelessmalware"
del logs\.shadowsensor_bookmark.xml 2>nul
python_runtime\python.exe scripts\run_pipeline.py
```

### PowerShell (Administrator, repo root)

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
Remove-Item logs\.shadowsensor_bookmark.xml -ErrorAction SilentlyContinue
python_runtime\python.exe scripts\run_pipeline.py
```

### What you should see at startup

```
============================================================
ShadowSensor Pipeline — Live Mode
...
[INFO] Loaded 15 rules from rules/definitions/
Event collection pipeline started (thread: ShadowSensor-Collector)
```

**No output after that is normal** during benign activity. The pipeline only prints when a rule fires.

Press **Ctrl+C** to stop. Hits are also written to `logs\rule_hits.log`.

---

## Step 5 — Confirm the pipeline is alive

Open a **second** Administrator window, go to the repo root, then:

### CMD

```bat
pushd "\\vmware-host\Shared Folders\filelessmalware"
dir logs\.shadowsensor_bookmark.xml
dir logs\rule_hits.log
```

### PowerShell

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
Get-Item logs\.shadowsensor_bookmark.xml
Get-Content logs\rule_hits.log -Tail 5
```

- `logs\rule_hits.log` should contain `=== SESSION START ===`
- After you open Notepad or browse folders, the bookmark file timestamp should update

### Quick single-rule test (second window)

**CMD** — not ideal for Start-Process; use PowerShell for this test, or:

**PowerShell:**

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
Start-Process powershell.exe -ArgumentList '-NoProfile','-EncodedCommand','JABjAG0AZAAgACcAVABlAHMAdAAnAA=='
```

Within a few seconds, the pipeline window should show `PS_ENCODED_CMD_001`.

---

## Step 6 — Run all true-positive test scripts

Pipeline must stay running in **window 1**. Run these in **window 2** (Administrator, repo root).

### PowerShell (recommended for test scripts)

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_01_powershell.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_02_lolbins.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_03_chains_api_network.ps1
```

Run **one line at a time**. Wait ~5 seconds between tests and watch the pipeline window for `RULE_HIT`.

| Script | Rules tested |
|--------|----------------|
| `vm_tp_test_01_powershell.ps1` | 4 PowerShell rules |
| `vm_tp_test_02_lolbins.ps1` | 4 LOLBin rules |
| `vm_tp_test_03_chains_api_network.ps1` | 4 parent-chain + network + 2 API rules |

Shorter smoke test (5 rules):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_fixed.ps1
```

---

## Step 7 — Benign baseline (Phase 2B gate)

1. Delete bookmark and start pipeline (Step 4).
2. For at least **3 minutes**, do normal activity:
   - Open Microsoft Edge from the desktop
   - Open File Explorer and browse folders
   - Open Task Manager
   - Open PowerShell and run `Get-Process`
   - Idle for 1 minute
3. **Pass:** zero `API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001` floods; no repeated rule floods.

---

## Offline checks (pipeline stopped OK)

From repo root:

### CMD

```bat
pushd "\\vmware-host\Shared Folders\filelessmalware"
python_runtime\python.exe scripts\verify_pipeline.py
python_runtime\python.exe scripts\e2e_step6_verification.py
```

### PowerShell

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
python_runtime\python.exe scripts\verify_pipeline.py
python_runtime\python.exe scripts\e2e_step6_verification.py
```

Both should end with `OVERALL: PASS`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `The system cannot find the path specified` | Enable VMware Shared Folders + VMware Tools; use `net use Z: "\\vmware-host\Shared Folders\filelessmalware"` |
| `This app can't run on your PC` (python) | `python_runtime\python.exe` is 0 bytes — restore from host or copy repo to `C:\filelessmalware` |
| `Sysmon channel not found` | Run as **Administrator**; confirm Sysmon service is running |
| No `RULE_HIT` during normal use | Expected for benign activity — run Step 5 encoded-command test |
| PowerShell script parse errors | Use `vm_tp_test_*.ps1` files (ASCII-only), not the old `vm_rule_hit_test.ps1` |
| Commands fail from `C:\` | You must `cd` / `pushd` to the repo root first |

---

## Quick reference — copy/paste blocks

### CMD — start pipeline

```bat
pushd "\\vmware-hodel logs\.shadowsensor_bookmark.xml 2>nul
python_runtime\python.exe scripts\run_pipeline.pyst\Shared Folders\filelessmalware"

```

### PowerShell — start pipeline

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
Remove-Item logs\.shadowsensor_bookmark.xml -ErrorAction SilentlyContinue
python_runtime\python.exe scripts\run_pipeline.py
```

### PowerShell — run all VM tests

```powershell
cd "\\vmware-host\Shared Folders\filelessmalware"
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_01_powershell.ps1
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_02_lolbins.ps1
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_03_chains_api_network.ps1
```

---

*Sandbox only. All technique simulations are for isolated VM validation.*

---

## Phase 3A — Storage Foundation verification commands (append-only)

Run these from repo root in an Administrator shell on the sandbox VM.

### 1) Initialize Phase 3 database schema

```bat
python_runtime\python.exe -c "from storage.database import init_db; init_db(); print('OK')"
```

Expected output:

```text
OK
```

### 2) Verify the 4 Phase 3 tables exist

If `sqlite3` is available:

```bat
sqlite3 data\shadowsensor.db ".tables"
```

Expected table names include:

```text
alerts events model_scores rule_hits
```

If `sqlite3` is not available, use Python fallback:

```bat
python_runtime\python.exe -c "import sqlite3; c=sqlite3.connect('data/shadowsensor.db'); cur=c.cursor(); print(','.join(sorted(r[0] for r in cur.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()))); c.close()"
```

Expected output contains:

```text
alerts,events,model_scores,rule_hits
```

### 3) Run pipeline and confirm SQLite write path is non-fatal

```bat
python_runtime\python.exe scripts\run_pipeline.py
```

Let it run for ~30 seconds, then stop with `Ctrl+C`.

Expected behavior:
- Pipeline starts and loads rules.
- If Sysmon channel is unavailable, pipeline may log collector thread errors, but SQLite initialization must still occur and process should not crash due to DB writes.

### 4) Check row counts after a pipeline run

```bat
python_runtime\python.exe -c "import sqlite3; c=sqlite3.connect('data/shadowsensor.db'); cur=c.cursor(); print('events', cur.execute('SELECT COUNT(*) FROM events').fetchone()[0]); print('rule_hits', cur.execute('SELECT COUNT(*) FROM rule_hits').fetchone()[0]); print('alerts', cur.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]); c.close()"
```

Expected output:
- Numeric counts for all three tables (including zero if no Sysmon events were ingested during the run).

### 5) Verify Phase 3A tests

```bat
python_runtime\python.exe -m pytest tests\test_phase3\test_storage.py -v
python_runtime\python.exe -m pytest tests\test_phase3\test_alert_manager.py -v
python_runtime\python.exe -m pytest tests\ -v
```

---

## Dependency Installation (python_runtime)

If Sub-task B dependencies are missing in the sandbox interpreter, install them with:

```bat
python_runtime\python.exe -m pip install "aiofiles>=23.2.1"
python_runtime\python.exe -m pip install "httpx>=0.27.0"
```

---

## Phase 3B — FastAPI Backend + KQL Engine verification commands (append-only)

Run these from repo root in an Administrator shell on the sandbox VM.

### 1) Start the dashboard backend

```bat
python_runtime\python.exe scripts\run_dashboard.py
```

Expected startup output includes:

```text
Uvicorn running on http://0.0.0.0:8080
```

### 2) Health endpoint

```bat
curl http://localhost:8080/api/v1/health
```

Expected response contains `"status":"ok"`.

### 3) Stats endpoint

```bat
curl "http://localhost:8080/api/v1/stats?quick=24h"
```

Expected response contains keys:
`total_alerts`, `by_severity`, `total_events`, `total_rule_hits`, `rules_fired`, `time_range`.

### 4) Rules endpoint (all loaded YAML rules + hit counts)

```bat
curl http://localhost:8080/api/v1/rules
```

Expected:
- JSON list response
- 15+ rule objects in current ruleset

### 5) Timeline interval check

```bat
curl "http://localhost:8080/api/v1/timeline?quick=15m"
```

Expected response contains `"interval":"1m"`.

### 6) Search with valid KQL

```bat
curl "http://localhost:8080/api/v1/search?q=severity:High&context=alerts"
```

Expected: HTTP 200 with paginated JSON payload.

### 7) Search with invalid KQL

```bat
curl "http://localhost:8080/api/v1/search?q=severity:"
```

Expected: HTTP 400 with JSON `detail` containing `KQL`.

### 8) Run Sub-task B test suites

```bat
python_runtime\python.exe -m pytest tests\test_phase3\test_kql_parser.py -v
python_runtime\python.exe -m pytest tests\test_phase3\test_kql_transformer.py -v
python_runtime\python.exe -m pytest tests\test_phase3\test_api_endpoints.py -v
python_runtime\python.exe -m pytest tests\ -v
```

---

## Phase 3C — Dashboard Core (5 Pages) verification commands (append-only)

Run these from repo root on the sandbox VM. Requires a browser (Edge/Chrome) and optionally an active pipeline feeding SQLite.

**No new pip installs required for Sub-task C** — all frontend libraries load via CDN (HTMX, ApexCharts, flatpickr).

### 1) Ensure database has data (optional but recommended)

Run pipeline for 30–60 seconds in one Administrator shell, then start dashboard in another:

```bat
python_runtime\python.exe scripts\run_pipeline.py
```

In a second shell:

```bat
python_runtime\python.exe scripts\run_dashboard.py
```

Expected startup:

```text
Uvicorn running on http://0.0.0.0:8080
```

### 2) Open each core page in the browser

| Page | URL |
|---|---|
| Home / Status | http://localhost:8080/dashboard/home |
| Alert Feed | http://localhost:8080/dashboard/alerts |
| Event Explorer | http://localhost:8080/dashboard/events |
| Process Tree | http://localhost:8080/dashboard/process-tree |
| Alert Details | http://localhost:8080/dashboard/alerts/1 *(use a valid alert id from your DB)* |

Quick curl smoke (HTML returned, no 500):

```bat
curl -s -o NUL -w "home %%{http_code}\n" http://localhost:8080/dashboard/home
curl -s -o NUL -w "alerts %%{http_code}\n" http://localhost:8080/dashboard/alerts
curl -s -o NUL -w "events %%{http_code}\n" http://localhost:8080/dashboard/events
curl -s -o NUL -w "process-tree %%{http_code}\n" http://localhost:8080/dashboard/process-tree
curl -s -o NUL -w "alert-404 %%{http_code}\n" http://localhost:8080/dashboard/alerts/99999
```

Expected: all return `200` except alert-404 which returns `404`.

### 3) Verify HTMX polling (DevTools → Network)

On **Alert Feed** (`/dashboard/alerts`):
- Confirm requests to `/dashboard/partials/alerts-rows` every ~3 seconds.
- Type text in the KQL bar (e.g. `severity:High`) — polling should **stop** while input is non-empty.
- Clear KQL (Escape or Clear button) — polling resumes.

On **Home** (`/dashboard/home`):
- Confirm requests to `/dashboard/partials/recent-alerts` every ~5 seconds.
- Confirm JS fetch requests to `/api/v1/stats`, `/api/v1/timeline`, `/api/v1/severity-distribution`, `/api/v1/top-rules` every ~5 seconds.

### 4) Verify theme toggle

1. First load should be **dark** theme (no flash of light).
2. Click the theme button (☀/☾) in the sidebar footer → switches to light.
3. Hard refresh (F5) → theme persists.
4. Visit all 5 pages in light mode — confirm no invisible text.

### 5) Verify time range picker

1. Click quick-select buttons (15m, 1h, 6h, 24h, 7d, 30d) — label updates (top-right).
2. On Home, stat card numbers should change when switching e.g. **1h** vs **30d** (if DB has historical data).
3. Custom range: click Start/End flatpickr inputs, pick datetimes, click **Apply** — label shows `from → to` and charts/stats refresh.

### 6) Verify charts (Home page)

- Timeline area chart, severity donut, and top-rules horizontal bar should render when alerts exist in range.
- Empty ranges show styled empty-state text inside chart containers.

### 7) Verify Event Explorer expandable rows

1. Open http://localhost:8080/dashboard/events
2. Click any event row — raw JSON `<pre>` block appears below.
3. Click again — detail row hides.

### 8) Verify Process Tree expand/collapse

1. Open http://localhost:8080/dashboard/process-tree
2. Click ▶ on a parent process — child list expands (▼).
3. Leaf nodes show • (not ▶).

### 9) Verify KQL on Alert Feed

1. Enter `severity:High` and press Enter — table filters to High alerts only.
2. Enter invalid query `severity:` — red inline error below KQL bar (no browser `alert()`).

### 10) Regression tests (no new tests in Sub-task C)

```bat
python_runtime\python.exe -m pytest tests\ -v
```

Expected: **227/227** passing (same as Sub-task B).

---

## Alert Feed Visual Fix Verification

After applying the Alert Feed table overflow and rule-name link fixes, verify in the browser:

1. Reload http://localhost:8080/dashboard/alerts
2. Confirm all 7 columns are visible without horizontal scroll
3. Confirm Ack and Resolve buttons both fit within the Actions column
4. Confirm clicking a Rule Name navigates to the Alert Details page for that alert
5. Confirm hovering a truncated rule name shows the full name in tooltip

---

## Alert Details Fix Verification

After applying the Alert Details 500 fix, verify in the browser:

1. Open http://localhost:8080/dashboard/alerts (Alert Feed)
2. Click any rule name in the Rule Name column
3. Confirm: Alert Details page renders correctly (no 500 error)
4. Confirm: all fields display or show "—" for null values
5. Confirm: raw JSON is visible in the collapsible section
6. Confirm: back button returns to Alert Feed

---

## Phase 3 Complete — Full System Verification

Start the system:

Terminal 1 (Administrator):

```bat
python_runtime\python.exe scripts\run_pipeline.py
```

Terminal 2:

```bat
python_runtime\python.exe scripts\run_dashboard.py
```

Browser: http://localhost:8080

### Verify all 9 pages

| Page | URL | What to check |
|---|---|---|
| Home | `/dashboard/home` | Stat cards (all 5 in one row), timeline chart, donut chart, bar chart, recent alerts table |
| Alert Feed | `/dashboard/alerts` | Live alert feed, HTMX 3s polling visible in DevTools Network, KQL bar with autofocus, Ack/Resolve buttons update status badge in-place |
| Alert Details | `/dashboard/alerts/{id}` | Click any rule name in Alert Feed, confirm Alert Details loads (no 500 error), all fields show or "—" for nulls, raw JSON collapsible works, back button works |
| Event Explorer | `/dashboard/events` | Event type pills filter table, expandable rows show raw JSON inline |
| Process Tree | `/dashboard/process-tree` | Nested list with ▶ expand/collapse |
| Query Console | `/dashboard/search` | KQL bar submits on Enter, context selector switches table columns, bad KQL shows inline red error (no browser alert popup) |
| ML Insights | `/dashboard/ml-insights` | Placeholder card visible, "● Models: Not trained" status |
| Rules Library | `/dashboard/rules` | Rules table loads, client-side filter works, severity pills filter without network request |
| Settings | `/dashboard/settings` | Health Refresh button updates stats via HTMX |

### Run full test suite

```bat
python_runtime\python.exe -m pytest tests\ -v
```

Expected: **249/249** passing.

---

## Known Environment: SQLite Journal Mode

SQLite WAL mode does not work on VMware shared folder paths (`\\vmware-host\Shared Folders\...`). `storage/database.py` handles this automatically — it attempts WAL and falls back to DELETE journal mode with a 5-second `busy_timeout`. No manual action needed.

Both `run_pipeline.py` and `run_dashboard.py` can run simultaneously; `busy_timeout` handles any momentary DB lock between the two processes.

---

## Known Environment: SQLite Journal Mode

SQLite WAL mode does not work on VMware shared folder paths (`\\vmware-host\Shared Folders\...`). `storage/database.py` handles this automatically — it attempts WAL and falls back to DELETE journal mode with a 5-second `busy_timeout`. No manual action needed.

Both `run_pipeline.py` and `run_dashboard.py` can run simultaneously; `busy_timeout` handles any momentary DB lock between the two processes.

---

## Phase 3 Complete — Full System Startup

### Prerequisites
- Run pipeline terminal as Administrator (Sysmon channel requires elevation)
- Dashboard terminal does NOT require Administrator
- Sysmon must be running: net start Sysmon64

### Start the system
Terminal 1 (Administrator):
```bat
python_runtime\python.exe scripts\run_pipeline.py
```

Terminal 2 (standard user):
```bat
python_runtime\python.exe scripts\run_dashboard.py
```

Open browser: http://localhost:8080

### Database location
C:\ShadowSensor\data\shadowsensor.db (local NTFS — NOT the VMware shared folder path)

To use a custom path:
```bat
set SHADOWSENSOR_DB_DIR=D:\CustomPath
python_runtime\python.exe scripts\run_pipeline.py
```

To check row counts:
```bat
python_runtime\python.exe -c "
import sqlite3
conn = sqlite3.connect(r'C:\ShadowSensor\data\shadowsensor.db')
for t in ['events','rule_hits','alerts','model_scores']:
    n = conn.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]
    print(f'{t}: {n} rows')
conn.close()
"
```

### Verify all 9 pages
- `/dashboard/home` — stat cards, charts, recent alerts
- `/dashboard/alerts` — live alert feed, click rule name → details
- `/dashboard/alerts/{id}` — alert details, raw JSON, MITRE links
- `/dashboard/events` — event explorer, type filter pills
- `/dashboard/process-tree` — nested process tree
- `/dashboard/search` — KQL query console
- `/dashboard/ml-insights` — placeholder (populated Phase 6B/7B)
- `/dashboard/rules` — rules library, client-side filter
- `/dashboard/settings` — health status, theme toggle

### Run full test suite
```bat
python_runtime\python.exe -m pytest tests/ -v
```
Expected: 249/249 passing

### Known environment notes
- SQLite WAL mode and PRAGMA synchronous=NORMAL both fail on VMware shared folder paths — this is handled in database.py with graceful fallback + busy_timeout=5000
- Bookmark WinError 5/183 on shared folder for .shadowsensor_bookmark.xml is non-blocking — collector restarts from beginning on each run
- Pipeline must run as Administrator for Sysmon EvtQuery access

---

## Kill Chain Visualisation — Subtask A Backend Verification (append-only)

These commands verify the Subtask A backend on any machine (host or VM).
Does NOT require Sysmon. Does NOT require Administrator. Does NOT require the pipeline.

### 1) Service import check

```bat
python_runtime\python.exe -c "from dashboard.services.killchain_service import load_rule_tactic_map, TACTIC_DISPLAY_ORDER; print('OK')"
```
Expected: `OK`

### 2) Rule tactic map smoke test

```bat
python_runtime\python.exe -c "from dashboard.services.killchain_service import load_rule_tactic_map; m = load_rule_tactic_map('rules/definitions'); print(f'Rules loaded: {len(m)}')"
```
Expected: `Rules loaded: 15`

### 3) Start dashboard (no Administrator needed)

```bat
python_runtime\python.exe scripts\run_dashboard.py
```

### 4) Kill chain endpoint checks (second terminal)

```bat
curl http://localhost:8080/dashboard/killchain
curl "http://localhost:8080/dashboard/partials/killchain-overview?quick=24h"
curl http://localhost:8080/dashboard/partials/killchain-stage/TA0002
curl http://localhost:8080/dashboard/partials/killchain-stage/INVALID_TACTIC
```

Expected responses: first three → HTTP 200 JSON; last → HTTP 404 JSON.

### 5) Full test suite

```bat
python_runtime\python.exe -m pytest tests/ -v --tb=short -q
```
Expected: 249 + N passed, 0 failed (N = number of new killchain tests).

---

## Kill Chain Visualisation — Subtask B Browser Verification (append-only)

Run these on the VM after starting both the pipeline (Admin terminal) and the dashboard.

### Start system

Terminal 1 (Administrator):
```bat
python_runtime\python.exe scripts\run_pipeline.py
```

Terminal 2 (standard user):
```bat
python_runtime\python.exe scripts\run_dashboard.py
```

Browser: `http://localhost:8080/dashboard/killchain`

### Quick endpoint checks (second terminal)

```bat
curl -s -o NUL -w "killchain_page: %%{http_code}\n" http://localhost:8080/dashboard/killchain
curl -s -o NUL -w "killchain_overview: %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-overview
curl -s -o NUL -w "killchain_stage: %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-stage/TA0002
curl -s -o NUL -w "invalid_stage_404: %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-stage/INVALID_TACTIC
```

Expected: first three 200, last one 404.

### Generate rule hits to see fired tactic cards

```powershell
powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_01_powershell.ps1
```

Wait 10 seconds. Tactic cards for Execution and Defense Evasion should switch to fired state.

### Full test suite

```bat
python_runtime\python.exe -m pytest tests/ -v --tb=short -q
```

Expected: 296 + N passed (N = new template tests from Subtask B), 0 failed.

### Verify HTMX polling

Open DevTools → Network tab on the kill chain page. Confirm requests to
`/dashboard/partials/killchain-overview` fire every ~5 seconds.

### Verify theme

Click the theme toggle in the sidebar footer. Kill chain cards must render correctly
in both dark and light mode with no invisible text.

---

## Kill Chain Visualisation — Subtask C (Final) Verification (append-only)

Run these on the VM to verify the complete kill chain feature.

### Start system

Terminal 1 (Administrator):
    python_runtime\python.exe scripts\run_pipeline.py

Terminal 2 (standard user):
    python_runtime\python.exe scripts\run_dashboard.py

Browser: http://localhost:8080/dashboard/killchain

### Generate rule hits

    powershell -ExecutionPolicy Bypass -File scripts\vm_tp_test_01_powershell.ps1

Wait 10 seconds. Tactic cards for Execution and Defense Evasion
should switch to fired state.

### Verify stage expansion

Click a fired tactic card.
Expected: inline panel appears with rule breakdown table.
Click Collapse. Expected: panel disappears.

### Verify View in Alert Feed links

Click "View in Alert Feed" in the rule breakdown table.
Expected: navigates to /dashboard/alerts with KQL filter applied.

### Endpoint checks

    curl -s -o NUL -w "killchain_page:      %%{http_code}\n" http://localhost:8080/dashboard/killchain
    curl -s -o NUL -w "killchain_overview:  %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-overview
    curl -s -o NUL -w "killchain_stage:     %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-stage/TA0002
    curl -s -o NUL -w "killchain_404:       %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-stage/INVALID_TACTIC

Expected: first three 200, last one 404.

### Full test suite

    python_runtime\python.exe -m pytest tests/ -v --tb=short -q

Expected: 320 + N passed (N = new stage detail tests from Subtask C), 0 failed.

### Kill Chain feature summary (complete as of Subtask C)

Kill chain page: /dashboard/killchain
Overview partial (HTMX polled every 5s): /dashboard/partials/killchain-overview
Stage detail partial (click-to-expand): /dashboard/partials/killchain-stage/{tactic_id}
Valid tactic IDs: TA0001 TA0002 TA0003 TA0004 TA0005 TA0006
                  TA0007 TA0008 TA0009 TA0010 TA0011 TA0040

---

## Kill Chain Visualisation — Phase Closure Note

The Kill Chain Visualisation holding phase is complete as of 2026-07-06.
The feature is fully operational. Use the following scripts on the VM
for ongoing verification or demonstration:

Quick endpoint check (dashboard running, second terminal):

    curl -s -o NUL -w "killchain:          %%{http_code}\n" http://localhost:8080/dashboard/killchain
    curl -s -o NUL -w "overview partial:   %%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-overview
    curl -s -o NUL -w "stage detail TA0002:%%{http_code}\n" http://localhost:8080/dashboard/partials/killchain-stage/TA0002

Expected: all 200.

Kill Chain verification scripts (run on VM, pipeline + dashboard active):

    powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_setup.ps1
    powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_all_tactics.ps1
    powershell -ExecutionPolicy Bypass -File scripts\killchain_verify_browser_checklist.ps1

Full test suite:

    python_runtime\python.exe -m pytest tests/ -v --tb=short -q

Expected: 333 passed, 0 failed.

---

## Phase 4A Complete — Rule Expansion Verification (append-only)

Run these from repo root to verify the Phase 4A rule expansion.

### 1) Confirm total rule count

    python_runtime\python.exe -c "
import sys, pathlib
sys.path.insert(0, '.')
from rules.loader import load_rules_from_directory
rules = load_rules_from_directory(pathlib.Path('rules'))
print(f'Total rules loaded: {len(rules)}')
"

Expected: Total rules loaded: 48

### 2) Full test suite

    python_runtime\python.exe -m pytest tests\ -v --tb=short -q

Expected: 399 passed, 0 failed.

### 3) Rule file breakdown after Phase 4A

| File | Rules |
|---|---|
| powershell.yaml | 11 |
| lolbins.yaml | 13 |
| network.yaml | 8 |
| api_memory.yaml | 7 |
| parent_child.yaml | 9 |
| **Total** | **48** |

### 4) New MITRE tactics covered (not in original 15-rule set)

- Credential Access (TA0006) — PS_CREDENTIAL_ACCESS_001
- Lateral Movement (TA0008) — NET_SMB_LATERAL_001
- Persistence (TA0003) — CHAIN_SCHEDULED_TASK_SCRIPT_001


---

## Phase 5 — Feature Engineering Pipeline verification commands (append-only)

Run these from repo root on the sandbox VM or host machine.
Does NOT require Sysmon or Administrator. Pipeline does not need to
be running.

### 1) Check Phase 5 files are all present

```bat
python_runtime\python.exe -c "
import pathlib
files = [
    'ml/__init__.py',
    'ml/features/__init__.py',
    'ml/features/feature_spec.py',
    'ml/features/extractor.py',
    'ml/features/aggregator.py',
    'ml/features/pipeline.py',
    'ml/features/exporter.py',
    'scripts/run_feature_extraction.py',
]
missing = [f for f in files if not pathlib.Path(f).exists()]
if missing:
    for f in missing: print(f'MISSING: {f}')
else:
    print('All Phase 5 files present: PASS')
"
```

### 2) Run Phase 5 test suite in isolation

```bat
python_runtime\python.exe -m pytest tests\test_phase5\ -v
```

Expected: 90 passed, 0 failed.

### 3) Run full regression suite

```bat
python_runtime\python.exe -m pytest tests\ -v --tb=short -q
```

Expected: 502 passed, 0 failed.

### 4) Extract features from the live database (no label)

```bat
python_runtime\python.exe scripts\run_feature_extraction.py --output data\features\latest_extract.csv
```

Expected output:
```
[INFO] Reading from: C:\ShadowSensor\data\shadowsensor.db
[INFO] Extracted N process windows
[INFO] Exported to: data\features\latest_extract.csv
[INFO] Features per row: 30
```

### 5) Extract with label 0 (Phase 6A benign baseline)

```bat
python_runtime\python.exe scripts\run_feature_extraction.py --label 0 --output data\features\benign_baseline.csv
```

### 6) Extract with label 1 (Phase 7A suspicious telemetry)

```bat
python_runtime\python.exe scripts\run_feature_extraction.py --label 1 --output data\features\suspicious.csv
```

### 7) Verify CSV structure

```bat
python_runtime\python.exe -c "
import csv, pathlib, sys
p = pathlib.Path('data/features/benign_baseline.csv')
if not p.exists():
    print('File not found — run extraction first')
    sys.exit(1)
rows = list(csv.reader(p.open()))
print(f'Header columns: {len(rows[0])}')
print(f'Data rows: {len(rows) - 1}')
print(f'First column: {rows[0][0]}')
print(f'Last column: {rows[0][-1]}')
"
```

Expected: Header columns 31, first column cmd_length, last column label.

### 8) Smoke test — missing DB (should exit 0, write header-only CSV)

```bat
python_runtime\python.exe scripts\run_feature_extraction.py --db nonexistent.db --output data\features\smoke_test.csv
python_runtime\python.exe -c "
import csv, pathlib
p = pathlib.Path('data/features/smoke_test.csv')
rows = list(csv.reader(p.open()))
assert len(rows) == 1 and len(rows[0]) == 30
print('Smoke test PASS')
"
```

### Known Phase 5 limitations (carried forward)

- (image, pid) grouping only — no ProcessGuid disambiguation (Phase 4B
  Issues 2/6, environmentally limited)
- is_signed is always 0 for EID-1 (ProcessCreate) events — confirmed
  Sysmon schema gap, not an implementation oversight
- DB must be on local NTFS (C:\ShadowSensor\data\) — SQLite WAL mode
  fails on VMware shared folder paths, same constraint as pipeline DB

After running Phase 6A benign baseline collection, use command 5 above
to export the labeled benign CSV that Phase 6B (Isolation Forest
training) will consume directly.
